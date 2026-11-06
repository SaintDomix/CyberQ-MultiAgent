#!/usr/bin/env python3
"""Offline acceptance of accepted v2 against locked evidence, with fitting/network guards."""
from collections import defaultdict
from contextlib import ExitStack
import copy
from datetime import timedelta
import json
from pathlib import Path
import sys
import tempfile
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
sys.path.insert(0, str(ROOT / 'scripts'))
import numpy as np
from behavioral_runtime.package import load, verify
from behavioral_runtime.live import LiveEngine
from behavioral_runtime.incidents import Incidents
from behavioral_v2.data import sha, write
from branch2.events import utc
from branch2.live_storage import Journal, digest
from run_m5_blind_benign_evaluation import FITTING_METHODS


def same_prediction(actual, expected):
    for name in ('window_start', 'window_end', 'client_id', 'user_agent_id', 'novelty_anomalous',
                 'xgb_label', 'reconciliation', 'model_observation'):
        if actual[name] != expected[name]:
            raise ValueError('Saved replay semantic mismatch: ' + name)
    for name in ('novelty_score', 'xgb_confidence', 'xgb_scores'):
        if not np.allclose(actual[name], expected[name], rtol=0, atol=1e-12):
            raise ValueError('Saved replay score mismatch: ' + name)


def replay(output=None):
    accepted = ROOT / 'outputs/branch2/accepted_behavioral_v2'
    manifest = verify(accepted)
    package = load(accepted)
    root = ROOT / 'outputs/branch2/m5_final_day'
    attack = root / 'fresh_attack_holdout_01'
    output = Path(output) if output is not None else attack / 'live_engine_acceptance.json'
    if output.exists():
        raise ValueError('Refuse overwrite of live acceptance')
    expected = json.loads((attack / 'predictions.json').read_text())['candidate']
    plan = json.loads((attack / 'predeclared_plan.json').read_text())
    cap = ROOT / 'evidence/branch2_captures/m5_fresh_attack_holdout_01'
    results = []
    for run in plan['runs']:
        rid = run['run_id']
        rows = sorted([p for p in expected if p['run_id'] == rid], key=lambda p: (p['window_start'], p['client_id'], p['user_agent_id']))
        with tempfile.TemporaryDirectory(prefix='m5-v2-replay-') as tmp:
            tmp = Path(tmp)
            source = tmp / 'replay.log'; source.write_bytes(b'')
            clock = [utc(rows[0]['window_start'])]
            engine = LiveEngine(source, accepted, tmp / 'runtime', clock=lambda: clock[0])
            try:
                source.write_bytes((cap / rid / 'access.log').read_bytes())
                clock[0] = max(utc(p['window_end']) for p in rows) + timedelta(seconds=12)
                engine.poll()
                observed = [e['prediction'] for e in engine.journal.entries()]
                if len(observed) != len(rows):
                    raise ValueError('Replay window count mismatch')
                for actual, prior in zip(observed, rows):
                    same_prediction(actual, prior)
                incidents = engine.incidents.values()
                before = (engine.root / 'predictions.jsonl').read_bytes()
                ids = [p['observation_id'] for p in observed]
                engine.stop()
                resumed = LiveEngine(source, accepted, tmp / 'runtime', resume=True, clock=lambda: clock[0])
                try:
                    resumed.poll()
                    if ((resumed.root / 'predictions.jsonl').read_bytes() != before
                            or resumed.incidents.values() != incidents
                            or resumed.journal.sequence != len(rows)):
                        raise ValueError('Resume created duplicate/changed observations or incidents')
                finally:
                    resumed.stop()
                if len(set(ids)) != len(ids) or len({i['episode_id'] for i in incidents}) != len(incidents):
                    raise ValueError('Duplicate replay identity')
                results.append({'run_id': rid, 'class': run['label'], 'windows': len(rows),
                                'incidents': len(incidents), 'prediction_match': True, 'resume_match': True})
            finally:
                engine.stop()
    # Locked benign observations are replayed into the same durable incident
    # projection. This does not reopen the real Apache log or recalculate the
    # locked benign evaluation. Saved features separately verify model copying.
    benign_predictions = json.loads((root / 'blind_benign_test_01/evaluation/candidate_predictions.json').read_text())
    grouped = defaultdict(list)
    for p in benign_predictions:
        grouped[p['run_id']].append(p)
    benign_results = []
    for rid, rows in sorted(grouped.items()):
        features = json.loads((root / 'browser_sessions' / rid / 'features.json').read_text())
        refreshed = package.predict(features)
        for actual, prior in zip(refreshed, rows):
            same_prediction(actual, prior)
        with tempfile.TemporaryDirectory(prefix='m5-benign-journal-replay-') as tmp:
            journal = Journal(tmp)
            try:
                incidents = Incidents(journal, package.config['persistence'], manifest['package_id'])
                for prior in rows:
                    p = copy.deepcopy(prior)
                    p.update(session_id=rid, model_id=manifest['package_id'],
                             observation_id=digest([rid, p['window_start'], p['client_id'], p['user_agent_id']]))
                    p['record_id'] = p['observation_id']
                    journal.persist({'record_id': p['record_id']}, p)
                    incidents.sync()
                if incidents.values():
                    raise ValueError('Locked benign replay unexpectedly creates an incident')
                benign_results.append({'run_id': rid, 'windows': len(rows), 'incidents': 0, 'prediction_match': True})
            finally:
                journal.close()
    result = {'status': 'PASS', 'accepted_package_id': manifest['package_id'],
              'accepted_root_sha256': manifest['root_sha256'], 'attack_replay': results,
              'attack_windows': sum(r['windows'] for r in results),
              'attack_incidents': sum(r['incidents'] for r in results),
              'benign_saved_observation_replay': benign_results,
              'benign_windows': len(benign_predictions), 'benign_incidents': 0,
              'restart_resume_match': True, 'duplicate_observations': 0, 'duplicate_incidents': 0,
              'UNKNOWN_capability': 'One isolated UNKNOWN is retained in benign replay; persistence-two escalation covered by synthetic tests',
              'score_comparison_absolute_tolerance': 1e-12,
              'SHAP_available_attack_windows': sum(p['shap_explanation']['status'] == 'AVAILABLE' for p in expected),
              'fit_calls': 0, 'network_requests': 0, 'real_apache_log_opened': False,
              'input_hashes': {str(p.relative_to(ROOT)): sha(p) for p in (
                  attack / 'predictions.json', root / 'blind_benign_test_01/evaluation/candidate_predictions.json')},
              'limitations': 'Replay validates incremental runtime and saved semantics, not a new prospective live deployment experiment. Benign replay uses saved accepted features/observations; raw Apache was not reopened.'}
    write(output, result)
    print(json.dumps(result))
    return result


if __name__ == '__main__':
    with ExitStack() as stack:
        for name in FITTING_METHODS:
            stack.enter_context(patch(name, side_effect=AssertionError('Fitting forbidden')))
        for name in ('socket.socket.connect', 'socket.socket.connect_ex', 'socket.create_connection',
                     'socket.getaddrinfo', 'socket.socket.sendto'):
            stack.enter_context(patch(name, side_effect=AssertionError('Network forbidden')))
        replay()
