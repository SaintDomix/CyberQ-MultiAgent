#!/usr/bin/env python3
"""Record an explicit scoped research decision and copy the immutable candidate."""
import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from behavioral_v2.data import sha, write
from behavioral_runtime.package import accept, ORIGIN_ROOT


def finalize(decision):
    if decision != 'A':
        raise ValueError('This packaging command requires an explicit promotion decision A')
    root = ROOT / 'outputs/branch2/m5_final_day'
    attack = root / 'fresh_attack_holdout_01'
    candidate = json.loads((attack / 'candidate_metrics.json').read_text())
    baseline = json.loads((attack / 'v1_metrics.json').read_text())
    integrity = json.loads((attack / 'evaluation_integrity.json').read_text())
    if integrity['status'] != 'PASS' or integrity['candidate_root_sha256'] != ORIGIN_ROOT:
        raise ValueError('Missing integrity gate')
    decision_path = attack / 'final_decision.json'
    if decision_path.exists() or (ROOT / 'outputs/branch2/accepted_behavioral_v2').exists():
        raise ValueError('Refuse overwrite of decision or accepted package')
    reason = ('Scoped promotion to the current Moodle laboratory: candidate and v1 each detected 14/14 fresh runs '
              'and 2/2 in every supported class, with 14/14 correct mean-score XGBoost run classes. '
              'Candidate reconciled 68/68 windows versus 66/68 for v1. Locked benign evidence shows '
              '0/6 candidate sessions alerted versus 6/6 for v1, and raw novelty FPR 1/33 versus 31/33. '
              'No catastrophic class loss was observed. These small controlled samples do not establish statistical '
              'significance, other-platform performance or unseen-threat sensitivity.')
    write(decision_path, {'decision': decision, 'candidate_root_sha256': ORIGIN_ROOT,
        'reason': reason, 'scope': 'Local Moodle laboratory only',
        'decision_semantics': 'Qualitative research judgment under the existing protocol and finalization request; no predeclared automatic numeric promotion threshold',
        'protocol_reference': 'docs/branch2/m5_final_day/FINAL_DAY_RUNBOOK.md: promotion paragraph',
        'evidence_sha256': {str(p.relative_to(ROOT)): sha(p) for p in (
            attack / 'candidate_metrics.json', attack / 'v1_metrics.json', attack / 'evaluation_integrity.json',
            root / 'blind_benign_test_01/evaluation/metrics.json')},
        'no_retraining': True, 'no_holdout_based_tuning': True,
        'successful_exploitation_confirmed': False, 'statistical_significance_claimed': False})
    lines = ['# M5 fresh attack holdout and final decision', '', reason, '',
        'Decision **A — PROMOTE CANDIDATE**, within the validated local laboratory scope.', '',
        '| Class | Runs | Windows | Candidate detected runs | v1 detected runs |',
        '|---|---:|---:|---:|---:|']
    for c, v in candidate['per_class'].items():
        lines.append(f"| {c} | {v['runs']} | {v['windows']} | {v['detected_runs']} | {baseline['per_class'][c]['detected_runs']} |")
    lines += ['', '| Metric | Candidate | Model v1 |', '|---|---:|---:|',
        '| Reconciled attack windows detected | 68/68 | 66/68 |',
        '| Raw novelty anomaly windows | 65/68 | 35/68 |',
        '| Raw XGBoost correct-class windows | 66/68 | 66/68 |',
        '| Raw XGBoost BENIGN misses | 1 | 0 |',
        '| Raw XGBoost wrong attack-class windows | 1 | 2 |',
        '| UNKNOWN_ANOMALY windows | 1 | 0 |', '| Alert episodes | 16 | 16 |',
        '| Locked benign novelty FPR | 1/33 (3.03%) | 31/33 (93.94%) |',
        '| Locked benign alerted sessions | 0/6 | 6/6 |',
        '| Locked benign alert episodes | 0 | 23 |', '',
        'Window pairing is exact: same run, UTC interval, client, user-agent and source-record membership; '
        'each package uses its own frozen features and preprocessing. Run XGBoost classes use mean uncalibrated '
        'score vectors. Alerts use each comparator’s documented frozen episode policy (v1 persistence 1; candidate 2).', '',
        'Raw novelty, raw classifier, reconciled observations and emitted alert episodes are separate metrics. '
        'One isolated candidate UNKNOWN observation on the attack evidence did not itself escalate to an incident. '
        'Known-pattern decisions can alert immediately, as predeclared; persistence two concerns UNKNOWN escalation.', '',
        'Limits: two runs per attack class; six student-role benign protocols; controlled repetitions are not '
        'independent real users. Human replication, genuine unseen-class sensitivity and other LMS accuracy '
        'remain unvalidated. SQLI/XSS/PATH labels mean observable attempts, never exploit success. Apache combined '
        'logs omit POST bodies. Model scores are uncalibrated, not probabilities. No parameters were changed.', '',
        'All models were loaded from saved artifacts; predictions survived saved-model reload exactly. '
        'The blind benign results were consumed from their locked evaluation, not recomputed.']
    write_path = attack / 'report.md'
    if write_path.exists():
        raise ValueError('Refuse report overwrite')
    write_path.write_text('\n'.join(lines) + '\n')
    m = accept(root / 'candidate_freeze_01', decision_path,
               root / 'blind_benign_test_01/evaluation/metrics.json', attack / 'candidate_metrics.json',
               ROOT / 'outputs/branch2/accepted_behavioral_v2')
    print(json.dumps({'package_id': m['package_id'], 'root_sha256': m['root_sha256']}))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--decision', choices=['A'], required=True)
    finalize(parser.parse_args().decision)
