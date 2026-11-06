"""Application projection: immutable evidence + read-only runtime -> frozen Fusion."""
from collections import Counter
import copy
import json
from pathlib import Path
import threading
import time
import hashlib
import sqlite3
from behavioral_runtime.package import verify
from behavioral_v2.episodes import episodes
from branch2.events import utc
from branch2.live_storage import digest
from fusion.pipeline import assemble
from fusion.schema import DIMENSIONS, CATEGORIES
from .adapters import finding, observation, episode, fusion_event
from .config import confined, ROOT, SOURCE_HASHES
from .privacy import sanitize
from .runtime import read_journal, SourceUnavailable, LiveControl
from .schemas import CQI, Dimension, FusionEvent, State
from .explainability import incident_explanation
from .explanation_sources import replay_features, key as feature_key
from posture.orchestration import PostureAssessmentOrchestrator
from coursework.posture import CourseworkPosture
from posture.model import not_reevaluated
from posture.fusion_bridge import current_correlations


def read(path):
    return json.loads(Path(path).read_text())


def bound_read(path, kind):
    if hashlib.sha256(Path(path).read_bytes()).hexdigest() != SOURCE_HASHES[kind]:
        raise SourceUnavailable('Frozen application source binding failed: ' + kind)
    return read(path)


class Application:
    def __init__(self, config, control=None, posture_service=None):
        self.config = config
        self.control = control or LiveControl(config)
        self.lock = threading.RLock()
        self.cache = {}
        self.started = time.monotonic()
        self.model_cache = None
        self.current_mode = config.mode
        posture_type = CourseworkPosture if Path(config.repository).resolve() == ROOT else PostureAssessmentOrchestrator
        self.posture_service = posture_service or posture_type(config.repository,
            bound_read(confined(config.repository, config.posture), 'posture'))

    def model(self):
        path = confined(self.config.repository, self.config.accepted)
        try:
            fingerprint = [(str(p.relative_to(path)), p.stat().st_size, p.stat().st_mtime_ns, p.stat().st_ctime_ns)
                           for p in sorted(path.rglob('*')) if p.is_file()]
            source_manifest = read(path / 'accepted_manifest.json')
            for name in sorted(source_manifest['code_sha256']):
                code = confined(ROOT, name)
                stat = code.stat()
                fingerprint.append((name, stat.st_size, stat.st_mtime_ns, stat.st_ctime_ns))
            if self.model_cache and fingerprint == self.model_cache[0]:
                return copy.deepcopy(self.model_cache[1])
            manifest = verify(path, project=ROOT)
            if manifest['root_sha256'] != self.config.expected_root:
                raise ValueError('Unexpected accepted identity')
            schema = read(path / 'model/feature_schema.json')
            value = {'integrity': 'VERIFIED', 'name': 'Behavioral v2', 'package_id': manifest['package_id'],
                'root_sha256': manifest['root_sha256'], 'candidate_origin_id': manifest['candidate_origin_id'],
                'feature_count': len(schema['feature_order']), 'schema_version': schema['version'],
                'schema_sha256': schema['sha256'], 'adapter': manifest['adapter'],
                'novelty_detector': manifest['frozen_config']['selected_model'],
                'novelty_threshold': manifest['frozen_config']['thresholds'][manifest['frozen_config']['selected_model']],
                'confidence_threshold': manifest['frozen_config']['confidence_threshold'],
                'persistence': manifest['frozen_config']['persistence'], 'runtime': manifest['runtime'],
                'classifier': 'XGBoost', 'confidence_semantics': 'UNCALIBRATED_MODEL_SCORE',
                'limitations': read(path / 'limitations.json'), 'training_performed': False}
            self.model_cache = (fingerprint, value)
            return copy.deepcopy(value)
        except (OSError, ValueError, KeyError, TypeError):
            self.model_cache = None
            return {'integrity': 'FAILED', 'name': 'Behavioral v2', 'package_id': None,
                    'error': 'Accepted package hash/schema/source verification failed; behavior and CQI unavailable.'}

    def research(self):
        if self.model()['integrity'] != 'VERIFIED':
            raise SourceUnavailable('Accepted model verification failed')
        accepted = confined(self.config.repository, self.config.accepted)
        benign = read(accepted / 'blind_benign_metrics.json')
        attack = read(accepted / 'fresh_attack_metrics.json')
        v1 = bound_read(confined(self.config.repository, self.config.attack) / 'v1_metrics.json', 'v1_attack_metrics')
        decision = read(accepted / 'acceptance_decision.json')
        expected = decision['evidence_sha256']
        for suffix, value in (('candidate_metrics.json', attack), ('v1_metrics.json', v1)):
            path = confined(self.config.repository, self.config.attack) / suffix
            keys = [k for k in expected if k.endswith('/' + suffix)]
            # The copied accepted candidate metric is independently hash-bound.
            if len(keys) != 1 or hashlib.sha256(path.read_bytes()).hexdigest() != expected[keys[0]]:
                raise SourceUnavailable('Locked research comparison hash failed')
        return {'benign': {'candidate': benign['candidate'], 'model_v1': benign['model_v1'],
                    'support': 'Six fresh student-role browser sessions; controlled laboratory evidence'},
                'attack': {'candidate': attack, 'model_v1': v1,
                    'support': 'Two fresh runs per seven classes; attempt patterns, not exploit success'},
                'limitations': self.model()['limitations'], 'recomputed': False}

    def replay(self, source, run_id, model):
        import hashlib
        if source == 'BENIGN_TEST':
            path = confined(self.config.repository, self.config.benign) / 'candidate_predictions.json'
            hashes = bound_read(path.parent / 'artifact_manifest.json', 'benign_manifest')['files']
            if hashlib.sha256(path.read_bytes()).hexdigest() != hashes[path.name]['sha256']:
                raise SourceUnavailable('Locked benign prediction hash mismatch')
            rows = read(path)
        else:
            path = confined(self.config.repository, self.config.attack) / 'predictions.json'
            hashes = bound_read(path.parent / 'artifact_hashes.json', 'attack_manifest')['files']
            if hashlib.sha256(path.read_bytes()).hexdigest() != hashes[path.name]['sha256']:
                raise SourceUnavailable('Locked attack prediction hash mismatch')
            rows = read(path)['candidate']
        available_runs = sorted({p['run_id'] for p in rows})
        if run_id and run_id not in available_runs:
            raise SourceUnavailable('Unknown replay run ID')
        transformed = []
        for i, raw in enumerate(sorted(rows, key=lambda p: (p['window_start'], p['run_id'], p['client_id'], p['user_agent_id'])), 1):
            if run_id and raw['run_id'] != run_id: continue
            p = copy.deepcopy(raw)
            p.update(record_id='observation-' + digest(raw), sequence=i,
                session_id='accepted-replay-' + p['run_id'], model_id=model['package_id'],
                schema_sha256=model['schema_sha256'], feature_schema_version=model['schema_version'],
                # This is an explicit replay clock derived from observed window
                # time, never an invented model-emission timestamp.
                emitted_at_utc=p['window_end'], time_semantics='REPLAY_WINDOW_END; original offline emitted_at unavailable',
                sequence_semantics='Stable replay ordinal; not an asserted original live sequence')
            transformed.append(p)
        es = [e for e in episodes(transformed, model['persistence']) if e['alert']]
        return transformed, es, {'available': True, 'process_running': False,
            'process_state': 'ACCEPTED_EVIDENCE_REPLAY', 'source': str(path.relative_to(self.config.repository)),
            'available_runs': available_runs, 'replay_source': source, 'selected_run': run_id,
            'sqlite_status': 'NOT_USED_FOR_LOCKED_REPLAY', 'network_requests': 0,
            'time_semantics': 'Evidence window end, not wall clock or asserted original emission time'}

    def snapshot(self, mode=None, replay='ATTACK_HOLDOUT', run_id=None, *, assessment_id=None, evidence=None):
        mode = mode or self.current_mode
        if mode not in ('LIVE_LAB', 'ACCEPTED_REPLAY') or replay not in ('ATTACK_HOLDOUT', 'BENIGN_TEST'):
            raise ValueError('Invalid mode/source')
        with self.lock:
            model = self.model()
            posture_path = confined(self.config.repository, self.config.posture)
            raw_posture = bound_read(posture_path, 'posture')
            assessment = None
            if mode == 'LIVE_LAB':
                assessment = self.posture_service.get(assessment_id) if assessment_id else self.posture_service.current()
                if assessment and assessment['status'] not in ('COMPLETE','PARTIAL'):
                    raise ValueError('A completed immutable posture assessment is required')
                raw_posture = (assessment['findings'] if assessment else
                    not_reevaluated(raw_posture, set(), 'not-assessed', None))
                posture_path = (self.posture_service.location(assessment['assessment_id']) / 'snapshot.json'
                                if assessment else self.config.repository / 'runtime/posture/not-assessed')
            findings = [finding(p) for p in raw_posture]
            error = None; rows = []; raw_episodes = []; live_feature_values = {}; live_evidence = {}
            runtime = {'available': False, 'process_running': False, 'source': self.config.apache_source}
            if model['integrity'] == 'VERIFIED':
                try:
                    if mode == 'ACCEPTED_REPLAY':
                        rows, raw_episodes, runtime = self.replay(replay, run_id, model)
                    elif self.control.session and not assessment_id:
                        rows, raw_episodes, runtime = read_journal(self.control.session, model['package_id'], model['schema_sha256'], include_features=True)
                        live_feature_values = {p['record_id']: p.pop('_explanation_features', {}) for p in rows}
                        live_evidence = {p['record_id']: dict(p.pop('_explanation_evidence', {}),
                            package_root_sha256=model['root_sha256']) for p in rows}
                        if self.control.process is not None:
                            runtime.update(self.control.status())
                    else:
                        runtime.update(self.control.status())
                        error = ('Historical posture has no paired Behavioral snapshot; D6 is unavailable.' if assessment_id else
                            'No accepted-v2 live runtime session selected. Replay data is not substituted.')
                except (OSError, ValueError, KeyError, TypeError, sqlite3.Error) as exc:
                    error = str(exc) if isinstance(exc, SourceUnavailable) else 'Behavior source unavailable or invalid'
                    runtime.update(self.control.status())
            else:
                error = model['error']
            if mode=='LIVE_LAB' and assessment and assessment.get('target')!='http://192.168.226.132/moodle/':
                # Saved Behavioral v2 telemetry has a validated Moodle-lab identity.
                # A configurable DAST target must never inherit another platform's D6.
                rows=[];raw_episodes=[]
                runtime.update(available=False,target_identity_match=False)
                error='Current DAST target has no matching configured behavioral telemetry; D6 unavailable.'
            generation = digest({'mode': mode, 'posture': raw_posture, 'predictions': rows,
                                 'episodes': raw_episodes, 'model': model, 'error': error})
            cached = self.cache.get(generation)
            if cached is None:
                incident_models = [episode(e, model['package_id'], mode == 'ACCEPTED_REPLAY') for e in raw_episodes]
                assigned = {oid: e.episode_id for e in incident_models for oid in e.observation_ids}
                feature_values = {}
                if mode == 'ACCEPTED_REPLAY':
                    try:
                        feature_values = replay_features(self.config.repository, rows, replay, model['schema_sha256'])
                    except (OSError, ValueError, KeyError, TypeError):
                        pass  # Saved deviations remain available, explicitly partial.
                observations = [observation(p, assigned, model['package_id'],
                    features=feature_values.get(feature_key(p), live_feature_values.get(p['record_id'])),
                    feature_evidence=live_evidence.get(p['record_id'])) for p in rows]
                for e in incident_models:
                    e.explanation = incident_explanation(e, observations)
                artifacts = None; fusion_models = []; cqi = None
                if (rows or (mode == 'LIVE_LAB' and assessment)) and model['integrity'] == 'VERIFIED':
                    artifacts = assemble(raw_posture, rows, str(posture_path.relative_to(self.config.repository)),
                                         runtime['source'], as_of=assessment['completed_at'] if not rows else None,
                                         lookback=self.config.lookback)
                    if mode == 'LIVE_LAB': artifacts['correlations'] = current_correlations(artifacts)
                    posture_ids = {p['evidence_id']: p['source_record_id'] for p in artifacts['canonical_evidence'] if p['source_branch'] == 'BRANCH1_POSTURE'}
                    for e in incident_models:
                        associations = [c for c in artifacts['correlations'] if set(c['behavior_record_ids']) & set(e.observation_ids)]
                        for c in associations: fusion_models.append(fusion_event(c, e, posture_ids))
                        if not associations:
                            fusion_models.append(FusionEvent(fusion_event_id='fusion-' + digest([e.episode_id, 'NO_CORRELATION']),
                                behavior_episode_id=e.episode_id, related_posture_finding_ids=[], relationship_type='NO_CORRELATION',
                                context_strength='NONE', contextual_severity=e.severity, created_at=e.last_seen,
                                rule_id='NO_REVIEWED_SEMANTIC_MATCH', explanation='No reviewed matching posture evidence. No context, causal claim or extra CQI penalty is inferred.'))
                        e.contextual_posture_links = sorted({fid for c in fusion_models if c.behavior_episode_id == e.episode_id for fid in c.related_posture_finding_ids})
                    cqi = self.quality(artifacts, findings, incident_models)
                cached = {'posture': findings, 'observations': observations, 'incidents': incident_models,
                          'fusion': fusion_models, 'cqi': cqi, 'artifacts': artifacts}
                self.cache = {generation: cached}  # Bounded current snapshot cache.
            data = copy.deepcopy(cached)
            runtime['uptime_seconds'] = round(time.monotonic() - self.started, 1)
            runtime['freshness'] = ('REPLAY_NOT_LIVE' if mode == 'ACCEPTED_REPLAY' else
                'MONITOR_RUNNING' if runtime.get('process_running') is True else 'RETAINED_OR_EXTERNALLY_MANAGED_SNAPSHOT')
            status = State(mode=mode, source_label='ACCEPTED EVIDENCE REPLAY' if mode == 'ACCEPTED_REPLAY' else 'LIVE LABORATORY TELEMETRY',
                model_integrity=model['integrity'], package_id=model.get('package_id'),
                posture_counts=dict(Counter(f.status for f in findings)), observation_count=len(rows),
                incident_count=len(data['incidents']), cqi_available=data['cqi'] is not None,
                as_of=data['cqi'].as_of if data['cqi'] else None, source_generation=generation,
                last_error=error, runtime=runtime, target={'target_id': 'moodle-local', 'name': 'Moodle Local Lab',
                    'platform': 'Moodle', 'base_url': 'http://192.168.226.132/moodle/', 'authorized': True},
                posture_scope='RESEARCH_BASELINE' if mode == 'ACCEPTED_REPLAY' else 'CURRENT_OPERATIONAL_POSTURE',
                posture_assessment=({k: v for k, v in assessment.items() if k != 'findings'} if assessment else
                    {'status': 'NOT_REEVALUATED' if mode == 'LIVE_LAB' else 'IMMUTABLE_RESEARCH_BASELINE',
                     'coverage': {'status': 'PARTIAL' if mode == 'LIVE_LAB' else 'RESEARCH_BASELINE'}}))
            if mode == 'LIVE_LAB' and data['cqi']:
                q = data['cqi']
                partial = not assessment or assessment['coverage']['status'] != 'FULL'
                if partial: q.overall_status = 'PARTIAL_EVIDENCE'
                q.policy.update(assessment_scope='CURRENT_CQI', coverage='PARTIAL' if partial else 'FULL',
                    posture_assessment_id=assessment['assessment_id'] if assessment else None,
                    missing_checks_are_pass=False)
                self.current_coverage(q, findings)
                if assessment and assessment.get('target')!='http://192.168.226.132/moodle/':
                    status.target={'target_id':assessment['target_id'],'name':'Authorized DAST application',
                        'platform':'Configured web application','base_url':assessment['target'],'authorized':True}
                attempt = self.posture_service.latest()
                if attempt and (not assessment or attempt['assessment_id'] != assessment['assessment_id']):
                    status.posture_assessment.update(latest_attempt_id=attempt['assessment_id'],
                        latest_attempt_status=attempt['status'], current_posture_available=False)
            elif data['cqi']:
                data['cqi'].policy.update(assessment_scope='RESEARCH_CQI', coverage='FROZEN_RESEARCH_EVIDENCE')
            if evidence is not None:
                evidence.update(assessment=assessment,rows=rows,historical=bool(assessment_id))
            return {**data, 'status': status, 'model': model}

    def current_posture_quality(self, assessment=None):
        """Posture-only current view when no closed behavioral window exists."""
        assessment = assessment or self.posture_service.current()
        if not assessment: return None
        artifacts = assemble(assessment['findings'], [], 'runtime/posture/' + assessment['assessment_id'],
                             'NO_BEHAVIOR_EVIDENCE', as_of=assessment['completed_at'], lookback=self.config.lookback)
        q = self.quality(artifacts, [finding(r) for r in assessment['findings']], [])
        q.overall_status = 'PARTIAL_EVIDENCE'
        q.policy.update(assessment_scope='CURRENT_CQI', coverage='PARTIAL',
            posture_assessment_id=assessment['assessment_id'], missing_checks_are_pass=False,
            behavior_scope='NO_BEHAVIOR_EVIDENCE; D6 unavailable')
        self.current_coverage(q, [finding(r) for r in assessment['findings']])
        return q

    def scientific_quality(self, mode=None, replay='ATTACK_HOLDOUT', run_id=None, as_of=None, *, bound_snapshot=None):
        """Versioned read-only policy reanalysis; old CQI/snapshots stay v1.

        LIVE uses an explicit wall-clock as-of, never latest historical event time
        masquerading as current telemetry. Replay uses its declared evidence clock.
        """
        from datetime import datetime, timezone
        from cqi_v2 import evaluate,registry
        from cqi_v2.model import leaves,root_for
        mode=mode or self.current_mode
        evidence={}
        if bound_snapshot is None:
            snap=self.snapshot(mode,replay,run_id,evidence=evidence)
        else:
            snap,evidence=bound_snapshot
        if snap['model']['integrity']!='VERIFIED':raise SourceUnavailable('Accepted model integrity failed')
        assessment=evidence.get('assessment')
        posture_rows=assessment['findings'] if assessment else (bound_read(confined(self.config.repository,self.config.posture),'posture') if mode=='ACCEPTED_REPLAY' else [])
        if as_of is None:
            as_of=(assessment['completed_at'] if evidence.get('historical') else datetime.now(timezone.utc).isoformat() if mode=='LIVE_LAB' else
                   snap['status'].as_of or max(o.window_end for o in snap['observations']))
        rows=evidence['rows']
        target=assessment.get('target') if assessment else None
        known={};base_ids={s['control_id'] for s in registry()['controls']}
        if assessment:
            for previous in self.posture_service.history():
                if (previous.get('target')!=assessment.get('target') or previous.get('assessment_profile',previous.get('mode'))!=assessment.get('assessment_profile',assessment.get('mode')) or previous.get('started_at','')>assessment['started_at']):continue
                prior=self.posture_service.get(previous['assessment_id'])
                for parent in prior.get('findings',[]):
                    for r in leaves(parent):
                        fid=r['finding_id'];root,dim=root_for(fid);dim=dim or CATEGORIES.get(r['category'])
                        if fid not in base_ids and dim:
                            known[fid]={'control_id':fid,'root_id':r.get('weakness_key') or r.get('canonical_finding_id') or root,
                                'dimension':dim,'platform_scope':'GENERIC_HTTP'}
        result=evaluate(posture_rows,as_of=as_of,observations=rows,incidents=snap['incidents'],known_controls=list(known.values()),
            posture_time=assessment['completed_at'] if assessment else as_of if mode=='ACCEPTED_REPLAY' else None,
            platform='generic_web' if target and target!='http://192.168.226.132/moodle/' else 'moodle')
        result['comparison_context']={'mode':mode,'assessment_id':assessment['assessment_id'] if assessment else None,
            'source_scope':'VERSIONED_POLICY_REANALYSIS; immutable source findings unchanged',
            'legacy_policy_version':'fusion-cqi-1.1','legacy_endpoint':'/api/cqi',
            'policy_change_is_security_change':False,'as_of_semantics':'POSTURE_ONLY_AT_ACQUISITION; D6_NOT_PAIRED' if evidence.get('historical') else 'EXPLICIT_REPLAY_EVIDENCE_TIME' if mode=='ACCEPTED_REPLAY' else 'CURRENT_UTC_OR_EXPLICIT_AS_OF',
            'old_scalar':snap['cqi'].overall if snap['cqi'] else None}
        result=sanitize(result)
        result['result_sha256']=digest({k:v for k,v in result.items() if k!='result_sha256'})
        return result

    @staticmethod
    def current_coverage(q, findings):
        missing = {f.dimension for f in findings if f.status == 'NOT_REEVALUATED'}
        for dimension in q.dimensions:
            if dimension.dimension_id in missing and dimension.score is not None:
                dimension.status = 'PARTIAL_EVIDENCE'
                dimension.explanation += ' Additional checks were NOT_REEVALUATED; this score describes observed controls only.'
        q.policy['unavailable_dimensions'] = [d.dimension_id for d in q.dimensions if d.score is None]
        q.policy['comparison_caution'] = 'Partial current CQI is not evidence of improvement over full research CQI; missing checks are not PASS.'

    def quality(self, artifacts, findings, incidents):
        clusters = sorted(artifacts['fusion_clusters'], key=lambda c: (-(c['contribution'] or 0), c['cluster_id']))
        contributors = [sanitize(c) for c in clusters if c['contribution'] and c['contribution'] > 0]
        selected = set(artifacts['cqi']['behavior_horizon']['selected_record_ids'])
        active = [e for e in incidents if selected & set(e.observation_ids)]
        dims = []
        for d in artifacts['dimensions']:
            drivers = [c for c in contributors if c['dimension'] == d['dimension']]
            dims.append(Dimension(dimension_id=d['dimension'], name=DIMENSIONS[d['dimension']], score=d['quality'],
                risk_index=d['risk'], status=d['score_status'], main_contributors=drivers,
                finding_count=sum(f.dimension == d['dimension'] for f in findings),
                active_incident_count=len(active) if d['dimension'] == 'D6' else 0, policy_weight=d['baseline_weight'],
                explanation=f"{d['scored_cluster_count']} scored root/episode clusters; quality = 100 × product(1 − contribution). Zero-risk and coverage exclusions retain source semantics."))
        policy = artifacts['cqi']
        return CQI(overall=policy['cqi'], overall_status=policy['score_status'], dimensions=dims,
            contributors=contributors, evidence_ids=sorted({e for c in clusters for e in c['member_evidence_ids']}),
            deductions=[{'cluster_id': c['cluster_id'], 'dimension': c['dimension'],
                'standalone_quality_reduction': 100 * c['contribution'], 'semantics': 'Standalone effect; deductions are NOT additive'} for c in contributors],
            active_behavioral_impact={'active_incident_count': len(active),
                'raw_selected_observations': len(selected), 'selected_observation_ids': sorted(selected),
                'D6_scoring_semantics': 'Frozen CQI includes raw behavioral observations, including suppressed UNKNOWN observations. Incident persistence is a separate policy; no CQI suppression is applied.'},
            sensitivity=artifacts['sensitivity'], policy={k: policy[k] for k in ('formula', 'formula_version',
                'weighting', 'weights_are_empirically_calibrated', 'coefficient_semantics', 'coefficients',
                'normalized_available_dimension_weights', 'display_rounding', 'limitations')},
            as_of=policy['behavior_horizon']['as_of'])
