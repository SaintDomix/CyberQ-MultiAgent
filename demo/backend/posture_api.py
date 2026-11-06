"""Server-controlled operational posture routes, no arbitrary URLs or commands."""
import json
from fastapi import APIRouter, HTTPException
from .schemas import PostureAction,PassivePostureAction
from .adapters import finding
from .posture_projection import assessment_metadata


def router(service):
    r = APIRouter()
    engine = service.posture_service

    def view(job):
        if not job: return {'status': 'NOT_REEVALUATED', 'assessment_id': None, 'scope': 'CURRENT_OPERATIONAL_POSTURE'}
        result = {**job, **assessment_metadata(engine, job)}
        result['last_successful_zap_assessment'] = engine.retained_zap()
        if job['status'] in ('COMPLETE', 'PARTIAL'):
            q = service.current_posture_quality(job)
            result['current_posture_cqi'] = q.model_dump() if q else None
            result['cqi_comparison_semantics'] = 'Posture-only partial projection; D6 unavailable. Live CQI uses current behavioral journal separately.'
            history = [j for j in engine.history() if j['status'] in ('COMPLETE', 'PARTIAL')
                and j.get('target')==job.get('target') and j['started_at'] < job['started_at']
                and j.get('assessment_profile',j.get('mode'))==job.get('assessment_profile',job.get('mode'))]
            previous = history[0] if history else None
            before = service.current_posture_quality(previous) if previous else None
            result['before_after'] = {'previous_assessment_id': previous['assessment_id'] if previous else None,
                'before': before.overall if before else None, 'after': q.overall if q else None,
                'delta': q.overall-before.overall if q and before and q.overall is not None and before.overall is not None else None,
                'comparison_scope':'SAME_TARGET_AND_ASSESSMENT_PROFILE',
                'interpretation': 'Same-profile current canonical evidence comparison; weights/coefficients did not change. Missing checks are not PASS. Profile coverage differences are not evidence of remediation. No research CQI was overwritten.'}
        return result

    @r.post('/api/posture/assessments', status_code=202)
    def start(body: PostureAction):
        try:
            if body.mode=='PASSIVE_BASELINE':
                if body.target_url not in (None,'http://192.168.226.132/moodle/'):raise ValueError('Restricted target mismatch')
                return engine.start(body.target_id,body.zap_enabled,body.mode)
            return engine.start(body.target_id,body.zap_enabled,body.mode,target_url=body.target_url,authorized=body.authorized,
                full_config={'authentication_profile':body.authentication_profile,'discovery_profile':body.discovery_profile,
                    'exclude_regex':tuple(body.exclude_regex),'api_imports':body.api_imports})
        except ValueError: raise HTTPException(409, 'Assessment unavailable or already running; no unsafe request executed')

    @r.post('/api/scanners/zap/passive-assessment', status_code=202)
    def passive_start(body: PassivePostureAction):return start(body)

    @r.post('/api/posture/assessments/{assessment_id}/cancel')
    def cancel(assessment_id: str):
        try:return engine.cancel(assessment_id)
        except ValueError:raise HTTPException(409,'No owned running assessment')

    @r.get('/api/posture/assessments')
    def history():
        return {'items': [{**{k: v for k, v in j.items() if k != 'findings'},
                           'assessment_profile':j.get('assessment_profile',j.get('mode','PASSIVE_BASELINE'))} for j in engine.history()],
                'scope': 'CURRENT_OPERATIONAL_POSTURE'}

    @r.get('/api/posture/assessments/latest')
    def latest(): return view(engine.latest())

    @r.get('/api/posture/assessments/{assessment_id}')
    def detail(assessment_id: str): return view(engine.get(assessment_id))

    @r.get('/api/scanners')
    def scanners(): return {'items': engine.scanners(), 'active_scanner': 'PROFILE_DEPENDENT',
        'mode':'STANDARD','default_profile':'STANDARD','profiles':['STANDARD','FULL_AUTHORIZED','PASSIVE_BASELINE'],
        'standard':{'policy_id':'zap-standard-1.0','hard_assessment_seconds':480,'active_scanner':'SELECTIVE_PROTECTED_CONTEXT',
            'requires_explicit_authorization':True,'target_configurable':True},
        'full_authorized':{'active_scanner':'PROTECTED_CONTEXT','requires_explicit_authorization':True,
            'target_configurable':True,'automatic_execution':False}}

    @r.get('/api/scanners/zap')
    @r.get('/api/scanners/zap/status')
    def zap_status():
        provider = engine.providers['zap']
        status = provider.readiness() if hasattr(provider, 'readiness') else provider.health()
        latest = engine.latest()
        current_state = latest['provider_statuses']['zap'] if latest else 'NONE'
        fresh_count = latest.get('raw_finding_counts', {}).get('zap', 0) if latest and current_state in ('COMPLETE','PARTIAL') else 0
        full=bool(latest and latest.get('mode') in ('STANDARD','FULL_AUTHORIZED'))
        if full and latest['status']=='RUNNING':
            status.update(assessment_readiness='BUSY',reason_code='OWNED_DAST_ASSESSMENT_RUNNING')
        return {**status, 'target': latest.get('target') if latest else 'http://192.168.226.132/moodle/',
                'mode': latest['mode'] if full else 'PASSIVE_BASELINE',
                'assessment_profile':latest.get('assessment_profile',latest.get('mode')) if latest else 'STANDARD',
                'active_scanner':'CONTROLLED_'+latest['mode'] if full else 'DISABLED',
                'zap_execution':latest.get('zap_execution') if full else None,
                'runtime_status': status.get('runtime_status',status['status']),
                'assessment_readiness': status.get('assessment_readiness','POLICY_BLOCKED'),
                'latest_attempt_status': current_state,
                'latest_attempt_reason': latest.get('provider_reasons',{}).get('zap') if latest else None,
                'last_successful_assessment': engine.retained_zap(),
                'fresh_alerts_in_current_run': fresh_count,
                'authenticated_coverage': 'NOT_VALIDATED', 'last_assessment_id': latest['assessment_id'] if latest else None,
                'assessment_state': latest['provider_statuses']['zap'] if latest else 'NOT_RUN',
                'alerts_count': latest['raw_finding_counts'].get('zap') if latest and latest.get('raw_finding_counts') else None,
                'raw_evidence_integrity': 'HASH_VERIFIED' if latest and latest.get('evidence_hashes') else 'NOT_AVAILABLE'}

    @r.get('/api/scanners/zap/findings')
    def zap_findings(view: str = 'current'):
        if view not in ('current','retained'): raise ValueError('Unknown ZAP evidence view')
        if view=='retained':
            meta=engine.retained_zap()
            items=[finding({**f,'evidence_sources':[f['evidence_source'] if f['evidence_source'] in ('ZAP_ACTIVE','ZAP_PASSIVE') else 'OWASP_ZAP']}).model_copy(update={'assessment_scope':'RETAINED_ZAP_EVIDENCE'}) for f in engine.retained_zap_findings()]
            return {'items':items,'assessment_id':meta['assessment_id'] if meta else None,
                    'scope':'RETAINED_ZAP_EVIDENCE','counted_as_fresh_in_current_cqi':False}
        latest = engine.current()
        return {'items': [finding(f) for f in latest['findings'] if set(f['evidence_sources'])&{'OWASP_ZAP','ZAP_ACTIVE','ZAP_PASSIVE'}] if latest else [],
                'assessment_id': latest['assessment_id'] if latest else None}

    @r.get('/api/scanners/zap/active-status')
    def zap_active_status():
        latest = engine.latest()
        return {'assessment_id': latest['assessment_id'] if latest else None,
                'assessment_profile': latest.get('assessment_profile',latest.get('mode')) if latest else None,
                'status': latest.get('zap_active_status', 'NOT_RUN') if latest else 'NOT_RUN',
                'summary': latest.get('zap_active_summary') if latest else None,
                'semantics': 'Current STANDARD/FULL_AUTHORIZED execution, or restricted-profile safety gate; unavailable is not scan completion.'}

    @r.get('/api/scanners/zap/capabilities')
    def zap_capabilities():
        latest=engine.latest()
        return {'assessment_id':latest['assessment_id'] if latest else None,
            'inventory':latest.get('zap_execution',{}).get('inventory') if latest else None,
            'fuzzer_job_contract':{'execution':'NOT_IMPLEMENTED; specialized configured job required',
                'required':['current_assessment_id','current_message_id','in_scope_target',
                    'injection_locations','server_controlled_payload_source','processors','finite_budget'],
                'unbounded_fuzz_everything':False},
            'authentication':'NOT_CONFIGURED; profile architecture supports future verified environment/session references'}

    return r
