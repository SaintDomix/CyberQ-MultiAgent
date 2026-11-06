"""Predetermined small counterfactual/sensitivity design; not new live evidence."""
from dataclasses import replace
from copy import deepcopy
from .policy import Policy

TIME='2026-10-28T18:14:10+00:00'
CONTROLS=[{'control_id':'CONTROL-'+d,'root_id':'CONTROL-'+d,'dimension':d,'platform_scope':'GENERIC_HTTP'} for d in ('D1','D2','D3','D4','D5')]
CATEGORY={'D1':'Security Headers','D2':'Authentication & Session','D3':'Exposure','D4':'Patch & Vulnerability Intelligence','D5':'Runtime Hardening'}

def finding(d='D1',status='FAIL',severity='HIGH',confirmation='CONFIRMED',eid=None):
    return {'finding_id':'CONTROL-'+d,'evidence_id':eid or 'fixture-'+d,'category':CATEGORY[d],
        'finding_type':'Constructed independent control '+d,'check_result':status,
        'confirmation_status':confirmation,'severity':severity,'evidence_source':'FIXTURE_NATIVE',
        'end_utc':'2026-10-28T18:14:00+00:00','provenance':{'fixture':True}}

def normal():
    return {'record_id':'fixture-normal','sequence':1,'window_start':'2026-10-28T18:14:00+00:00',
        'window_end':TIME,'emitted_at_utc':TIME,'reconciled_label':'BENIGN','reconciliation':{'decision':'BENIGN'},
        'novelty_anomalous':False,'novelty_state':'NORMAL'}

def incident(label='SQLI_ATTEMPT',eid='fixture-episode'):
    o=normal();o.update(record_id=eid+'-observation',reconciled_label=label,novelty_anomalous=True,
        novelty_state='ANOMALOUS',reconciliation={'decision':label})
    e={'episode_id':eid,'class':label,'start_time':o['window_start'],'last_seen':o['window_end'],
       'observation_ids':[o['record_id']],'observation_count':2 if label=='UNKNOWN_ANOMALY' else 1}
    return o,e

def scenarios():
    clean=[finding(d,'PASS') for d in CATEGORY]
    def make(rows=None,obs=None,es=None,**kw):return {'posture_rows':deepcopy(clean if rows is None else rows),'as_of':TIME,
        'observations':deepcopy([normal()] if obs is None else obs),'incidents':deepcopy([] if es is None else es),'controls':CONTROLS,**kw}
    serious=deepcopy(clean);serious[0]=finding('D1',severity='CRITICAL')
    low=deepcopy(clean);low[0]=finding('D1',severity='LOW')
    weak=deepcopy(clean);weak[0]=finding('D1',severity='CRITICAL',confirmation='NOT_CONFIRMED')
    fixed=deepcopy(serious);fixed[0]['lifecycle']={'state':'REMEDIATED','verified':True,'verified_at':TIME,'evidence_reference':'fixture-recheck-hash'}
    extra=deepcopy(serious);extra[2]=finding('D3',severity='HIGH')
    duplicate=deepcopy(serious)+[dict(serious[0],evidence_id='fixture-zap',evidence_source='FIXTURE_ZAP')]
    missing=deepcopy(clean);missing[4]=finding('D5','NOT_AVAILABLE',confirmation='NOT_TESTED')
    role=deepcopy(clean);role[1]=finding('D2','NOT_ASSESSED',confirmation='NOT_TESTED')
    partial=deepcopy(clean);partial[0]=finding('D1','PARTIAL')
    generic=make(platform='generic_web');generic['controls']=CONTROLS+[{'control_id':'MOODLE-ONLY','root_id':'MOODLE-ONLY','dimension':'D5','platform_scope':'PLATFORM_MOODLE'}]
    o,e=incident();u,ue=incident('UNKNOWN_ANOMALY','fixture-unknown');o2,e2=incident('BRUTE_FORCE','fixture-second')
    return {
      'normal_complete':make(), 'confirmed_critical':make(serious),'verified_remediation':make(fixed),
      'independent_additional_weakness':make(extra),'duplicate_native_zap':make(duplicate),
      'only_low_confidence_indication':make(weak),'low_severity':make(low),
      'missing_internal_configuration':make(missing),'missing_role_visibility':make(role),
      'generic_moodle_inapplicable':generic,'partial_scan':make(partial),
      'known_incident':make(obs=[o],es=[e]),'unknown_incident':make(obs=[u],es=[ue]),
      'isolated_unknown_observation':make(obs=[u]),'two_independent_incidents':make(obs=[o,o2],es=[e,e2]),
      'duplicate_episode':make(obs=[o,o],es=[e,e]),'verified_incident_closure':make(obs=[o],es=[e],closures=[{'episode_id':e['episode_id'],'state':'CLOSED','verified':True,'verified_at':TIME,'evidence_reference':'fixture-closure-review'}]),
      'missing_behavior':make(obs=[]),'old_incident_no_recent_telemetry':
          {'posture_rows':deepcopy(clean),'controls':CONTROLS,'as_of':'2026-10-28T18:30:00+00:00','observations':[o],'incidents':[e]},
      'temporal_activity_recovery':{'posture_rows':deepcopy(clean),'controls':CONTROLS,'as_of':'2026-10-28T18:30:00+00:00','observations':[dict(normal(),record_id='new-normal',window_start='2026-10-28T18:29:50+00:00',window_end='2026-10-28T18:30:00+00:00',emitted_at_utc='2026-10-28T18:30:00+00:00')],'incidents':[e]}}

def sensitivity_policies():
    p=Policy();out={'baseline':p}
    for d in p.weights:
        for multiplier in (.8,1.2):out[f'weight_{d}_{multiplier}']=replace(p,weights={k:v*(multiplier if k==d else 1) for k,v in p.weights.items()})
    for multiplier in (.8,1.2):
        out[f'severity_{multiplier}']=replace(p,severity={k:min(1,v*multiplier) for k,v in p.severity.items()})
        out[f'reliability_{multiplier}']=replace(p,reliability={k:min(1,v*multiplier) for k,v in p.reliability.items()})
        out[f'behavior_{multiplier}']=replace(p,behavior={k:min(1,v*multiplier) for k,v in p.behavior.items()})
    for v in (.25,.75):out[f'partial_observability_{v}']=replace(p,partial_observability=v)
    for v in (10.,30.):out[f'compensation_points_{v}']=replace(p,compensation_points=v)
    return out
