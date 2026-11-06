#!/usr/bin/env python3
"""Bounded policy validation/reanalysis; synthetic scenarios never become live evidence."""
import argparse
import csv
from dataclasses import asdict
import hashlib
import json
from pathlib import Path
import shutil
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'src'),str(ROOT)]
from cqi_v2 import evaluate,compare,Policy,registry
from cqi_v2.validation import scenarios,sensitivity_policies
from fusion.pipeline import assemble
from branch2.reconciliation import reconcile
from branch2.live_storage import digest
from demo.backend.services import Application
from demo.backend.config import Config
from behavioral_runtime.package import verify

def write(out,name,data):
    with (out/name).open('x') as f:json.dump(data,f,indent=2,sort_keys=True,allow_nan=False);f.write('\n')

def old_fixture(s):
    # Mechanical adapter to old required wire fields; no empirical interpretation.
    posture={}
    for row in s['posture_rows']:
        r=dict(row)
        if r['check_result'] in ('NOT_AVAILABLE','NOT_ASSESSED'):r['check_result']='NOT_TESTED'
        posture.setdefault(r['finding_id'],r)  # Canonical duplicates score once before Fusion.
    rows=[]
    for i,o in enumerate({r['record_id']:r for r in s['observations']}.values(),1):
        decision=o['reconciliation']['decision'];anomalous=o.get('novelty_anomalous',False)
        label=decision if decision not in ('UNKNOWN_ANOMALY','UNCERTAIN') else 'BENIGN'
        score=.99 if label!='BENIGN' else .7 if decision=='UNKNOWN_ANOMALY' else .99
        rows.append(dict(o,sequence=i,reconciliation=reconcile(anomalous,label,score,.8),
            if_anomalous=anomalous,xgb_label=label,xgb_confidence=score,confidence_calibrated=False,training_performed=False,
            client_id='fixture-client',user_agent_id='fixture-agent',session_id='fixture-session',source_file='synthetic-fixture'))
    try:return assemble(list(posture.values()),rows,'synthetic-posture','synthetic-behavior',as_of=s['as_of'])['cqi']['cqi']
    except (ValueError,KeyError,TypeError):return None

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--out',default='outputs/cqi/task3a_02')
    parser.add_argument('--baseline',default='outputs/cqi/task3a_02/baseline_legacy_outputs.json',help='Preserved old-policy comparison receipt; read-only')
    a=parser.parse_args()
    out=(ROOT/a.out).resolve()
    if not out.is_relative_to(ROOT/'outputs/cqi') or out.exists():raise ValueError('New CQI output required')
    if shutil.disk_usage(ROOT).free<500_000_000:raise ValueError('Disk guard')
    out.mkdir(parents=True)
    ss=scenarios();policies=sensitivity_policies();policy=Policy()
    # Immutable compact design before calculating scenario or retained-source scores.
    write(out,'design_protocol.json',{'policy':policy.export(),'registry_sha256':registry()['sha256'],
        'scenario_names':list(ss),'scenario_count':len(ss),'sensitivity_variants':{k:v.export() for k,v in policies.items()},
        'aggregation_candidates':['arithmetic','geometric','guarded_geometric'],
        'selection':'Guarded geometric selected by explicit maximum 20-point compensation requirement, not best fit to observed scores. ln(2) maps one unit of hazard to half dimension quality. All are ordinal policy assumptions.',
        'source_types':['constructed_counterfactuals','retained_hash_verified_Moodle_evidence'],
        'fitted_or_calibrated':False,'new_target_traffic':False})
    outputs={name:evaluate(**s) for name,s in ss.items()}
    baseline=outputs['normal_complete'];rows=[]
    expected_pairs={'verified_remediation':('confirmed_critical','NONDECREASE'),
        'independent_additional_weakness':('confirmed_critical','NONINCREASE'),
        'duplicate_native_zap':('confirmed_critical','EQUAL'),
        'duplicate_episode':('known_incident','EQUAL'),
        'verified_incident_closure':('known_incident','NONDECREASE'),
        'temporal_activity_recovery':('old_incident_no_recent_telemetry','NONDECREASE')}
    for name,result in outputs.items():
        base_name,direction=expected_pairs.get(name,('normal_complete','NONINCREASE'))
        if name in ('normal_complete','generic_moodle_inapplicable'):direction='EQUAL'
        before=outputs[base_name];delta=result['overall']-before['overall'] if result['overall'] is not None and before['overall'] is not None else None
        holds=(delta is None or delta>=-1e-10 if direction=='NONDECREASE' else
               delta is None or delta<=1e-10 if direction=='NONINCREASE' else delta is not None and abs(delta)<1e-10)
        assert holds,(name,delta,direction)
        rows.append({'scenario':name,'source_type':'CONSTRUCTED_COUNTERFACTUAL; NOT a new live scan',
            'comparison_scenario':base_name,'input_delta':name,'old_policy_cqi':old_fixture(ss[name]),
            'new_cqi':result['overall'],'conditional_cqi':result['conditional_overall'],
            'coverage':result['coverage']['observability'],'effective_coverage':result['coverage']['effective_reliability_coverage'],
            'delta':delta,'expected_direction':direction,'actual_direction':'EQUAL' if delta==0 else 'DECREASE' if delta is not None and delta<0 else 'INCREASE' if delta is not None else 'UNAVAILABLE',
            'direction_pass':holds,'status':result['overall_status'],'aggregation_alternatives':result['aggregation_alternatives']})
    write(out,'counterfactual_results.json',{'scenarios':rows,'details':outputs})
    with (out/'counterfactual_results.csv').open('x',newline='') as f:
        fields=[k for k in rows[0] if k!='aggregation_alternatives'];w=csv.DictWriter(f,fieldnames=fields);w.writeheader();w.writerows({k:r[k] for k in fields} for r in rows)
    variation={};inversions=[]
    def sign(x):return 1 if x>1e-9 else -1 if x< -1e-9 else 0
    for name,p in policies.items():
        values={k:evaluate(**s,policy=p)['overall'] for k,s in ss.items()};variation[name]=values
        for a in ss:
            for b in ss:
                if a>=b:continue
                x,y=outputs[a]['overall'],outputs[b]['overall'];u,v=values[a],values[b]
                if None in (x,y,u,v):continue
                if sign(x-y)*sign(u-v)==-1:inversions.append({'variant':name,'first':a,'second':b,'baseline_difference':x-y,'variant_difference':u-v})
        assert values['verified_remediation']>=values['confirmed_critical']>=values['independent_additional_weakness']
        assert values['normal_complete']>values['known_incident']>=values['two_independent_incidents']
        assert values['confirmed_critical']==values['duplicate_native_zap']
    write(out,'sensitivity.json',{'variant_count':len(policies),'scenario_count':len(ss),'scores':variation,'strict_pairwise_rank_inversions':inversions,
        'important_monotonic_and_duplicate_orderings_robust':True,'rank_inversion_count':len(inversions),
        'assumptions_not_statistically_calibrated':True})
    # Retained observations/explanations/CQI baseline are verified before scoring.
    service=Application(Config());observed=[];old_refs=json.loads((ROOT/a.baseline).read_text())
    for source in ('BENIGN_TEST','ATTACK_HOLDOUT'):
        snap=service.snapshot(mode='ACCEPTED_REPLAY',replay=source)
        obs_hash=hashlib.sha256(json.dumps([o.model_dump(mode='json',by_alias=True) for o in snap['observations']],sort_keys=True).encode()).hexdigest()
        inc_hash=hashlib.sha256(json.dumps([e.model_dump(mode='json',by_alias=True) for e in snap['incidents']],sort_keys=True).encode()).hexdigest()
        assert obs_hash==old_refs[source]['observation_hash'] and inc_hash==old_refs[source]['incident_hash']
        assert snap['cqi'].model_dump(mode='json')==old_refs[source]['cqi']
        new=service.scientific_quality('ACCEPTED_REPLAY',source)
        observed.append({'source':source,'kind':'RETAINED_OBSERVED_EVIDENCE_REANALYSIS; no new experiment',
            'old_cqi':snap['cqi'].overall,'new':new,'observations_unchanged':True,'incidents_unchanged':True})
    current=service.posture_service.current()
    if current:
        path=service.posture_service.location(current['assessment_id'])/'snapshot.json'
        assert hashlib.sha256(path.read_bytes()).hexdigest()==old_refs['CURRENT_POSTURE']['snapshot_sha256']
        old=service.current_posture_quality(current);assert old.model_dump(mode='json')==old_refs['CURRENT_POSTURE']['old_cqi']
        observed.append({'source':current['assessment_id'],'kind':'RETAINED_POSTURE_AT_ORIGINAL_COMPLETION; no current live-security claim',
            'snapshot_sha256':hashlib.sha256(path.read_bytes()).hexdigest(),'old_cqi':old.overall,
            'new':evaluate(current['findings'],as_of=current['completed_at'],posture_time=current['completed_at'])})
    write(out,'retained_evidence_comparison.json',observed)
    write(out,'baseline_legacy_outputs.json',old_refs)
    write(out,'control_registry_reference.json',registry())
    write(out,'accepted_integrity.json',{'root':verify(ROOT/'outputs/branch2/accepted_behavioral_v2')['root_sha256'],
        'models_loaded_or_fit_by_validation':False,'legacy_policy_changed':False,'observations_explanations_incidents_unchanged':True})
    report=['# CQI v2 scientific validation','',
        'Constructed scenarios below are counterfactual policy tests, not new attacks or scans. Policy coefficients are not empirically calibrated. Historical source findings and old scores remain unchanged.','',
        '| Scenario | Old v1 | New conservative | Conditional | Coverage | Delta | Direction |',
        '|---|---:|---:|---:|---:|---:|---|']
    fmt=lambda v:'—' if v is None else f'{v:.4f}'
    for r in rows:report.append('| '+' | '.join([r['scenario'],fmt(r['old_policy_cqi']),fmt(r['new_cqi']),fmt(r['conditional_cqi']),fmt(r['coverage']),fmt(r['delta']),r['actual_direction']])+' |')
    report+=['','## Retained evidence','', '| Source | Old CQI | New conservative CQI | Conditional | Coverage |','|---|---:|---:|---:|---:|']
    for r in observed:report.append('| '+' | '.join([r['source'],fmt(r['old_cqi']),fmt(r['new']['overall']),fmt(r['new']['conditional_overall']),fmt(r['new']['coverage']['observability'])])+' |')
    report+=['',f"Sensitivity: {len(policies)} parameter variants × {len(ss)} fixed scenarios. Strict pairwise rank reversals: {len(inversions)}. Important monotonic/duplicate/incident orderings remained valid in all variants.",
        'Full reversals, including trade-offs between evidence confidence and severity, are retained in sensitivity.json. These do not establish empirical calibration.',
        '', 'A weak-dimension guard creates plateaus: an additional weakness can lower another dimension without moving an already-binding overall cap. This satisfies weak monotonicity, not strict sensitivity of every overall change.',
        'Missing D6 produces an overall lower bound of zero when some posture is observed; this deliberately communicates profound current-state uncertainty rather than a measured complete failure. Conditional estimates and the interval must be read alongside it.',
        '', 'New API: /api/cqi/v2; legacy /api/cqi remains v1 for existing clients and history. No active monitor was restarted. No frontend redesign or automatic policy switch in existing screens was performed.',
        '', 'See docs/research/CQI_MATHEMATICAL_MODEL.md for exact formulas, assumptions, proofs, rationale and reproduction.']
    with (out/'report.md').open('x') as f:f.write('\n'.join(report)+'\n')
    print(json.dumps({'result':'PASS','scenarios':len(ss),'variants':len(policies),'rank_reversals':len(inversions),'retained_comparisons':len(observed),'output':str(out)}))

if __name__=='__main__':main()
