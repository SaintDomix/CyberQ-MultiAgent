"""Thin orchestration: call Fusion directly, present and verify its immutable results."""
from pathlib import Path
from collections import Counter
import hashlib
from src.fusion.pipeline import evaluate
from src.fusion.schema import dumps
from .acceptance import check_acceptance

VERSION = 'end-to-end-assessment-1.0'
ROOT = Path(__file__).resolve().parents[2]


def inventory(roots):
    return {str(p.resolve()): {'sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'bytes':p.stat().st_size}
            for root in roots if Path(root).exists() for p in sorted(Path(root).rglob('*')) if p.is_file()}


def verify_inventory(before):
    changed = []
    for name, expected in sorted(before.items()):
        p = Path(name)
        if not p.is_file() or {'sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'bytes':p.stat().st_size} != expected:
            changed.append(name)
    return {'unchanged':not changed, 'pre_existing_file_count':len(before), 'changed_or_missing':changed,
            'inventory_sha256':hashlib.sha256(dumps(before).encode()).hexdigest()}


def write_json(path, value):
    with path.open('x',encoding='utf-8') as handle:handle.write(dumps(value)+'\n')


def compare(baseline, sqli, expected_members=5):
    ds=[]
    for before, after in zip(baseline['dimensions'],sqli['dimensions']):
        if before['dimension'] != after['dimension']:raise ValueError('Incompatible dimension ordering')
        a,z=before['quality'],after['quality']
        ds.append({'dimension':before['dimension'],'baseline_quality':a,'sqli_quality':z,'delta':z-a if a is not None and z is not None else None})
    a,z=baseline['cqi']['cqi'],sqli['cqi']['cqi']
    def episodes(data):return [x for x in data['fusion_clusters'] if x['rule_id']=='TEMPORALLY_CORRELATED_BEHAVIOR_EPISODE']
    sql=[x for x in episodes(sqli) if x['behavior_class']=='SQLI_ATTEMPT']
    bpost=[x for x in baseline['canonical_evidence'] if x['source_branch']=='BRANCH1_POSTURE']
    spost=[x for x in sqli['canonical_evidence'] if x['source_branch']=='BRANCH1_POSTURE']
    correlations=[c for c in sqli['correlations'] if c['rule_id']=='CONTEXT_SQLI_ATTEMPT']
    return {'status':'COMPARED', 'baseline_name':'PRE-SQLI BASELINE (may include unknown anomalies)',
        'baseline_as_of':baseline['summary']['behavior_horizon']['as_of'], 'sqli_as_of':sqli['summary']['behavior_horizon']['as_of'],
        'lookback_seconds':baseline['summary']['behavior_horizon']['behavior_lookback_seconds'],
        'baseline_cqi':a, 'sqli_cqi':z, 'delta':z-a if a is not None and z is not None else None,
        'dimensions':ds, 'changed_dimensions':[d['dimension'] for d in ds if d['baseline_quality'] != d['sqli_quality']],
        'posture_identical':bpost==spost, 'behavior_episode_counts':{'baseline':len(episodes(baseline)),'sqli':len(episodes(sqli))},
        'known_attempt_counts':{'baseline':baseline['coverage']['branch2']['known_attack_attempts'],'sqli':sqli['coverage']['branch2']['known_attack_attempts']},
        'correlation_counts':{'baseline':len(baseline['correlations']),'sqli':len(sqli['correlations'])},
        'baseline_behavior_counts':baseline['coverage']['branch2'],'sqli_behavior_counts':sqli['coverage']['branch2'],
        'sqli_episode_count':len(sql),'sqli_episode_member_counts':[x['member_count'] for x in sql],
        'expected_sqli_members':expected_members,'sqli_episodes':sql,'sqli_correlations':sqli['correlations'],'baseline_correlations':baseline['correlations'],
        'sqli_contextual_correlations':correlations,
        'interpretation':'The CQI decrease reflects a change in recent behavioral evidence while the frozen posture snapshot remains unchanged.'
            if bpost==spost and a is not None and z is not None and z<a else
            'Compare observed dimension and coverage changes; the acceptance scenario decrease was not established.',
        'cqi_is_probability':False,'successful_exploitation_confirmed':False}


def build_assessment(fusion, model_acceptance):
    evidence=fusion['canonical_evidence']
    posture=[x for x in evidence if x['source_branch']=='BRANCH1_POSTURE']
    behavioral=[x for x in evidence if x['source_branch']=='BRANCH2_BEHAVIOR']
    drivers=[]
    by_id={x['evidence_id']:x for x in evidence}
    for c in sorted(fusion['fusion_clusters'],key=lambda c: (-(c['contribution'] or 0),c['cluster_id'])):
        if c['contribution'] is None or c['contribution']<=0:continue
        drivers.append({k:c[k] for k in ('cluster_id','dimension','contribution','member_count','rationale','recommendations')})
        drivers[-1]['representative_evidence']=by_id[c['representative_evidence_id']]
    episodes=[]
    for c in fusion['fusion_clusters']:
        if c['rule_id']!='TEMPORALLY_CORRELATED_BEHAVIOR_EPISODE':continue
        episodes.append({**c,'semantic_scope':'ATTEMPT_PATTERN' if c['behavior_class'] not in ('UNKNOWN_ANOMALY','UNCERTAIN') else 'ANOMALY_OR_UNCERTAINTY',
                         'successful_exploitation_confirmed':False})
    actions={}
    for rec in fusion['recommendations']:
        for action in rec['actions']:
            targets=actions.setdefault(action,set())
            targets.update(rec.get('evidence_ids',[]))
            if 'evidence_id' in rec:targets.add(rec['evidence_id'])
    summary={field:dict(sorted(Counter(str(x[field]) for x in posture).items()))
             for field in ('severity','check_result','evidence_strength','category')}
    shap=Counter((x['source_details'].get('shap_explanation') or {}).get('status','NOT_SUPPLIED') for x in behavioral)
    return {'schema_version':VERSION,'fusion_policy_version':fusion['cqi']['formula_version'],
        'platform_metadata':{'observed_posture_assets':sorted(set(str(x['affected_asset']) for x in posture if x['affected_asset'] is not None)),
                             'platform_name':None,'note':'Only source-supported metadata; platform name not inferred.'},
        'assessment_scope':'Offline latest accepted posture snapshot plus recent saved-model behavioral evidence',
        'behavior_horizon':fusion['summary']['behavior_horizon'],'cqi':fusion['cqi'],
        'cqi_is_probability':False,'weights_are_empirically_calibrated':False,'successful_exploitation_confirmed':False,
        'training_performed':fusion['provenance']['training_performed'],'dimensions':fusion['dimensions'],
        'top_risk_drivers':drivers,'behavioral_episodes':episodes,'correlations':fusion['correlations'],
        'coverage':fusion['coverage'],'recommendations':[{'action':k,'evidence_ids':sorted(v)} for k,v in sorted(actions.items())],
        'posture_summary':summary,'sensitivity':fusion['sensitivity'],'limitations':fusion['summary']['limitations'],
        'upstream_explainability':{'source':'Frozen M2D predictions; no SHAP execution in M3C', 'selected_window_shap_status_counts':dict(sorted(shap.items())), 'causal':False},
        'provenance':fusion['provenance'],'provenance_references':['provenance.json','fusion/provenance.json'],
        'model_package_identity':{'model_id':fusion['provenance']['inputs']['model_manifest']['sha256'],
            'feature_schema_sha256':model_acceptance['schema_sha256'],
            'accepted_model_id':model_acceptance['model_id'],
            'prediction_model_ids':sorted(set(x['provenance']['model_id'] for x in behavioral)),
            'prediction_schema_ids':sorted(set(x['provenance']['schema_sha256'] for x in behavioral)),
            'validated':True,'schema_validated':True}}


def assess(branch1,branch2,model_manifest,live_acceptance,out,as_of=None,lookback=300,
           baseline_as_of=None,sqli_as_of=None,expected_sqli_members=5,protected_roots=None):
    from src.fusion.schema import utc
    from src.fusion.pipeline import read_json
    from .render_markdown import render_markdown
    from .render_html import render_html
    target=Path(out).resolve()
    if target.exists():raise FileExistsError('Refusing existing output directory')
    if bool(baseline_as_of) != bool(sqli_as_of):raise ValueError('Both comparison timestamps are required')
    if type(lookback) is not int or lookback<=0:raise ValueError('Positive lookback required')
    if type(expected_sqli_members) is not int or expected_sqli_members<1:raise ValueError('Positive expected SQLI membership required')
    for stamp in (as_of,baseline_as_of,sqli_as_of):
        if stamp is not None:utc(stamp)
    if baseline_as_of and utc(baseline_as_of)>=utc(sqli_as_of):raise ValueError('Baseline must precede SQLI state')
    # Validate JSON artifact paths before any reads, including inventory protection.
    inputs=[Path(x).resolve() for x in (branch1,branch2,model_manifest,live_acceptance)]
    for path,suffix in zip(inputs,('.json','.jsonl','.json','.json')):
        if path.suffix!=suffix or '/var/log/' in str(path):raise ValueError('Only frozen JSON artifacts; host logs forbidden')
        if target==path or target in path.parents:raise ValueError('Output contains input artifact')
    roots=list(protected_roots) if protected_roots is not None else [ROOT/name for name in ('data','evidence','outputs')]
    before=inventory(roots)
    # Fusion is the sole implementation of adaptation, horizon, dedup, scoring and correlation.
    fusion=evaluate(*inputs,target/'fusion',as_of=as_of,lookback=lookback)
    comparison={'status':'NOT_REQUESTED','explanation':'Supply both comparison timestamps to assess the M3C scenario profile.'}
    if baseline_as_of:
        baseline=evaluate(*inputs,target/'comparison_states'/'baseline',as_of=baseline_as_of,lookback=lookback)
        sqli=evaluate(*inputs,target/'comparison_states'/'sqli',as_of=sqli_as_of,lookback=lookback)
        if any(data['provenance']['inputs']!=fusion['provenance']['inputs'] for data in (baseline,sqli)):
            raise ValueError('Input identities changed between assessment states')
        comparison=compare(baseline,sqli,expected_sqli_members)
    assessment=build_assessment(fusion,read_json(inputs[3]))
    for name in ('cqi','dimensions','fusion_clusters','correlations','coverage','sensitivity','provenance'):
        write_json(target/(name+'.json'),fusion[name])
    write_json(target/'recommendations.json',assessment['recommendations'])
    write_json(target/'assessment.json',assessment);write_json(target/'comparison.json',comparison)
    for name, content in [('report.md',render_markdown(assessment,comparison)),('report.html',render_html(assessment,comparison))]:
        with (target/name).open('x',encoding='utf-8') as handle:handle.write(content)
    integrity=verify_inventory(before)
    write_json(target/'integrity_verification.json',integrity)
    acceptance=check_acceptance(assessment,comparison,integrity,
                               all((target/name).stat().st_size>0 for name in ('report.md','report.html')))
    write_json(target/'acceptance.json',acceptance)
    write_json(target/'summary.json',{'version':VERSION,'acceptance':acceptance['overall'],'acceptance_profile':acceptance['profile'],
        'cqi':fusion['cqi']['cqi'],'comparison_status':comparison['status'],'reports':['report.md','report.html'],
        'cqi_is_probability':False,'training_performed':False})
    files=[]
    for path in sorted(target.rglob('*')):
        if path.is_file():files.append({'filename':str(path.relative_to(target)),'sha256':hashlib.sha256(path.read_bytes()).hexdigest(),
            'bytes':path.stat().st_size,'role':('runtime_inventory_audit' if path.name=='integrity_verification.json' else 'human_report' if path.suffix in ('.md','.html') else 'machine_evidence')})
    write_json(target/'artifact_manifest.json',{'version':'m3c-artifact-manifest-1.0', 'files':files,
        'self_hash_convention':'Manifest excludes itself to avoid recursion; all other output files, including nested Fusion states, are hashed.'})
    return {'assessment':assessment,'comparison':comparison,'acceptance':acceptance}
