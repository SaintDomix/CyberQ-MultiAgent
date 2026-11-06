"""Registered specialist tools. Only server-selected, authentic copied evidence.

File artifacts and immutable SQLite are independent external data integrations;
frozen ML inference is a code-execution integration, not an external API call.
"""
from collections import Counter, defaultdict
from datetime import datetime, timezone
from functools import lru_cache
import hashlib
import json
import math
from pathlib import Path

from coursework.isolation import ROOT, require_live_owner
from demo.backend.config import Config, confined, SOURCE_HASHES
from .models import EvidenceRef, ToolResult, VerificationOutcome, TaskError
from .store import digest


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


@lru_cache(maxsize=1)
def anchors():
    return json.loads((ROOT/'coursework/initial_inventory.json').read_text())['preserved_artifacts']


def reference(path, *, ids=(), observed_at=None, kind='FILE'):
    path=confined(ROOT,path)
    relative=str(path.relative_to(ROOT))
    expected=anchors().get(relative)
    if expected is None:
        raise TaskError('UNANCHORED_SOURCE','Evidence is not in the preserved artifact inventory')
    return EvidenceRef(ref_id='ref-'+digest([relative,expected])[:24],path=relative,
        expected_sha256=expected,read_sha256=sha(path),source_record_ids=[str(v) for v in ids if v is not None],
        observed_at=observed_at,kind=kind)


def read(path):
    p=confined(ROOT,path)
    if p.stat().st_size > 64*1024*1024:
        raise TaskError('ARTIFACT_SIZE_LIMIT','Artifact exceeds the bounded read limit')
    return json.loads(p.read_bytes())


def outcome(subject,status,*reasons,refs=()):
    return VerificationOutcome(subject=subject,status=status,reasons=list(reasons),related_refs=list(refs))


def native_read(ctx):
    if ctx.state.request.mode=='LIVE_LAB':
        from .live import live_tool
        return live_tool(ctx,'native.read_baseline')
    path=Config().posture
    ref=reference(path)
    if ref.read_sha256!=SOURCE_HASHES['posture']:
        raise TaskError('NATIVE_SOURCE_INTEGRITY','Frozen Native source hash mismatch')
    rows=read(path)
    ref=reference(path,ids=[r['evidence_id'] for r in rows])
    return ToolResult(summary={'findings':len(rows),'scope':'FROZEN_RESEARCH_BASELINE','live_collection':False},
                      data={'rows':rows},evidence=[ref])


def native_map(ctx):
    from fusion.adapters import posture
    original=ctx.output('native.read_baseline')
    records=[r.export() for r in posture(original.data['rows'],original.evidence[0].path)]
    return ToolResult(summary={'mapped_records':len(records),
        'confirmation_status_counts':dict(Counter(r['confirmation_status'] for r in original.data['rows'])),
        'finding_semantics':'VERSION_BASED remains distinct from CONFIRMED'},
        data={'canonical_records':records},evidence=original.evidence)


@lru_cache(maxsize=1)
def saved_zap_id():
    # Selection is server-controlled, not a path supplied by the browser.
    for p in sorted((ROOT/'runtime/posture').glob('posture-*/snapshot.json'),reverse=True):
        value=read(p)
        if value.get('provider_statuses',{}).get('zap')=='COMPLETE': return p.parent.name
    raise TaskError('ZAP_EVIDENCE_MISSING','No completed saved ZAP assessment is available')


def zap_read(ctx):
    if ctx.state.request.mode=='LIVE_LAB':
        from .live import live_tool
        return live_tool(ctx,'zap.read_assessment')
    from posture.orchestration import PostureAssessmentOrchestrator
    archive=PostureAssessmentOrchestrator(ROOT,[])
    aid=saved_zap_id()
    job=archive.get(aid)  # Existing file-membership, hash and identity checks.
    directory=archive.location(aid)
    payload=read(directory/'zap.json')
    refs=[reference(directory/name,observed_at=payload.get('completed_at'),
                    ids=[aid],kind='FILE') for name in ('artifact_manifest.json','snapshot.json','request.json','zap.json')]
    return ToolResult(summary={'assessment_id':aid,'recorded_profile':job['mode'],
        'saved_findings':len(payload['findings']),'source_status':payload['status'],
        'new_scan_executed':False,'scope':'IMPORTED_HISTORICAL_ONLY'},
        data={'assessment':{k:job.get(k) for k in ('assessment_id','target','mode','started_at','completed_at','status')},
              'findings':payload['findings'],'session_lifecycle':payload.get('session_lifecycle'),
              'context_id':payload.get('context_id'),'context_name':payload.get('context_name'),
              'stages':{k:v.get('status') for k,v in payload.get('stages',{}).items() if isinstance(v,dict)}},evidence=refs)


def zap_profile(ctx):
    if ctx.state.request.mode=='LIVE_LAB':
        from .live import live_tool
        return live_tool(ctx,'zap.check_profile')
    original=ctx.output('zap.read_assessment')
    try:require_live_owner()
    except ValueError:locked=True
    else:locked=False
    if not locked: raise TaskError('LAB_GATE_CHANGED','Expected coursework laboratory lock is unavailable',status='BLOCKED')
    rows=original.data['findings'];aid=original.data['assessment']['assessment_id']
    from demo.backend.adapters import finding
    mapped=[finding(r).model_dump(mode='json') for r in rows]
    return ToolResult(summary={**original.summary,'requested_profile':ctx.state.request.zap_profile,
        'live_gate':'LOCKED','saved_profile_is_not_requested_profile_execution':True,
        'supported_preserved_profiles':['PASSIVE_BASELINE','STANDARD','FULL_AUTHORIZED'],
        'scoring_scope':'SUPPLEMENTARY_ONLY; existing accepted-replay CQI uses the frozen Native source; no new direct ZAP weight'},
        data={'assessment_id':aid,'mapped_findings':mapped,'target':original.data['assessment']['target']},evidence=original.evidence)


def behavior_extract(ctx):
    if ctx.state.request.mode=='LIVE_LAB':
        from .live import live_tool
        return live_tool(ctx,'behavior.extract_features')
    from demo.backend.services import Application
    from demo.backend.explanation_sources import replay_features, key
    app=Application(Config())
    model=app.model()
    if model['integrity']!='VERIFIED':raise TaskError('MODEL_INTEGRITY','Accepted model verification failed')
    scenario=ctx.state.request.scenario
    replay='BENIGN_TEST' if scenario in ('benign_replay','unknown_run') else 'ATTACK_HOLDOUT'
    predictions,_,_=app.replay(replay,None,model)
    labels={'sqli_run':'SQLI_ATTEMPT','xss_run':'XSS_ATTEMPT','traversal_run':'PATH_TRAVERSAL_ATTEMPT',
            'bruteforce_run':'BRUTE_FORCE','unknown_run':'UNKNOWN_ANOMALY'}
    run_id=None
    if scenario in labels:
        candidates=sorted({p['run_id'] for p in predictions if p['reconciliation']['decision']==labels[scenario]})
        if not candidates:raise TaskError('SCENARIO_EVIDENCE_MISSING','Requested class has no authentic saved run')
        run_id=candidates[0]
        predictions=[p for p in predictions if p['run_id']==run_id]
    if not predictions:raise TaskError('BEHAVIOR_EVIDENCE_MISSING','No saved predictions available')
    ctx.check()
    values=replay_features(ROOT,predictions,replay,model['schema_sha256'])
    if len(values)!=len(predictions):raise TaskError('FEATURE_EVIDENCE_MISSING','Some 83-feature windows cannot be resolved to authentic sources')
    rows=[];paths=set()
    for p in predictions:
        ctx.check()
        vector=values[key(p)]
        if len(vector)!=83:raise TaskError('FEATURE_SCHEMA','Resolved feature count differs from the frozen 83-column contract')
        source=(f'outputs/branch2/m5_final_day/browser_sessions/{p["run_id"]}/features.json' if replay=='BENIGN_TEST' else
                f'evidence/branch2_captures/m5_fresh_attack_holdout_01/{p["run_id"]}/access.log')
        paths.add(source)
        rows.append({**p,'source_file':source,'features':vector})
    base=Config().benign if replay=='BENIGN_TEST' else Config().attack
    prediction_file=base+('/candidate_predictions.json' if replay=='BENIGN_TEST' else '/predictions.json')
    manifest_file=base+('/artifact_manifest.json' if replay=='BENIGN_TEST' else '/artifact_hashes.json')
    paths.update((prediction_file,manifest_file,Config().accepted+'/accepted_manifest.json'))
    refs=[reference(path,observed_at=max(p['window_end'] for p in predictions),
                    ids=sorted({p['run_id'] for p in predictions})) for path in sorted(paths)]
    return ToolResult(summary={'feature_count':83,'windows':len(rows),'complete_runs':len({p['run_id'] for p in predictions}),
        'replay':replay,'selected_run':run_id,'schema_sha256':model['schema_sha256'],'package_id':model['package_id']},
        data={'rows':rows,'saved_predictions':predictions,'replay':replay,'run_id':run_id,'model':model},evidence=refs)


def behavior_infer(ctx):
    if ctx.state.request.mode=='LIVE_LAB':
        from .live import live_tool
        return live_tool(ctx,'behavior.infer')
    from behavioral_runtime.package import load
    source=ctx.output('behavior.extract_features')
    package=load(ROOT/Config().accepted)
    ctx.check()
    inferred=package.predict(source.data['rows'],explain=True)
    ctx.check()
    if len(inferred)!=len(source.data['rows']):raise TaskError('INFERENCE_LENGTH','Saved inference returned an unexpected row count')
    values=[]
    for saved,p in zip(source.data['saved_predictions'],inferred):
        p.update({k:saved[k] for k in ('record_id','sequence','session_id','model_id','schema_sha256',
            'feature_schema_version','emitted_at_utc','time_semantics')})
        values.append(p)
    return ToolResult(summary={'windows_inferred':len(values),'models':['OCSVM','XGBoost'],
        'training_performed':False,'llm_calls':0,'shap_available':sum(p['shap_explanation']['status']=='AVAILABLE' for p in values)},
        data={'predictions':values},evidence=source.evidence)


def behavior_incidents(ctx):
    if ctx.state.request.mode=='LIVE_LAB':
        from .live import live_tool
        return live_tool(ctx,'behavior.explain_incidents')
    from behavioral_v2.episodes import episodes
    from demo.backend.adapters import episode
    from demo.backend.explainability import explain
    source=ctx.output('behavior.extract_features');inference=ctx.output('behavior.infer')
    predictions=inference.data['predictions'];package_id=source.data['model']['package_id']
    incidents=[episode(e,package_id,True).model_dump(mode='json') for e in episodes(predictions,2) if e['alert']]
    explanation=explain(predictions[0],features=source.data['rows'][0]['features'],package_id=package_id)
    return ToolResult(summary={**inference.summary,'incidents':len(incidents),
        'decision_counts':dict(Counter(p['reconciliation']['decision'] for p in predictions)),
        'successful_exploitation_confirmed':False},
        data={'incidents':incidents,'example_explanation':explanation},evidence=source.evidence)


def verify_artifacts(ctx):
    from behavioral_runtime.package import verify
    refs={r.ref_id:r for a in ('native','zap','behavioral') for r in ctx.state.outputs[a].evidence}
    outcomes=[]
    for ref in refs.values():
        ctx.check()
        try:
            path=confined(ROOT,ref.path)
            if not path.is_file():
                outcomes.append(outcome(ref.ref_id,'MISSING','Referenced artifact is unavailable',refs=[ref.ref_id]));continue
            if ref.anchor=='COURSEWORK_TASK_SNAPSHOT':
                if ctx.state.request.mode!='LIVE_LAB':
                    outcomes.append(outcome(ref.ref_id,'INVALID','Live snapshots cannot substitute for preserved offline evidence',refs=[ref.ref_id]))
                    continue
                ctx.engine.live_adapter.check_reference(ctx,ref)
                outcomes.append(outcome(ref.ref_id,'VERIFIED','Immutable task snapshot hash and task/session provenance checked',refs=[ref.ref_id]))
                continue
            actual=sha(path);anchor=anchors().get(ref.path)
            status='VERIFIED' if actual==ref.read_sha256==ref.expected_sha256==anchor else 'INVALID'
            outcomes.append(outcome(ref.ref_id,status,'Independent byte hash compared with preserved inventory and producer read hash',refs=[ref.ref_id]))
        except (OSError,ValueError):outcomes.append(outcome(ref.ref_id,'INVALID','Artifact reference is unreadable or outside confinement',refs=[ref.ref_id]))
    m=verify(ROOT/Config().accepted)
    outcomes.append(outcome('model-package','VERIFIED','Frozen package, source-code hashes, schema and accepted origin verified'))
    ctx.state.verification.extend(outcomes)
    return ToolResult(summary={'artifact_checks':len(outcomes),'invalid_or_missing':sum(o.status in ('INVALID','MISSING') for o in outcomes)},
        data={'model_id':m['package_id'],'schema_sha256':m['schema_sha256']},evidence=list(refs.values()))


def verify_consistency(ctx):
    if ctx.state.request.mode=='LIVE_LAB':
        from .live import live_tool
        return live_tool(ctx,'verify.consistency')
    """Check producer claims against source bytes and cross-record semantics."""
    from branch2.events import utc
    from behavioral_v2.features31 import matrix
    outcomes=[]
    native=ctx.output('native.read_baseline')
    if native.data['rows']!=read(native.evidence[0].path):
        outcomes.append(outcome('native-content','CONFLICTED','Delivered Native records differ from the hash-bound source'))
    else:outcomes.append(outcome('native-content','VERIFIED','Delivered records match immutable source bytes'))
    allowed={'CONFIRMED','VERSION_BASED','LIKELY','CONTEXTUAL','NOT_CONFIRMED','NOT_APPLICABLE','NOT_TESTED','FALSE_POSITIVE'}
    for name,records in [('native',native.data['rows']),('zap',ctx.output('zap.read_assessment').data['findings'])]:
        seen={};duplicates=[];conflicts=[]
        for row in records:
            rid=row.get('evidence_id')
            if not rid or row.get('confirmation_status') not in allowed:
                outcomes.append(outcome(name+'-record','INVALID','Evidence identity or confirmation status is invalid'));continue
            signature=digest(row)
            if rid in seen:
                (duplicates if seen[rid]==signature else conflicts).append(rid)
            seen[rid]=signature
            start,end=row.get('start_utc'),row.get('end_utc')
            if start and end and utc(start)>utc(end):
                outcomes.append(outcome(rid,'INVALID','Evidence timestamp interval is reversed'))
        outcomes.append(outcome(name+'-identities','CONFLICTED' if conflicts else 'PARTIAL' if duplicates else 'VERIFIED',
            f'Unique evidence identities: {len(seen)}; exact duplicates: {len(duplicates)}; contradictory identities: {len(conflicts)}'))
    zap=ctx.output('zap.read_assessment');aid=zap.data['assessment']['assessment_id']
    zap_path=next(r.path for r in zap.evidence if r.path.endswith('/zap.json'))
    if zap.data['findings']!=read(zap_path)['findings'] or any(r.get('assessment_id')!=aid for r in zap.data['findings']):
        outcomes.append(outcome('zap-content','CONFLICTED','ZAP source content or assessment identifiers do not match'))
    else:outcomes.append(outcome('zap-content','VERIFIED','ZAP findings match verified assessment and source'))
    targets={r['affected_asset'] for r in native.data['rows']}
    if zap.data['assessment']['target'] not in targets:
        outcomes.append(outcome('target-identity','CONFLICTED','Native and ZAP target identities differ'))
    extraction=ctx.output('behavior.extract_features');inference=ctx.output('behavior.infer')
    schema=read(Config().accepted+'/model/feature_schema.json')
    try:matrix(extraction.data['rows'],schema)
    except ValueError:outcomes.append(outcome('feature-vector-contract','INVALID','Feature schema, order or finite-value contract failed'))
    if len(extraction.data['saved_predictions'])!=len(inference.data['predictions']) or len(extraction.data['rows'])!=len(inference.data['predictions']):
        outcomes.append(outcome('behavior-row-counts','INVALID','Saved, extracted and newly inferred row counts differ'))
    identity=set();different=[]
    for saved,p in zip(extraction.data['saved_predictions'],inference.data['predictions']):
        ctx.check()
        rid=p['record_id']
        if rid in identity:outcomes.append(outcome(rid,'CONFLICTED','Duplicate behavioral observation identity'))
        identity.add(rid)
        if any(saved.get(k)!=p.get(k) for k in ('record_id','run_id','window_start','window_end','client_id','user_agent_id')):
            outcomes.append(outcome(rid,'CONFLICTED','Inference record identity differs from its source window'))
        if (utc(p['window_start'])>=utc(p['window_end']) or p['schema_sha256']!=schema['sha256']
                or p['model_id']!=extraction.data['model']['package_id'] or p.get('training_performed') is not False):
            outcomes.append(outcome(rid,'INVALID','Behavioral time, schema, model or training contract is invalid'))
        if (saved['xgb_label']!=p['xgb_label'] or saved['reconciliation']!=p['reconciliation']
                or not math.isclose(saved['novelty_score'],p['novelty_score'],rel_tol=1e-6,abs_tol=1e-7)
                or not math.isclose(saved['xgb_confidence'],p['xgb_confidence'],rel_tol=1e-6,abs_tol=1e-7)):
            different.append(rid)
    outcomes.append(outcome('saved-vs-new-inference','CONFLICTED' if different else 'VERIFIED',
        f'Compared actual saved-model inference with preserved predictions; differences: {len(different)}'))
    incidents=ctx.output('behavior.explain_incidents').data['incidents']
    if any(not set(i['observation_ids']).issubset(identity) for i in incidents):
        outcomes.append(outcome('incident-membership','INVALID','An incident references an unavailable observation'))
    else:outcomes.append(outcome('incident-membership','VERIFIED','Incident members belong to the delivered inference records'))
    # Same named controls with different evidence times are contextual differences,
    # not proof of contradiction or remediation. No invented timestamp fills a gap.
    named={r['finding_id']:r for r in native.data['rows']}
    differences=[r['finding_id'] for r in zap.data['findings'] if r['finding_id'] in named
                 and r['check_result']!=named[r['finding_id']]['check_result']]
    outcomes.append(outcome('cross-source-temporal-scope','PARTIAL',
        'Native baseline has no asserted collection timestamp; saved ZAP and behavioral runs are not a paired live observation',
        f'Controls with differing cross-source verdicts: {len(differences)}; treated as contextual, not simultaneous contradictions',
        'Different branch times are normal. Replay CQI retains its existing frozen Native inputs, not a new ZAP scoring weight; no time or freshness is invented'))
    latest=max(utc(p['window_end']) for p in inference.data['predictions'])
    age=(datetime.now(timezone.utc)-latest).total_seconds()
    outcomes.append(outcome('freshness','PARTIAL',f'Historical behavioral evidence age at verification: {int(age)} seconds',
        'Allowed for declared historical replay only; not suitable as current live evidence'))
    ctx.state.verification.extend(outcomes)
    return ToolResult(summary={'consistency_checks':len(outcomes),'temporal_scope':'HISTORICAL_REANALYSIS_PARTIAL',
        'cross_source_verdict_differences':len(differences)},data={'outcomes':[o.model_dump() for o in outcomes]})


def verify_journal(ctx):
    if ctx.state.request.mode=='LIVE_LAB':
        from .live import live_tool
        return live_tool(ctx,'verify.journal')
    from demo.backend.runtime import read_journal
    extraction=ctx.output('behavior.extract_features')
    paths=sorted((ROOT/'runtime/behavioral_v2').glob('*/session_manifest.json'),reverse=True)
    if not paths:
        o=outcome('retained-journal','MISSING','No corroborating immutable journal is available')
        ctx.state.verification.append(o)
        return ToolResult(summary={'status':'MISSING','journal':'UNAVAILABLE'})
    path=paths[0].parent
    model=extraction.data['model']
    refs=[reference(path/name,kind='SQLITE' if name=='journal.sqlite3' else 'FILE')
          for name in ('journal.sqlite3','session_manifest.json','checkpoint.json')]
    invalid=False
    for ref in refs:
        if ref.expected_sha256!=ref.read_sha256:
            invalid=True
            ctx.state.verification.append(outcome(ref.ref_id,'INVALID','Corroborating journal differs from preservation inventory',refs=[ref.ref_id]))
    import sqlite3
    try:
        if invalid:raise ValueError('Invalid preserved journal')
        predictions,incidents,status=read_journal(path,model['package_id'],model['schema_sha256'],include_features=True)
    except (ValueError,OSError,sqlite3.Error):
        ctx.state.verification.append(outcome('retained-journal','INVALID','Immutable journal identity, record hashes or cursor integrity failed'))
        status={'sqlite_status':'INVALID'}
    else:
        ctx.state.verification.append(outcome('retained-journal','VERIFIED',
            f'Immutable SQLite record hashes, sequences, model/schema identities and incident cursor verified: {len(predictions)} predictions, {len(incidents)} incidents',
            'Independent historical corroboration only; not the behavioral run being scored',refs=[r.ref_id for r in refs]))
    counts=Counter(o.status for o in ctx.state.verification)
    verdict=next((s for s in ('INVALID','CONFLICTED','MISSING','PARTIAL') if counts[s]),'VERIFIED')
    return ToolResult(summary={'verification_status':verdict,'outcomes':dict(counts),
        'sqlite_status':status['sqlite_status'],'journal_is_scored':False},
        data={'permitted_for_historical_cqi':not any(counts[s] for s in ('INVALID','CONFLICTED','MISSING'))},evidence=refs)


def quality_evaluate(ctx):
    if ctx.state.request.mode=='LIVE_LAB':
        from .live import live_tool
        return live_tool(ctx,'quality.evaluate')
    from cqi_v2 import evaluate
    from demo.backend.schemas import Incident
    verdict=ctx.output('verify.journal')
    if not verdict.data.get('permitted_for_historical_cqi'):
        raise TaskError('EVIDENCE_REJECTED','Verification rejected evidence; no cybersecurity assessment was produced')
    source=ctx.output('native.read_baseline')
    observations=ctx.output('behavior.infer').data['predictions']
    incidents=[Incident.model_validate(i) for i in ctx.output('behavior.explain_incidents').data['incidents']]
    as_of=max(p['window_end'] for p in observations)
    result=evaluate(source.data['rows'],as_of=as_of,observations=observations,incidents=incidents,
                    posture_time=as_of,platform='moodle')
    return ToolResult(summary={'overall':result['overall'],'policy':result['policy']['version'],
        'dimension_count':len(result['dimensions']),'scope':'HISTORICAL_REANALYSIS_PARTIAL',
        'verification_status':verdict.summary['verification_status'],'is_probability':False},
        data={'cqi':result,'as_of_semantics':'Existing accepted-replay policy clock; not an asserted Native collection time',
              'supplementary_zap_scored':False,'verification_gate':verdict.summary})


def quality_check(ctx):
    if ctx.state.request.mode=='LIVE_LAB':
        from .live import live_tool
        return live_tool(ctx,'quality.check_result')
    from demo.backend.services import Application
    source=ctx.output('behavior.extract_features')
    result=ctx.output('quality.evaluate').data['cqi']
    reference_result=Application(Config()).scientific_quality('ACCEPTED_REPLAY',source.data['replay'],source.data['run_id'])
    def close(a,b):return a is b if a is None or b is None else math.isclose(a,b,rel_tol=1e-6,abs_tol=1e-6)
    if not close(result['overall'],reference_result['overall']):
        raise TaskError('CQI_INCONSISTENT','Agent CQI differs from unchanged existing replay implementation')
    if len(result['dimensions'])!=6 or any(not close(a['score'],b['score']) for a,b in zip(result['dimensions'],reference_result['dimensions'])):
        raise TaskError('CQI_DIMENSION_INCONSISTENT','D1-D6 output differs from existing replay implementation')
    if result['is_probability'] is not False:raise TaskError('CQI_SEMANTICS','CQI must not be labelled attack probability')
    return ToolResult(summary={**ctx.output('quality.evaluate').summary,'consistency_with_existing_cqi':'PASS',
        'assessment_outcome':'HISTORICAL_REANALYSIS_WITH_LIMITATIONS'},
        data={'cqi':result,'assessment_summary':assessment_summary(ctx),'verification':[o.model_dump() for o in ctx.state.verification],
              'warnings':['Saved evidence is historical; this task did not observe current lab security.',
                          'ZAP is authentic supplementary evidence. Existing accepted-replay CQI consumes frozen Native inputs; no direct ZAP weight is added.',
                          'Native collection timestamp is unavailable. Existing replay clock semantics are preserved.',
                          'Deterministic specialist agents and frozen ML; no LLM request was made.'],
              'consistency_with_existing_cqi':'PASS'})


def assessment_summary(ctx):
    from demo.backend.adapters import finding
    from demo.backend.privacy import sanitize
    native=ctx.output('native.read_baseline').data['rows']
    zap=ctx.output('zap.read_assessment').data['findings']
    previews=[]
    for source,rows in (('Native',native),('ZAP',zap)):
        for r in rows:
            if r.get('check_result') not in ('FAIL','PARTIAL'):continue
            item=finding(r)
            previews.append({'source':source,'finding_id':item.finding_id,'title':item.title,
                'status':item.status,'severity':item.severity,'confirmation':r['confirmation_status']})
    return sanitize({'native_findings':len(native),'native_failed_checks':sum(r.get('check_result')=='FAIL' for r in native),
        'zap_findings':len(zap),'behavior_windows':len(ctx.output('behavior.infer').data['predictions']),
        'incidents':len(ctx.output('behavior.explain_incidents').data['incidents']),
        'verification_status':ctx.output('verify.journal').summary.get('verification_status','UNAVAILABLE'),
        'findings_preview':previews[:10],
        'zap_scope':'CURRENT_COURSEWORK_POSTURE' if ctx.state.request.mode=='LIVE_LAB' else 'SUPPLEMENTARY_UNPAIRED_HISTORICAL'})


TOOLS={
 'native.read_baseline':('native','PRESERVED_FILES',native_read),
 'native.map_controls':('native','INTERNAL_CODE',native_map),
 'zap.read_assessment':('zap','PRESERVED_FILES',zap_read),
 'zap.check_profile':('zap','INTERNAL_CODE',zap_profile),
 'behavior.extract_features':('behavioral','PRESERVED_FILES_AND_FEATURE_CODE',behavior_extract),
 'behavior.infer':('behavioral','FROZEN_ML_CODE_EXECUTION',behavior_infer),
 'behavior.explain_incidents':('behavioral','INTERNAL_CODE',behavior_incidents),
 'verify.artifacts':('verification','PRESERVED_FILES',verify_artifacts),
 'verify.consistency':('verification','INTERNAL_CODE',verify_consistency),
 'verify.journal':('verification','IMMUTABLE_SQLITE',verify_journal),
 'quality.evaluate':('quality','EXISTING_CQI_CODE',quality_evaluate),
 'quality.check_result':('quality','EXISTING_APPLICATION_CODE',quality_check),
}
