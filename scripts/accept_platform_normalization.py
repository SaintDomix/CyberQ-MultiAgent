#!/usr/bin/env python3
"""Offline hash-bound shadow proof. No network, fitting, new captures or raw exports."""
import argparse
from dataclasses import asdict,replace
import gzip
import hashlib
import json
from pathlib import Path
import shutil
import sys
import time
import numpy as np

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'src'),str(ROOT)]
from platform_normalization import ingest,adapter
from platform_normalization.schema import digest,NormalizedBatch
from platform_normalization.bridge import legacy_event,feature_rows,predict
from platform_normalization.dependencies import dependency_matrix,behavioral_contract
from platform_normalization.posture import control_inventory
from behavioral_runtime.package import load,verify
from behavioral_v2.features31 import extract
from behavioral_v2.browser_capture import attribute_slice,ATTRIBUTION_POLICY
from behavioral_v2.episodes import episodes
from branch2.adapters.apache import read_log
from demo.backend.services import Application
from demo.backend.config import Config
from demo.backend.explanation_sources import replay_features,key
from demo.backend.explainability import explain


def write(path,value):
    with path.open('x') as f:json.dump(value,f,indent=2,sort_keys=True,allow_nan=False);f.write('\n')


def owned_browser_events(run):
    p=ROOT/'outputs/branch2/m5_final_day/browser_sessions'/run/'manifest.json'
    manifest=json.loads(p.read_text());prov=manifest['provenance'];source=Path(prov['source_path'])
    found=None
    # Rotation does not authorize different bytes. An archive is accepted only
    # when the exact original bounded source slice SHA256 matches.
    for path in [source]+sorted(source.parent.glob(source.name+'.*')):
        try:
            opener=gzip.open if path.suffix=='.gz' else open
            with opener(path,'rb') as f:
                f.seek(prov['offset_start']);raw=f.read(prov['offset_end']-prov['offset_start'])
            if hashlib.sha256(raw).hexdigest()==prov['slice_sha256']:found=(path,raw);break
        except (OSError,EOFError):continue
    if found is None:raise ValueError('Exact accepted source bytes unavailable for '+run)
    old,reproduced=attribute_slice(found[1],source,prov['offset_start'],prov['start_utc'],prov['end_utc'],
        manifest['actor_id'],'M5Capture/'+run,prov['expected_user_agent_sha256'],ATTRIBUTION_POLICY)
    assert all(prov.get(k)==v for k,v in reproduced.items()) and old
    b=ingest(found[1],format='apache',platform='moodle',source_reference=str(source))
    assert b.state=='COMPLETE'
    owned={r['start']+1:r for r in prov['accepted_source_byte_ranges']};position=prov['offset_start']
    selected=[]
    for event,line in zip(b.events,found[1].splitlines(keepends=True)):
        start=position;position+=len(line)
        if start+1 in owned:
            assert hashlib.sha256(line).hexdigest()==owned[start+1]['sha256']
            selected.append(replace(event,line_number=start+1,record_sha256=owned[start+1]['sha256']))
    b.events=selected
    assert [asdict(e) for e in old]==[asdict(legacy_event(e)) for e in b.events]
    return old,b,{'session_id':run,'manifest_sha256':hashlib.sha256(p.read_bytes()).hexdigest(),
        'slice_sha256':prov['slice_sha256'],'resolved_archive':str(found[0]),
        'accepted_records':len(old),'ambient_excluded':prov['foreign_records'],
        'ownership_filtering_reproduced':True,'source_relocation':'Hash-identical rotated archive; original manifest remains unchanged.'}


def run(out,reference=None):
    if out.exists():raise FileExistsError('Refuse overwrite')
    if shutil.disk_usage(ROOT).free<500_000_000:raise ValueError('Disk safety threshold')
    model=load(ROOT/'outputs/branch2/accepted_behavioral_v2');platform=adapter('moodle')
    service=Application(Config());old_reference=json.loads(Path(reference).read_text()) if reference else None
    evidence=[];window_checks=[];source_counts={};clock=[];snapshots={};total_events=0
    for source in ['BENIGN_TEST','ATTACK_HOLDOUT']:
        snapshot=service.snapshot(mode='ACCEPTED_REPLAY',replay=source)
        predictions,_,_=service.replay(source,None,snapshot['model'])
        reference_vectors=replay_features(ROOT,predictions,source,model.feature_schema['sha256'])
        if old_reference:
            assert {o.observation_id:digest(o.model_dump(mode='json',by_alias=True)) for o in snapshot['observations']}==old_reference[source]['observations']
            assert digest([o.model_dump(mode='json',by_alias=True) for o in snapshot['incidents']])==old_reference[source]['incidents']
        batches={};events={}
        for run_id in sorted({p['run_id'] for p in predictions}):
            if source=='BENIGN_TEST':
                old,b,receipt=owned_browser_events(run_id);evidence.append(receipt)
            else:
                path=ROOT/'evidence/branch2_captures/m5_fresh_attack_holdout_01'/run_id/'access.log'
                old,errors,h=read_log(path);assert not errors
                t=time.perf_counter();b=ingest(path.read_bytes(),format='apache',platform='moodle',source_reference=str(path));clock.append((time.perf_counter()-t,len(b.events)))
                assert b.state=='COMPLETE' and h==b.source['sha256']
                assert [asdict(e) for e in old]==[asdict(legacy_event(e)) for e in b.events]
                evidence.append({'run_id':run_id,'source_sha256':h,'events':len(old)})
            total_events+=len(old);batches[run_id]=b;events[run_id]={e.line_number:e for e in b.events}
        legacy_rows=[];new_rows=[]
        for p in predictions:
            selected=[events[p['run_id']][n] for n in p['line_numbers']]
            b=batches[p['run_id']]
            subset=NormalizedBatch(selected,b.source,b.detection,b.quality,b.mapping,b.state)
            generated=feature_rows(subset,platform=platform,run_id=p['run_id'],feature_schema_hash=model.feature_schema['sha256'])
            assert len(generated)==1 and key(generated[0])==key(p)
            values=generated[0]['features'];expected=reference_vectors[key(p)]
            assert values==expected
            if old_reference:assert digest(values)==old_reference[source]['features'][p['record_id']]
            assert explain(p,features=values,package_id=snapshot['model']['package_id'])==explain(p,features=expected,package_id=snapshot['model']['package_id'])
            legacy_rows.append({**p,'features':expected,'schema_sha256':model.feature_schema['sha256']})
            new_rows.append({**p,'features':values,'schema_sha256':model.feature_schema['sha256']})
            window_checks.append({'observation_id':p['record_id'],'run_id':p['run_id'],'feature_sha256':digest(values),'event_count':len(selected),'exact_equivalence':True})
        x=np.asarray([[r['features'][k] for k in model.feature_schema['feature_order']] for r in legacy_rows])
        y=np.asarray([[r['features'][k] for k in model.feature_schema['feature_order']] for r in new_rows])
        scaler=model.models['OCSVM']['scaler'];assert np.array_equal(scaler.transform(x),scaler.transform(y))
        a=model.predict(legacy_rows);b=model.predict(new_rows);assert a==b
        for p,q in zip(predictions,b):
            assert p['xgb_label']==q['xgb_label'] and p['novelty_anomalous']==q['novelty_anomalous']
            assert p['reconciliation']==q['reconciliation']
            assert abs(p['novelty_score']-q['novelty_score'])<1e-10
            assert abs(p['xgb_confidence']-q['xgb_confidence'])<1e-10
        assert episodes(a,2)==episodes(b,2)
        source_counts[source]=len(a);snapshots[source]={'observation_count':len(a),'incident_count':len(snapshot['incidents']),'complete_observation_hash':digest([o.model_dump(mode='json',by_alias=True) for o in snapshot['observations']]),'incident_hash':digest([o.model_dump(mode='json',by_alias=True) for o in snapshot['incidents']])}
    # Equivalent generic fixtures; this is an engineering fixture, not a new
    # experimental platform or additional evaluation evidence.
    formats=[('apache.log','apache'),('nginx.log','nginx'),('events.json','json'),('events.jsonl','jsonl'),('events.csv','csv')]
    canonical=[];features=[];verdicts=[]
    for name,fmt in formats:
        batch=ingest((ROOT/'tests/fixtures/normalization'/name).read_bytes(),format=fmt)
        canonical.append([e.analytical() for e in batch.events])
        result=predict(batch,model,explain=False)
        features.append([r['features'] for r in result['rows']])
        verdicts.append([{k:v for k,v in p.items() if k not in ('source_file','source_sha256','line_numbers')} for p in result['predictions']])
    assert all(c==canonical[0] for c in canonical)
    assert all(f==features[0] for f in features) and all(v==verdicts[0] for v in verdicts)
    rich=ingest((ROOT/'tests/fixtures/normalization/events.json').read_bytes(),format='json')
    partial=ingest(json.dumps([{'timestamp':'2026-01-01T00:00:01Z','client_ip':'192.0.2.10','method':'GET','path':'/academy/','status':200}]),format='json')
    context={'authorized_target':True,'http_collection_available':True,'zap_runtime_ready':True}
    capabilities={'MOODLE_VALIDATED_SOURCE':batches[next(iter(batches))].diagnostics(platform,context),
        'GENERIC_RICH_FIXTURE':rich.diagnostics(adapter(),context),'GENERIC_PARTIAL_FIXTURE':partial.diagnostics(adapter(),context)}
    assert not behavioral_contract(partial)['execution_allowed']
    out.mkdir(parents=True)
    write(out/'feature_dependencies.json',dependency_matrix())
    write(out/'branch1_applicability.json',control_inventory(ROOT))
    write(out/'capability_acceptance.json',{'prerequisite_semantics':'Engineering fixture assumes authorized HTTP and ready ZAP; no real scan executed. Internal collector, patch baseline and role sessions are not assumed.','sources':capabilities})
    write(out/'moodle_shadow.json',{'result':'PASS','windows':len(window_checks),'events':total_events,'sources':source_counts,'window_checks':window_checks,'source_provenance':evidence,'snapshots':snapshots,'exact_event_feature_scaler_prediction_episode_explanation_equality':True,'saved_score_absolute_tolerance':1e-10,'feature_order':model.feature_schema['feature_order'],'new_network_requests':0,'fitting_calls':0,'production_frozen_reader_replaced':False})
    elapsed=sum(t for t,n in clock);count=sum(n for t,n in clock)
    write(out/'performance.json',{'source':'14 accepted attack evidence logs, one measured ingestion pass each; includes file read','count':count,'seconds':elapsed,'records_per_second':count/elapsed,'mean_ms_per_record':1000*elapsed/count,'cold_import_and_model_loading_excluded':True})
    write(out/'format_invariance.json',{'result':'PASS','formats':[f for n,f in formats],'events_per_format':len(canonical[0]),'windows_per_format':len(features[0]),'canonical_analytical_sha256':digest(canonical[0]),'feature_vectors_sha256':digest(features[0]),'predictions_sha256':digest(verdicts[0]),'optional_context_missing_accepted':True,'required_query_missing_blocks_inference':True})
    if reference:write(out/'legacy_reference_hashes.json',old_reference)
    write(out/'accepted_integrity.json',{'root_before':model.accepted_manifest['root_sha256'],'root_after':verify(ROOT/'outputs/branch2/accepted_behavioral_v2')['root_sha256'],'feature_count':83})
    print(json.dumps({'result':'PASS','windows':len(window_checks),'events':total_events,'sources':source_counts,'output':str(out),'records_per_second':count/elapsed}))


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--out',default='outputs/normalization/task2c_03');p.add_argument('--reference');a=p.parse_args();run(Path(a.out),a.reference)
