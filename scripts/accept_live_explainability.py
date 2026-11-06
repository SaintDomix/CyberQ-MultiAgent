#!/usr/bin/env python3
"""Read the actual loopback product API and verify its LIVE journal references.

No inference, feature extraction, training, monitor start or traffic generation.
"""
import argparse
import hashlib
import json
from pathlib import Path
import sqlite3
import sys
from urllib.request import build_opener,ProxyHandler
from zoneinfo import ZoneInfo
from datetime import datetime
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'src'),str(ROOT)]
from behavioral_runtime.package import verify
from demo.backend.explainability import digest


def accept(port,out,before=None):
    if not 1024<=port<=65535:raise ValueError('Invalid loopback port')
    opener=build_opener(ProxyHandler({}))
    def api(path):
        with opener.open(f'http://127.0.0.1:{port}/api/'+path,timeout=15) as response:
            return json.load(response)
    status=api('system/status?mode=LIVE_LAB')
    rows=api('behavior/observations?mode=LIVE_LAB&limit=200')['items']
    incidents=api('behavior/incidents?mode=LIVE_LAB&limit=200')['items']
    assert status['mode']=='LIVE_LAB' and status['model_integrity']=='VERIFIED' and rows
    session_id=status['runtime']['session_id']
    candidates=[]
    for path in (ROOT/'runtime/behavioral_v2').glob('*/session_manifest.json'):
        if json.loads(path.read_text()).get('session_id')==session_id:candidates.append(path.parent.resolve())
    assert len(candidates)==1 and candidates[0].is_relative_to(ROOT/'runtime/behavioral_v2')
    root=candidates[0];dbpath=root/'journal.sqlite3';before_db=hashlib.sha256(dbpath.read_bytes()).hexdigest()
    db=sqlite3.connect(dbpath.as_uri()+'?mode=ro',uri=True)
    stored={}
    try:
        db.execute('PRAGMA query_only=ON')
        for rid,payload,h in db.execute('SELECT record_id,payload,sha256 FROM results'):
            assert hashlib.sha256(payload.encode()).hexdigest()==h;stored[rid]=(json.loads(payload),h)
    finally:db.close()
    if before:
        old={r['observation_id']:r for r in json.loads(Path(before).read_text())['items']}
        assert set(old)=={r['observation_id'] for r in rows}
        for o in rows:
            assert {k:v for k,v in o.items() if k!='explanation'}=={k:v for k,v in old[o['observation_id']].items() if k!='explanation'}
    for o in rows:
        e=o['explanation'];s,h=stored[o['observation_id']];values=s['window']['row']['features']
        assert e['technical']['feature_values']==values and len(values)==83
        assert e['provenance']['feature_evidence']['vector_sha256']==digest(values)
        assert e['provenance']['feature_evidence']['journal_payload_sha256']==h
        assert e['provenance']['feature_evidence']['recomputed'] is False
        assert e['classification']['class']==s['prediction']['xgb_label']
        for part in ('anomaly','classification'):
            for f in e[part]['factors']:assert f['observation']==values[f['feature']]
    selected={}
    for label in ('BENIGN','UNKNOWN_ANOMALY'):
        options=[o for o in rows if o['reconciled_label']==label];assert options
        selected[label]=max(options,key=lambda o:(o['xgb_score'],-o['sequence']))
    known=[o for o in rows if o['reconciled_label'] not in ('BENIGN','UNKNOWN_ANOMALY','UNCERTAIN')]
    if known:selected['KNOWN_PATTERN']=known[0]
    endpoints={}
    for name,o in selected.items():
        e=api('explainability/'+o['observation_id']+'?mode=LIVE_LAB')
        for k in ('anomaly','classification','technical','provenance'):
            assert e[k]==o['explanation'][k]
        endpoints[name]=e
    assert hashlib.sha256(dbpath.read_bytes()).hexdigest()==before_db
    package=verify(ROOT/'outputs/branch2/accepted_behavioral_v2')
    payload={'mode':'LIVE_LAB','status':status,'observations':list(selected.values()),'incidents':incidents,
        'explainability_endpoint_responses':endpoints,'checked_observation_ids':[o['observation_id'] for o in rows],
        'session':str(root.relative_to(ROOT)),'all_current_vectors_verified':True,
        'known_pattern_available':bool(known),'known_pattern_note':None if known else
            'Current SQLI_ATTEMPT classifier scores remain below the frozen confidence threshold; no known attempt is asserted.',
        'journal_sha256_before':before_db,'journal_sha256_after':before_db,'package_root_sha256':package['root_sha256'],
        'network_requests_to_target':0,'monitor_started':False,'model_calls':0,'feature_recomputation_calls':0,
        'API_path':'actual loopback backend; same observation/explainability endpoints used by the frontend'}
    if out.exists():raise FileExistsError('Refuse to overwrite live acceptance')
    out.mkdir(parents=True)
    (out/'live_api_payload.json').write_text(json.dumps(payload,sort_keys=True,indent=2,allow_nan=False)+'\n')
    lines=['# Current LIVE observation explanation acceptance','',
        'Source: actual production loopback API, LIVE_LAB, existing selected journal. Monitoring was intentionally stopped; it remains stopped.',
        f"Verified all {len(rows)} current observation vectors directly against their SHA256-verified saved journal payloads.",'',
        'No inference, extraction, training or target traffic was invoked.','']
    for label,o in selected.items():
        e=o['explanation'];local=datetime.fromisoformat(o['window_start']).astimezone(ZoneInfo('Asia/Qyzylorda'))
        lines += [f'## {label}', '', o['observation_id'],f"Window: {local.isoformat()} (Asia/Qyzylorda)",
            f"OCSVM {o['novelty_state']}, score {o['novelty_score']}; XGBoost {o['xgb_label']}, uncalibrated score {o['xgb_score']}.",
            e['summary'],'','Anomaly/reference factors:','']+['- '+f['human_text'] for f in e['anomaly']['factors']]
        lines += ['','Classifier factors:','']+['- '+f['human_text'] for f in e['classification']['factors']]
        lines += ['',f"SHAP: {e['evidence_quality']['shap_status']}. Actual inference vector reused, hash {e['provenance']['feature_evidence']['vector_sha256']}.",'']
    lines += [payload['known_pattern_note'] or 'Known-pattern example included.', '',
        'Observation is not incident. UNKNOWN and known-attempt escalation use unchanged frozen policy.']
    (out/'report.md').write_text('\n'.join(lines)+'\n')
    print(json.dumps({'status':'PASS','session':payload['session'],'current_observations_verified':len(rows),
        'selected':{k:v['observation_id'] for k,v in selected.items()},'known_pattern_available':bool(known),
        'journal_unchanged':True,'package_root':package['root_sha256']}))


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--port',type=int,default=8000)
    parser.add_argument('--out',default='outputs/explainability/task2a1_live_01')
    parser.add_argument('--before',default=None)
    args=parser.parse_args();out=(ROOT/args.out).resolve()
    if not out.is_relative_to(ROOT/'outputs/explainability'):raise SystemExit('Invalid acceptance output root')
    accept(args.port,out,args.before)
