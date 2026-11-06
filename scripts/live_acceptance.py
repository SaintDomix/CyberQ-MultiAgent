#!/usr/bin/env python3
"""Operator-attested operational check; never synthesizes browsing or research labels."""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import sys
import uuid
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from demo.operations import read_state, owned, api
from demo.backend.services import Application
from demo.backend.config import Config
from branch2.live_storage import atomic_json

PENDING = ROOT/'runtime/demo_control/live_acceptance_pending.json'


def run(action, confirm=False, stop=False):
    model=Application(Config()).model()
    if model['integrity']!='VERIFIED':raise ValueError('Accepted model integrity failed')
    state=read_state()
    if not owned(state):raise ValueError('Start the owned demo backend first')
    if action=='begin':
        if PENDING.exists():raise ValueError('Acceptance already pending; finish or cancel it explicitly')
        api(state['port'],'/api/demo/mode',action=True,body={'mode':'LIVE_LAB'})
        s=api(state['port'],'/api/system/status?mode=LIVE_LAB')
        if not s['runtime'].get('process_running'):
            api(state['port'],'/api/runtime/start',action=True)
            import time
            for _ in range(50):
                s=api(state['port'],'/api/system/status?mode=LIVE_LAB')
                if s['runtime'].get('sqlite_status')=='VERIFIED_READ_ONLY':break
                time.sleep(.2)
            else:raise ValueError('Monitor did not reach journal readiness')
        receipt={'receipt_id':datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'-'+uuid.uuid4().hex[:8],
            'before':s,'model_package_id':model['package_id'],'root_sha256':model['root_sha256'],
            'started_at_utc':datetime.now(timezone.utc).isoformat(),'status':'AWAITING_OPERATOR_BROWSING'}
        atomic_json(PENDING,receipt)
        print('Monitor ready. Browse Moodle normally in your own browser. Wait for complete 10-second windows plus grace, then run live_acceptance.py finish. No credentials are requested here.')
        return receipt
    if not PENDING.exists():raise ValueError('No pending operator acceptance')
    receipt=json.loads(PENDING.read_text())
    if action=='cancel':
        receipt.update(status='CANCELLED_BY_OPERATOR',operator_browsing_confirmed=False)
    else:
        if not confirm and input('Have you completed ordinary authorized Moodle browsing? Type YES: ').strip()!='YES':
            raise ValueError('Operator browsing confirmation required')
        after=api(state['port'],'/api/system/status?mode=LIVE_LAB')
        if after['runtime'].get('session_id')!=receipt['before']['runtime'].get('session_id'):
            raise ValueError('Monitoring session changed; do not compare unrelated journals')
        observations=after['observation_count']-receipt['before']['observation_count']
        incidents=after['incident_count']-receipt['before']['incident_count']
        if observations<0 or incidents<0:raise ValueError('Journal counters moved backwards')
        receipt.update(after=after,new_observations=observations,new_incidents=incidents,
            operator_browsing_confirmed=True,no_new_incidents=incidents==0,
            status='PENDING_CLOSED_WINDOWS' if observations==0 else 'PASS_NO_NEW_INCIDENTS' if incidents==0 else 'REVIEW_REQUIRED',
            interpretation='Operational whole-server journal check, not isolated blind research FPR. Any incident requires review; no threshold changes follow.',
            finished_at_utc=datetime.now(timezone.utc).isoformat())
    if stop:api(state['port'],'/api/runtime/stop',action=True)
    out=ROOT/'outputs/demo/live_acceptance';out.mkdir(parents=True,exist_ok=True)
    target=out/(receipt['receipt_id']+'.json')
    with target.open('x') as f:json.dump(receipt,f,indent=2);f.write('\n')
    atomic_json(out/'latest.json',{'status':receipt['status'],'receipt':str(target.relative_to(ROOT)),
        'model_package_id':model['package_id'],'operator_browsing_confirmed':receipt['operator_browsing_confirmed']})
    PENDING.unlink()  # Own mutable pending control state, never source evidence.
    return receipt


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('action',choices=['begin','finish','cancel']);p.add_argument('--confirm-browsing',action='store_true');p.add_argument('--stop-monitor',action='store_true')
    args=p.parse_args()
    try:print(json.dumps(run(args.action,args.confirm_browsing,args.stop_monitor),indent=2))
    except (OSError,ValueError,KeyError):raise SystemExit('Acceptance not completed. Check demo status, retained pending receipt and operator prerequisites; no result fabricated.')
