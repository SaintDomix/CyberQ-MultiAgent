#!/usr/bin/env python3
"""Offline plan/verification/import or explicitly authorized lab capture. No training."""
import argparse
import json
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
from branch2.capture.planning import schedule
from branch2.capture.safety import validate_schedule
from branch2.capture.server import CaptureServer,write
from branch2.capture.verification import verify
from branch2.capture.importing import import_capture
from branch2.capture.orchestration import RemoteAgent,capture


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    actions=parser.add_subparsers(dest='action',required=True)
    run=actions.add_parser('run')
    run.add_argument('--context',type=Path,default=ROOT/'experiments/branch2_lab_context.template.json')
    run.add_argument('--seed',type=int,default=42)
    run.add_argument('--run-offset',type=int,default=0,help='Explicit new run-number range for later/replacement sessions')
    run.add_argument('--counts',type=Path,help='Explicit JSON counts for all eight classes; reductions are marked partial')
    run.add_argument('--only-run-id',help='Select one existing seeded run after applying --run-offset; marked partial')
    run.add_argument('--dry-run',action='store_true')
    run.add_argument('--authorized',action='store_true')
    run.add_argument('--interactive',action='store_true')
    run.add_argument('--ssh-host',default='saintdomix@192.168.226.132')
    run.add_argument('--server-repo',default=str(ROOT))
    run.add_argument('--capture-root',default='evidence/branch2_captures/session01')
    agent=actions.add_parser('agent')
    agent.add_argument('operation',choices=['init','begin','finish','abort'])
    agent.add_argument('--root',type=Path,required=True)
    agent.add_argument('--authorized',action='store_true')
    qa=actions.add_parser('verify');qa.add_argument('--root',type=Path,required=True)
    imp=actions.add_parser('import');imp.add_argument('--root',type=Path,required=True)
    imp.add_argument('--name',required=True);imp.add_argument('--allow-partial',action='store_true')
    args=parser.parse_args()
    try:
        if args.action=='agent' or (args.action=='run' and not args.dry_run):
            raise ValueError('COURSEWORK_CAPTURE_DISABLED_PENDING_LAB_HANDOFF')
        if args.action=='run':
            context=json.loads(args.context.read_text())
            plan=schedule(context,args.seed,json.loads(args.counts.read_text()) if args.counts else None,args.run_offset,args.only_run_id)
            validate_schedule(plan)
            if args.dry_run:print(json.dumps(plan,indent=2));return 0
            if not args.authorized:raise ValueError('Explicit --authorized required')
            print(json.dumps(capture(plan,RemoteAgent(args.ssh_host,args.server_repo,args.capture_root),True,args.interactive),indent=2))
        elif args.action=='agent':
            if not args.authorized:raise ValueError('Explicit --authorized required')
            root=args.root.resolve()
            import re
            if root.parent!=ROOT/'evidence/branch2_captures' or not re.fullmatch(r'[A-Za-z0-9_-]+',root.name):raise ValueError('Capture must be one named session under the source-of-truth evidence root')
            server=CaptureServer(root,Path('/var/log/apache2/access.log'))
            data=json.load(sys.stdin)
            if args.operation=='init':server.initialize(data);result={'initialized':True}
            elif args.operation=='begin':result=server.begin(data['run_id'])
            elif args.operation=='abort':result=server.abort(data['run_id'])
            else:result=server.finish(data['run_id'],data['result'])
            print(json.dumps(result))
        elif args.action=='verify':
            result=verify(args.root);print(json.dumps(result,indent=2));return 0 if result['verified'] else 2
        else:print(json.dumps(import_capture(ROOT,args.root,args.name,args.allow_partial),indent=2))
        return 0
    except (ValueError,OSError,KeyError,TypeError,StopIteration):
        print('Branch 2 capture failed: authorization, scope, context, capture integrity or prerequisites; inspect retained artifacts',file=sys.stderr)
        return 1


if __name__=='__main__':raise SystemExit(main())
