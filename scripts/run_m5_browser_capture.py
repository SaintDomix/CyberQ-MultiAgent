#!/usr/bin/env python3
"""Plan or explicitly authorize real-browser sessions; never invoke ML models."""
import argparse
import json
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'src'))
from behavioral_v2.browser_capture import make_plan,validate_plan,capture,readiness,CaptureError,verify_capture
from behavioral_v2.data import write


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__);sub=p.add_subparsers(dest='action',required=True)
    plan=sub.add_parser('plan');plan.add_argument('--seed',type=int,default=20261014)
    plan.add_argument('--roles',default='student');plan.add_argument('--root',type=Path,default=ROOT/'outputs/branch2/m5_final_day')
    check=sub.add_parser('readiness');check.add_argument('--roles',default='student,teacher,admin')
    run=sub.add_parser('capture');run.add_argument('--root',type=Path,default=ROOT/'outputs/branch2/m5_final_day')
    run.add_argument('--partition',choices=['TRAIN','VALIDATION','TEST'],required=True)
    run.add_argument('--only-session-id');run.add_argument('--actor-ip',default='192.168.226.132')
    run.add_argument('--authorized',action='store_true');run.add_argument('--dry-run',action='store_true')
    run.add_argument('--freeze',type=Path)
    run.add_argument('--resume-completed',action='store_true',help='Verify and skip COMPLETE sessions; never reuse invalid/partial IDs')
    verify=sub.add_parser('verify');verify.add_argument('--root',type=Path,default=ROOT/'outputs/branch2/m5_final_day')
    verify.add_argument('--only-session-id',required=True)
    development=sub.add_parser('collect-development',help='Resumable TRAIN + VALIDATION only; independently verify every COMPLETE capture')
    development.add_argument('--root',type=Path,default=ROOT/'outputs/branch2/m5_final_day')
    development.add_argument('--actor-ip',default='192.168.226.132')
    development.add_argument('--authorized',action='store_true')
    development.add_argument('--dry-run',action='store_true')
    args=p.parse_args(argv)
    try:
        if args.action=='readiness':
            print(json.dumps([readiness(r) for r in args.roles.split(',')],indent=2));return 0
        root=args.root.resolve();allowed=ROOT/'outputs/branch2/m5_final_day'
        if root!=allowed and not root.is_relative_to(allowed):raise CaptureError('INVALID_NEW_M5_ROOT')
        if args.action=='plan':
            plan=make_plan(args.seed,tuple(args.roles.split(',')));root.mkdir(parents=True,exist_ok=True)
            write(root/'predeclared_capture_plan.json',plan)
            print(json.dumps({'sessions':24,'split':plan['split_counts'],'estimated_minutes':plan['estimated_browser_seconds']/60,'network_requests':0}));return 0
        plan=validate_plan(json.loads((root/'predeclared_capture_plan.json').read_text()))
        if args.action=='collect-development':
            from behavioral_v2.development_capture import collect_development
            result=collect_development(root,plan,authorized=args.authorized,dry_run=args.dry_run,
                actor=args.actor_ip,emit=lambda record:print(json.dumps(record),flush=True))
            # Full immutable summary is saved separately on authorized execution.
            print(json.dumps({k:v for k,v in result.items() if k not in ('sessions','verification_receipts')},indent=2))
            return 2 if result['status']=='STOPPED' else 0
        if args.action=='verify':
            print(json.dumps(verify_capture(root,plan,args.only_session_id)));return 0
        sessions=[s for s in plan['sessions'] if s['partition']==args.partition and (not args.only_session_id or s['session_id']==args.only_session_id)]
        if not sessions:raise CaptureError('NO_RESERVED_SESSIONS_SELECTED')
        if args.dry_run:
            print(json.dumps({'sessions':sessions,'network_requests':0,'log_reads':0},indent=2));return 0
        if not args.authorized:raise CaptureError('EXPLICIT_AUTHORIZATION_REQUIRED')
        if args.partition=='TEST':
            from behavioral_v2.study31 import verify_freeze
            if args.freeze is None:raise CaptureError('FROZEN_PACKAGE_REQUIRED_FOR_TEST_CAPTURE')
            verify_freeze(args.freeze)
        # Preflight all selected roles before touching logs or launching browsers.
        for role in {s['role'] for s in sessions}:
            info=readiness(role)
            if not info['credentials_present'] or not info['identity_marker_present']:
                raise CaptureError('MISSING_CREDENTIALS_OR_IDENTITY_MARKER')
        statuses=[]
        for session in sessions:
            existing=root/'browser_sessions'/session['session_id']
            if existing.exists():
                if not args.resume_completed:raise CaptureError('SESSION_ID_ALREADY_USED')
                from behavioral_v2.study31 import load_browser_session
                load_browser_session(root,session,plan)
                print(json.dumps({'session_id':session['session_id'],'status':'VERIFIED_ALREADY_COMPLETE','new_requests':0}),flush=True)
                continue
            result=capture(plan,session['session_id'],root/'browser_sessions',authorized=True,actor=args.actor_ip,freeze_path=args.freeze)
            statuses.append({'session_id':session['session_id'],'status':result['status'],'windows':result['windows'],'error_code':result['error_code']})
            print(json.dumps(statuses[-1]),flush=True)
            if result['status']!='COMPLETE':return 2 # preserve failure; no blind replacement/retries
        return 0
    except (CaptureError,OSError,KeyError,ValueError):
        print('Browser capture unavailable: prerequisites, authorization, reserved split, scope or capture integrity. No secret details exported.',file=sys.stderr)
        return 2


if __name__=='__main__':raise SystemExit(main())
