#!/usr/bin/env python3
"""Offline development/freeze/holdout gates. Never generates attack traffic."""
import argparse
import json
import os
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'src'))
from behavioral_v2.data import write


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root',type=Path,default=ROOT/'outputs/branch2/m5_final_day')
    sub=parser.add_subparsers(dest='action',required=True)
    sub.add_parser('status')
    p=sub.add_parser('review-historical');p.add_argument('--out',type=Path)
    p=sub.add_parser('review-development');p.add_argument('--summary',type=Path,required=True)
    p.add_argument('--exclude-invalid',required=True,help='Explicit comma-separated immutable INVALID development IDs')
    p=sub.add_parser('build');p.add_argument('--out',type=Path,default=ROOT/'data/branch2_v3/final_day_01')
    p=sub.add_parser('train-freeze');p.add_argument('--dataset',type=Path,default=ROOT/'data/branch2_v3/final_day_01/dataset.json')
    p.add_argument('--out',type=Path)
    p=sub.add_parser('evaluate-fresh');p.add_argument('--freeze',type=Path);p.add_argument('--out',type=Path)
    p=sub.add_parser('attack-plan');p.add_argument('--freeze',type=Path);p.add_argument('--out',type=Path)
    p=sub.add_parser('evaluate-attacks');p.add_argument('--freeze',type=Path);p.add_argument('--capture-root',type=Path,required=True);p.add_argument('--out',type=Path)
    for action in ('human-start','human-stop'):
        p=sub.add_parser(action);p.add_argument('--session-id',choices=['H1','H2','H3'],required=True)
        p.add_argument('--freeze',type=Path);p.add_argument('--authorized',action='store_true')
        if action=='human-start':p.add_argument('--actor-ip',default='192.168.226.129')
        else:p.add_argument('--protocol-complete',action='store_true')
    p=sub.add_parser('evaluate-human');p.add_argument('--freeze',type=Path);p.add_argument('--out',type=Path)
    p=sub.add_parser('evaluate-old-external');p.add_argument('--freeze',type=Path);p.add_argument('--out',type=Path)
    p.add_argument('--session',type=Path,default=ROOT/'runtime/demo/31aff64be5fd482ebfbd2679f157ab73/live_001')
    p=sub.add_parser('audit-import');p.add_argument('--input',type=Path,required=True);p.add_argument('--out',type=Path,required=True)
    args=parser.parse_args(argv)
    try:
        root=args.root.resolve();allowed=ROOT/'outputs/branch2/m5_final_day'
        if root!=allowed and not root.is_relative_to(allowed):raise ValueError('Use new final-day roots only')
        if hasattr(args,'out') and args.out is not None:
            dest=args.out.resolve();base=ROOT/'data/branch2_v3' if args.action=='build' else allowed
            if not dest.is_relative_to(base) or dest==base or dest.exists():raise ValueError('New isolated output required')
        freeze=getattr(args,'freeze',None) or root/'freeze_manifest.json'
        if args.action=='status':
            from behavioral_v2.browser_capture import validate_plan,readiness
            plan=validate_plan(json.loads((root/'predeclared_capture_plan.json').read_text()))
            # Report existence only for blinded TEST; do not open its features.
            present=[s['session_id'] for s in plan['sessions'] if (root/'browser_sessions'/s['session_id']/'manifest.json').is_file()]
            print(json.dumps({'plan_sha256':plan['sha256'],'reserved_sessions':24,'capture_manifests_present':len(present),
                'freeze_exists':freeze.is_file(),'model_promotion':'NOT_AUTHORIZED_WITHOUT_FRESH_EVIDENCE',
                'roles':[readiness(r) for r in sorted({s['role'] for s in plan['sessions']})]},indent=2));return 0
        if args.action=='review-historical':
            from behavioral_v2.features31 import review_historical
            data=json.loads((ROOT/'data/branch2_v2/final_candidate_01/dataset.json').read_text())
            split=json.loads((ROOT/'outputs/branch2/m2c_final_01/split_manifest.json').read_text())
            result=review_historical(data,split,ROOT);write(args.out or root/'historical_train_feature_review.json',result)
            print(json.dumps({k:result[k] for k in ('stage','runs','windows','benign_windows','fit_calls')}));return 0
        if args.action=='review-development':
            from behavioral_v2.development_review import review_development
            result=review_development(root,args.summary,args.exclude_invalid.split(','),ROOT)
            write(root/'development_review.json',result)
            print(json.dumps({'review':result['status'],'included':len(result['included_browser_sessions']),
                'excluded':len(result['excluded_browser_sessions']),'sha256':result['sha256']}))
            return 0 if result['status']=='PASS' else 2
        if args.action=='build':
            from behavioral_v2.study31 import build_development
            old=json.loads((ROOT/'data/branch2_v2/final_candidate_01/dataset.json').read_text())
            split=json.loads((ROOT/'outputs/branch2/m2c_final_01/split_manifest.json').read_text())
            result=build_development(root,old,split,ROOT)
            args.out.mkdir(parents=True,exist_ok=False)
            write(args.out/'dataset.json',result);write(args.out/'split_manifest.json',result['split_manifest'])
            write(args.out/'development_manifest.json',result['development_manifest'])
            print(json.dumps(result['qa']));return 0
        if args.action=='train-freeze':
            from behavioral_v2.study31 import train_freeze
            result=train_freeze(json.loads(args.dataset.read_text()),root,args.out or root/'candidate_01')
        elif args.action=='evaluate-fresh':
            from behavioral_v2.study31 import evaluate_fresh
            result=evaluate_fresh(root,freeze,args.out or root/'fresh_benign_01')
        elif args.action=='attack-plan':
            from behavioral_v2.holdouts31 import attack_plan
            result=attack_plan(freeze,json.loads((ROOT/'experiments/branch2_lab_context.template.json').read_text()),args.out or root/'fresh_attack_plan_01')
        elif args.action=='evaluate-attacks':
            from behavioral_v2.holdouts31 import evaluate_attacks
            result=evaluate_attacks(args.capture_root,freeze,args.out or root/'fresh_attack_01',ROOT)
        elif args.action=='human-start':
            if not args.authorized:raise ValueError('Explicit authorization required')
            from behavioral_v2.holdouts31 import human_start
            result=human_start(root,args.session_id,freeze,args.actor_ip)
        elif args.action=='human-stop':
            if not args.authorized:raise ValueError('Explicit authorization required')
            from behavioral_v2.holdouts31 import human_stop
            result=human_stop(root,args.session_id,freeze,protocol_complete=args.protocol_complete)
        elif args.action=='evaluate-human':
            from behavioral_v2.holdouts31 import evaluate_human
            result=evaluate_human(root,freeze,args.out or root/'human_evaluation_01',ROOT)
        elif args.action=='evaluate-old-external':
            from behavioral_v2.holdouts31 import evaluate_old_external
            result=evaluate_old_external(args.session,freeze,args.out or root/'old_external_replication_01',ROOT)
        else:
            from behavioral_v2.platforms import MoodleAuditAdapter
            adapter=MoodleAuditAdapter(os.environ.get('M5_AUDIT_HMAC_KEY','').encode())
            records=json.loads(args.input.read_text());normalized=[adapter.convert(r) for r in records]
            args.out.mkdir(parents=True,exist_ok=False);write(args.out/'audit_events.json',normalized)
            from behavioral_v2.data import sha
            write(args.out/'provenance.json',{'source_sha256':sha(args.input),'rows':len(normalized),'raw_sensitive_fields_retained':False})
            result={'imported_events':len(normalized),'network_calls':0,'database_queries':0,'raw_sensitive_fields_retained':False}
        print(json.dumps(result,indent=2));return 0
    except (ValueError,KeyError,OSError,ImportError):
        print('M5 stage blocked: missing verified captures, freeze, dependencies, authorization, or evidence integrity. Existing results preserved; no substitute metrics.',file=sys.stderr)
        return 2


if __name__=='__main__':raise SystemExit(main())
