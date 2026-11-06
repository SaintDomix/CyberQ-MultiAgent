#!/usr/bin/env python3
"""Offline, additive M5 research workflow. Never collects traffic or alters v1."""
import argparse
import json
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))


def main(argv=None):
    from behavioral_v2.data import sha,write,new_dir,rebuild,discover,external,validate_partitions
    parser=argparse.ArgumentParser(description=__doc__)
    sub=parser.add_subparsers(dest='action',required=True)
    for name in ('diagnose','build','train','external'):
        p=sub.add_parser(name);p.add_argument('--out',type=Path,required=True)
        p.add_argument('--dataset',type=Path,default=ROOT/'data/branch2_v2/final_candidate_01/dataset.json')
        if name in ('diagnose','external'):p.add_argument('--session',type=Path)
        if name in ('train','external'):p.add_argument('--v1-model',type=Path,default=ROOT/'outputs/branch2/m2c_final_01')
        if name=='external':p.add_argument('--study',type=Path,required=True)
    p=sub.add_parser('plan-benign');p.add_argument('--out',type=Path,required=True);p.add_argument('--seed',type=int,default=42)
    p=sub.add_parser('infer');p.add_argument('--out',type=Path,required=True)
    p.add_argument('--model',type=Path,required=True);p.add_argument('--rows',type=Path,required=True)
    args=parser.parse_args(argv)
    try:
        output=args.out.resolve()
        allowed=ROOT/('data/branch2_v3' if args.action=='build' else 'outputs/branch2/m5')
        if not output.is_relative_to(allowed) or output==allowed or output.exists():
            raise ValueError('Use a NEW versioned subdirectory of '+str(allowed))
        if args.action=='plan-benign':
            from behavioral_v2.capture_plan import plan
            out=new_dir(output);result=plan(args.seed);write(out/'capture_plan.json',result)
            print(json.dumps({'planned_benign_runs':24,'network_requests_made':0}));return 0
        if args.action=='infer':
            from behavioral_v2.inference import load
            rows=json.loads(args.rows.read_text());out=new_dir(output)
            package=load(args.model);write(out/'predictions.json',package.predict(rows,explain=True))
            write(out/'provenance.json',{'fit_calls':0,'model_sha256':sha(args.model/'package_manifest.json'),'rows_sha256':sha(args.rows)})
            return 0
        data=json.loads(args.dataset.read_text())
        if args.action in ('build','diagnose'):
            v3,split,cache=rebuild(data,ROOT)
            out=new_dir(output)
            if args.action=='build':
                write(out/'dataset.json',v3);write(out/'split_manifest.json',split)
                write(out/'provenance.json',{'v1_dataset_sha256':sha(args.dataset),
                    'v3_schema_sha256':v3['feature_schema']['sha256'],'source_hashes_verified':True,
                    'external_in_training':False})
                print(json.dumps({'runs':sum(r['included'] for r in v3['runs']),'windows':len(v3['rows']),
                    'features':len(v3['feature_schema']['feature_order'])}))
            else:
                from behavioral_v2.diagnostics import diagnostic,coverage
                session=args.session or discover(ROOT/'runtime/demo')
                rows,predictions,events=external(session)
                validate_partitions(v3,split,rows)
                result=diagnostic(data,split,rows,predictions,events)
                write(out/'diagnostic.json',result);write(out/'benign_coverage.json',coverage(data,cache,ROOT))
                write(out/'external_rows.json',rows)
                write(out/'provenance.json',{'session':str(session.relative_to(ROOT)),
                    'source_files':{n:sha(session/n) for n in ('predictions.jsonl','windows.jsonl','events.jsonl','session_manifest.json')},
                    'external_use':'diagnostic only; no training labels','verified_observations':sum(len(v) for v in events.values()),
                    'bounded_source_reconstruction':True,'raw_requests_persisted':False})
                print(json.dumps({'session':str(session),'windows':len(rows),'groups':{k:v['windows'] for k,v in result['groups'].items()}}))
        elif args.action=='train':
            from behavioral_v2.experiment import train_study
            from branch2.splitting import split_final_runs
            for name,digest in data['sources'].items():
                if sha(ROOT/name)!=digest:raise ValueError('Dataset source hash mismatch')
            split=split_final_runs(data)
            v1=json.loads((ROOT/'data/branch2_v2/final_candidate_01/dataset.json').read_text())
            if [(r['run_id'],r['window_start'],r['source_sha256']) for r in data['rows']] != [(r['run_id'],r['window_start'],r['source_sha256']) for r in v1['rows']]:
                raise ValueError('Paired v1/v2 window inventory mismatch')
            package=train_study(data,split,v1,args.v1_model,output)
            print(json.dumps(package.config,indent=2))
        else:
            from behavioral_v2.experiment import external_compare
            session=args.session or discover(ROOT/'runtime/demo')
            rows,predictions,events=external(session)
            from branch2.splitting import split_final_runs
            validate_partitions(data,split_final_runs(data),rows)
            result=external_compare(rows,predictions,args.study,args.v1_model,output)
            print(json.dumps({k:result[k] for k in ('classification','selected_model','persistence','v1_replay_matches_live')}))
        return 0
    except (ValueError,OSError,KeyError,ImportError) as error:
        # Never echo parser contents, paths carrying queries or source records.
        print('M5 offline operation failed: '+type(error).__name__,file=sys.stderr)
        return 1


if __name__=='__main__':raise SystemExit(main())
