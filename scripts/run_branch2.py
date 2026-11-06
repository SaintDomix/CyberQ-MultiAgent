#!/usr/bin/env python3
"""Offline Dataset v2 construction, training/evaluation and saved-model inference."""
import argparse
import json
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
from branch2.dataset import build, digest
from branch2.splitting import split_runs
from branch2.models import train
from branch2.evaluation import evaluate
from branch2.artifacts import write_json, new_output, save, load


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    actions=parser.add_subparsers(dest='action',required=True)
    dataset=actions.add_parser('build')
    dataset.add_argument('--metadata',type=Path,default=ROOT/'experiments/experiment_metadata.csv')
    dataset.add_argument('--labels',type=Path,default=ROOT/'experiments/branch2_v2_labels.json')
    dataset.add_argument('--window',type=int,default=10)
    dataset.add_argument('--out',type=Path,required=True)
    training=actions.add_parser('train')
    training.add_argument('--dataset',type=Path,required=True)
    training.add_argument('--out',type=Path,required=True)
    training.add_argument('--seed',type=int,default=42)
    training.add_argument('--test-fraction',type=float,default=.3)
    training.add_argument('--contamination',type=float,default=.1)
    training.add_argument('--confidence-threshold',type=float,default=.8)
    training.add_argument('--if-only',action='store_true',help='Explicit provisional partial IF package; never substitutes a classifier')
    final=actions.add_parser('train-final',help='M2C TRAIN/VALIDATION/frozen TEST; predeclared grids, all eight classes')
    final.add_argument('--dataset',type=Path,required=True)
    final.add_argument('--out',type=Path,required=True)
    final.add_argument('--seed',type=int,default=42)
    inference=actions.add_parser('infer')
    inference.add_argument('--dataset',type=Path,required=True)
    inference.add_argument('--model',type=Path,required=True)
    inference.add_argument('--out',type=Path,required=True)
    args=parser.parse_args()
    try:
        output=new_output(args.out,ROOT)
        if args.action=='build':
            result=build(ROOT,args.metadata,args.labels,args.window)
            output.mkdir(parents=True)
            write_json(output/'dataset.json',result)
            write_json(output/'sufficiency.json',result['sufficiency'])
            write_json(output/'run_inventory.json',result['runs'])
            write_json(output/'source_manifest.json',result['sources'])
            print(f'Dataset v2 provisional: {result["qa"]["run_count"]} runs; {len(result["rows"])} windows; {output}')
        else:
            data=json.loads(args.dataset.read_text())
            if args.action=='train-final':
                from branch2.final_pipeline import run_final
                print(json.dumps(run_final(data,args.dataset,output,ROOT,args.seed),indent=2))
            elif args.action=='train':
                split=split_runs(data,args.seed,args.test_fraction)
                package,heldout=train(data,split,if_only=args.if_only,seed=args.seed,contamination=args.contamination,confidence_threshold=args.confidence_threshold)
                predictions=package.predict(heldout)
                metrics=evaluate(predictions,package.classes)
                save(package,output,split,metrics,predictions,digest(args.dataset))
                print(json.dumps(metrics,indent=2))
            else:
                package=load(args.model)
                predictions=package.predict(data['rows'])
                output.mkdir(parents=True)
                write_json(output/'predictions.json',predictions)
                write_json(output/'inference_metadata.json',{'dataset_sha256':digest(args.dataset),'model_package_sha256':digest(args.model/'package_manifest.json'),
                    'evaluation':'Inference only; may include training runs. Do not count this as held-out evaluation.'})
        return 0
    except (ValueError, OSError, ImportError, KeyError) as error:
        print(f'Branch 2 offline failure: {error}',file=sys.stderr)
        return 1


if __name__=='__main__':raise SystemExit(main())
