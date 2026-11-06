#!/usr/bin/env python3
"""Reproducible offline assessment/reporting from frozen Branch 1/2 outputs."""
import argparse
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from src.reporting.assessment import assess


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    commands=parser.add_subparsers(dest='command',required=True)
    run=commands.add_parser('assess')
    for name in ('branch1','branch2','model-manifest','live-acceptance','out'):run.add_argument('--'+name,required=True)
    run.add_argument('--as-of')
    run.add_argument('--behavior-lookback-seconds',type=int,default=300)
    run.add_argument('--baseline-as-of');run.add_argument('--sqli-as-of')
    run.add_argument('--expected-sqli-members',type=int,default=5)
    args=parser.parse_args(argv)
    try:
        result=assess(args.branch1,args.branch2,args.model_manifest,args.live_acceptance,args.out,
            args.as_of,args.behavior_lookback_seconds,args.baseline_as_of,args.sqli_as_of,args.expected_sqli_members)
    except (ValueError,OSError,KeyError,TypeError) as exc:parser.exit(2,'Offline assessment failed: '+str(exc)+'\n')
    print('Acceptance:',result['acceptance']['overall'],'('+result['acceptance']['profile']+')')
    print('CQI:',result['assessment']['cqi']['cqi_display'],'— quality index, not probability')
    return 0 if result['acceptance']['overall']=='PASS' else 1


if __name__=='__main__':raise SystemExit(main())
