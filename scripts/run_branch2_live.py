#!/usr/bin/env python3
"""Passive M2D saved-model inference. No traffic generation, training or evaluation."""
import argparse
import math
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
from branch2.live import LiveEngine,IntegrityFault


def terminal(prediction):
    decision=prediction['reconciliation']
    print(f"{prediction['emitted_at_utc']} {decision['decision']} IF={'anomaly' if prediction['if_anomalous'] else 'normal'} "
          f"XGB={prediction['xgb_label']} uncalibrated_score={prediction['xgb_confidence']:.3f} "
          f"{decision['reason']} processing_ms={prediction['processing_duration_ms']:.2f}",flush=True)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    sub=parser.add_subparsers(dest='action',required=True);run=sub.add_parser('run')
    run.add_argument('--source',type=Path,default=Path('/var/log/apache2/access.log'))
    run.add_argument('--model',type=Path,default=ROOT/'outputs/branch2/m2c_final_01')
    run.add_argument('--out',type=Path,required=True);run.add_argument('--resume',action='store_true')
    run.add_argument('--duration',type=float);run.add_argument('--poll-interval',type=float,default=.5)
    run.add_argument('--grace',type=float,default=2);run.add_argument('--no-explain',action='store_true')
    args=parser.parse_args()
    try:
        out=args.out.resolve();base=ROOT/'outputs/branch2/live'
        if not out.is_relative_to(base) or out==base:raise ValueError('Use a dedicated session under outputs/branch2/live')
        if args.model.resolve()!=ROOT/'outputs/branch2/m2c_final_01':raise ValueError('Only the frozen final M2C package is authorized')
        if args.duration is not None and (not math.isfinite(args.duration) or not .1<=args.duration<=86400):raise ValueError('Invalid bounded duration')
        engine=LiveEngine(args.source,args.model,out,resume=args.resume,grace=args.grace,
            poll_interval=args.poll_interval,explain=not args.no_explain,status=terminal)
        engine.run(args.duration)
        return 0 if engine.integrity=='OK' else 2
    except IntegrityFault as error:
        print('Live inference integrity fault: '+str(error)+'; no reset performed. Inspect retained session audit.',file=sys.stderr)
        return 2
    except (OSError,ValueError,KeyError):
        print('Live inference stopped: source/model/state/config integrity or filesystem prerequisites; inspect session audit. No reset performed.',file=sys.stderr)
        return 2


if __name__=='__main__':raise SystemExit(main())
