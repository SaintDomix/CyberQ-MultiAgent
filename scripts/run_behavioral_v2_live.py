#!/usr/bin/env python3
"""Passive accepted-v2 saved inference; no traffic generation or training."""
import argparse
import math
from pathlib import Path
import sys
import json
import os
import re
from datetime import datetime,timezone

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from behavioral_runtime.live import LiveEngine, IntegrityFault


def terminal(p):
    print(f"{p['emitted_at_utc']} observation={p['sequence']} {p['reconciliation']['decision']} "
          f"novelty={p['novelty_state']} XGB={p['xgb_label']} uncalibrated_score={p['xgb_confidence']:.3f}", flush=True)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='action', required=True)
    run = sub.add_parser('run')
    run.add_argument('--source', type=Path, default=Path('/var/log/apache2/access.log'))
    run.add_argument('--accepted', type=Path, default=ROOT / 'outputs/branch2/accepted_behavioral_v2')
    run.add_argument('--out', type=Path, required=True)
    run.add_argument('--resume', action='store_true')
    run.add_argument('--duration', type=float)
    run.add_argument('--poll-interval', type=float, default=.5)
    run.add_argument('--grace', type=float, default=2)
    run.add_argument('--no-explain', action='store_true')
    args = parser.parse_args(argv)
    failure=None;stage='path_validation'
    try:
        out, base = args.out.resolve(), ROOT / 'runtime/coursework/behavioral_v2'
        if not out.is_relative_to(base) or out == base:
            raise ValueError('Use a dedicated coursework monitoring session')
        failure=out.with_suffix('.failure.json')
        if args.accepted.resolve() != ROOT / 'outputs/branch2/accepted_behavioral_v2':
            raise ValueError('Only the accepted Behavioral v2 package is authorized')
        if args.duration is not None and (not math.isfinite(args.duration) or not .1 <= args.duration <= 86400):
            raise ValueError('Invalid duration')
        from coursework.isolation import require_live_owner
        stage='authorization'
        require_live_owner()
        stage='engine_initialization'
        engine = LiveEngine(args.source, args.accepted, out, resume=args.resume,
                            grace=args.grace, poll_interval=args.poll_interval,
                            explain=not args.no_explain, status=terminal)
        import time
        def leased_sleep(seconds):
            require_live_owner()
            time.sleep(seconds)
        stage='monitoring'
        engine.run(args.duration,sleep=leased_sleep)
        return 0 if engine.integrity == 'OK' else 2
    except (OSError, ValueError, KeyError) as error:
        text=str(error)
        code=text if re.fullmatch(r'[A-Z][A-Z0-9_]{3,100}',text) else type(error).__name__
        record={'timestamp':datetime.now(timezone.utc).isoformat(),'stage':stage,'exception_type':type(error).__name__,
                'code':code,'errno':getattr(error,'errno',None)}
        if failure is not None:
            fd=os.open(failure,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
            with os.fdopen(fd,'w') as handle:json.dump(record,handle)
        print(json.dumps(record),file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
