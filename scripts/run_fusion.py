#!/usr/bin/env python3
"""Offline Fusion + CQI CLI. No branch execution imports."""
import argparse
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from src.fusion.pipeline import evaluate


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    run = commands.add_parser('evaluate')
    for name in ('branch1', 'branch2', 'model-manifest', 'live-acceptance', 'out'):
        run.add_argument('--' + name, required=True)
    run.add_argument('--as-of')
    run.add_argument('--behavior-lookback-seconds', type=int, default=300)
    args = parser.parse_args(argv)
    try:
        result = evaluate(args.branch1, args.branch2, args.model_manifest, args.live_acceptance,
                          args.out, args.as_of, args.behavior_lookback_seconds)
    except (ValueError, OSError, TypeError, KeyError) as exc:
        parser.exit(2, 'Offline fusion failed: ' + str(exc) + '\n')
    print('CQI:', result['cqi']['cqi_display'], '(quality index; not probability)')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
