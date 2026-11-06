#!/usr/bin/env python3
"""Explicit authorized operational assessment; saved models/CQI are unchanged."""
import argparse
import json
from pathlib import Path
import sys
ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / 'src')]
from demo.backend.services import Application
from demo.backend.config import Config


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=['status', 'assess'])
    parser.add_argument('--authorized', action='store_true')
    parser.add_argument('--without-zap', action='store_true')
    parser.add_argument('--profile',choices=['STANDARD','FULL_AUTHORIZED','PASSIVE_BASELINE'],default='STANDARD')
    parser.add_argument('--target-url',default='http://192.168.226.132/moodle/')
    args = parser.parse_args()
    app = Application(Config())
    if args.action == 'assess':
        if not args.authorized: parser.error('Explicit --authorized is required for laboratory HTTP requests')
        result = app.posture_service.start(zap_enabled=not args.without_zap, background=False,
            mode=args.profile,target_url=args.target_url,authorized=args.authorized)
        quality = app.current_posture_quality(result) if result['status'] in ('COMPLETE', 'PARTIAL') else None
        output = {k: v for k, v in result.items() if k != 'findings'}
        output['current_posture_cqi'] = quality.model_dump() if quality else None
        print(json.dumps(output, indent=2))
        return 0 if result['status'] in ('COMPLETE', 'PARTIAL') else 2
    print(json.dumps({'scanners': app.posture_service.scanners(), 'latest': app.posture_service.latest()}, indent=2))
    return 0


if __name__ == '__main__':
    try: sys.exit(main())
    except (OSError, ValueError): sys.exit('Operational assessment unavailable; no historical result substituted or secret details exported')
