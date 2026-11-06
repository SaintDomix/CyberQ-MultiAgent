#!/usr/bin/env python3
"""Kali execution wrapper for a prepared post-freeze plan; uses M2B unchanged."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'src'))
from branch2.capture.safety import validate_schedule
from branch2.capture.orchestration import capture,RemoteAgent


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--plan',type=Path,required=True);p.add_argument('--binding',type=Path,required=True)
    p.add_argument('--capture-root',default='evidence/branch2_captures/m5_final_day_attack01')
    p.add_argument('--authorized',action='store_true');p.add_argument('--dry-run',action='store_true')
    args=p.parse_args(argv)
    try:
        raw=args.plan.read_bytes();plan=json.loads(raw);binding=json.loads(args.binding.read_bytes())
        validate_schedule(plan)
        if hashlib.sha256(raw).hexdigest()!=binding['schedule_file_sha256'] or plan['m5_freeze_sha256']!=binding['freeze_sha256']:
            raise ValueError('Prepared freeze/plan mismatch')
        freeze_relative=binding.get('freeze_relative_path','outputs/branch2/m5_final_day/freeze_manifest.json')
        if freeze_relative not in ('outputs/branch2/m5_final_day/freeze_manifest.json',
            'outputs/branch2/m5_final_day/candidate_freeze_01/freeze_manifest.json'):
            raise ValueError('Unsupported source-of-truth freeze path')
        if 'worker_wrapper_sha256' in binding and hashlib.sha256(Path(__file__).read_bytes()).hexdigest()!=binding['worker_wrapper_sha256']:
            raise ValueError('Prepared wrapper changed')
        if not re.fullmatch(r'evidence/branch2_captures/m5_[A-Za-z0-9_-]+',args.capture_root):raise ValueError('New M5 capture root required')
        if args.dry_run:
            print(json.dumps({'runs':len(plan['runs']),'planned_requests':plan['estimated_requests'],
                'estimated_seconds':plan['estimated_duration_seconds'],'network_requests':0,'ssh_calls':0}));return 0
        if not args.authorized:raise ValueError('Explicit authorization required')
        raise ValueError('COURSEWORK_REMOTE_CAPTURE_DISABLED')

    except (ValueError,KeyError,OSError,subprocess.SubprocessError):
        print('Fresh attack capture blocked: authorization, prepared plan, server freeze, SSH or lab-worker prerequisites.',file=sys.stderr)
        return 2


if __name__=='__main__':raise SystemExit(main())
