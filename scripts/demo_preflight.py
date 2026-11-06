#!/usr/bin/env python3
import argparse
import json
from pathlib import Path
import sys
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from demo.preflight import preflight

if __name__ == '__main__':
    p = argparse.ArgumentParser(description='Read-only operational preflight; no Apache content read or model fitting')
    p.add_argument('--mode', choices=['ACCEPTED_REPLAY','LIVE_LAB'], default='ACCEPTED_REPLAY')
    p.add_argument('--port', type=int, default=8000)
    args = p.parse_args(); result = preflight(args.mode, args.port)
    print(json.dumps(result, indent=2)); raise SystemExit(2 if result['result']=='FAIL' else 0)
