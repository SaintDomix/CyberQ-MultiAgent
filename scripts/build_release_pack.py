#!/usr/bin/env python3
"""Write new release artifacts; never overwrite an existing result or fit models."""
import argparse
import csv
import json
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from demo.release_pack import write_new, export_pack


def main(stage):
    if stage=='reliability':
        from demo.release_benchmarks import reliability
        target=ROOT/'outputs/reliability/final_acceptance.json'
        if target.exists():raise ValueError('Refuse overwrite of reliability receipt')
        result=reliability();write_new(target,result);print(json.dumps({'status':result['status'],'checks':result['checks']}))
        return 0 if result['status']=='PASS' else 2
    if stage=='performance':
        from demo.release_benchmarks import performance
        out=ROOT/'outputs/benchmarks/final'
        if out.exists():raise ValueError('Refuse overwrite of performance artifacts')
        result=performance();write_new(out/'performance.json',result)
        with (out/'performance.csv').open('x',newline='') as f:
            writer=csv.DictWriter(f,fieldnames=['stage','count','mean','median','p95','max','unit']);writer.writeheader()
            writer.writerows({'stage':name,**v} for name,v in result['stages'].items())
        lines=['# Actual saved-evidence performance', '', result['api_transport'], '',
            '| Stage | Count | Mean ms | Median ms | p95 ms | Max ms |','|---|---:|---:|---:|---:|---:|']
        for name,v in result['stages'].items():lines.append(f"| {name} | {v['count']} | {v['mean']:.6f} | {v['median']:.6f} | {v['p95']:.6f} | {v['max']:.6f} |")
        lines += ['',result['detection_latency_semantics'],'',f"Peak process RSS: {result['peak_process_RSS_bytes']} bytes. Runtime DB: {result['runtime_DB_bytes']} bytes. Accepted package: {result['accepted_package_bytes']} bytes.",
            '',f"Measured process CPU seconds: {result['process_CPU_seconds']:.6f}; wall seconds: {result['wall_seconds']:.6f}. No instantaneous CPU percentage is claimed.",
            '', 'Results are machine/scheduler/cache dependent; no performance threshold or model parameter was tuned. No fitting or network calls occurred.']
        write_new(out/'performance.md','\n'.join(lines)+'\n');print(json.dumps(result));return 0
    print(json.dumps(export_pack()));return 0


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('stage',choices=['reliability','performance','pack'])
    try:raise SystemExit(main(p.parse_args().stage))
    except (OSError,ValueError,KeyError) as exc:raise SystemExit('Release artifact generation stopped: '+str(exc))
