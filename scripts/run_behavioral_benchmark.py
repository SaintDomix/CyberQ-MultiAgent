#!/usr/bin/env python3
"""Prepare, then execute one isolated Task 2B benchmark. No traffic generation."""
import argparse
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'src'),str(ROOT)]
from behavioral_benchmark.three_pipeline import prepare,execute,write

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action',choices=('prepare','run'))
    parser.add_argument('--out',default='outputs/behavioral/task2b_benchmark_01')
    args=parser.parse_args();out=(ROOT/args.out).resolve()
    if not out.is_relative_to(ROOT/'outputs/behavioral'):
        raise SystemExit('Benchmark artifacts must remain under outputs/behavioral')
    if args.action=='prepare':
        config=prepare(out);print('PROTOCOL_PREPARED',config['sha256'])
    else:
        try:
            results,decision=execute(out);print(decision['decision'])
        except Exception as exc:
            if (out/'execution_started.json').exists() and not (out/'execution_completed.json').exists() and not (out/'execution_failure.json').exists():
                write(out/'execution_failure.json',{'type':type(exc).__name__,'reason':str(exc),
                    'accepted_package_modified':False,'requires_documented_fix_before_any_new_execution':True})
            raise
