#!/usr/bin/env python3
"""Run declared benchmark parents through the production Active Validation engine."""
import argparse
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'src'))
from branch1 import Context
from branch1.common import Document, finding
from branch1.active import Registry, SafetyPolicy, run_active
from branch1.active.advanced import SQLInjection, UnsafeReflection, AccountEnumeration
from branch1.active.runtime import RuntimeContext
from branch1.active.safety import origin
from branch1.reporting import validate_output, write_report


def parents_from_spec(document):
    return [finding(document, 'controlled_benchmark', row['parent_id'], 'Controlled lab benchmark', row['validator'],
                    'NOT_TESTED', 'NOT_TESTED', None, explanation='Declared benchmark candidate; expected labels are fixture design, not measured results', index=i)
            for i,row in enumerate(document.payload)]


def comparison(spec, results):
    by_id = {r['parent_finding_id']: r for r in results}
    rows = []
    for item in spec:
        actual = by_id[item['parent_id']]
        evaluated = actual['execution_status'] == 'EXECUTED'
        measured = {k: actual[k] for k in ('outcome', 'check_result', 'confirmation_status')}
        rows.append({'parent_id': item['parent_id'], 'expected': item['expected'], 'actual': measured,
                     'evaluated': evaluated, 'matched': measured == item['expected'] if evaluated else None})
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--target', required=True)
    parser.add_argument('--context-env', default='B1_BENCH_CONTEXT')
    parser.add_argument('--active', action='store_true')
    parser.add_argument('--authorized', action='store_true')
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    try:
        out = validate_output(ROOT,args.out)
        if out.exists() and any(out.iterdir()): raise ValueError('Use a new empty output directory')
        runtime = RuntimeContext.from_env(args.context_env)
        spec = Document.load(Path(__file__).with_name('expected_outcomes.json'), ROOT)
        parents = parents_from_spec(spec)
        for row in spec.payload:
            url = runtime.mappings[row['parent_id']][row['validator']]['url']
            if origin(url) != origin(args.target): raise ValueError('Benchmark context must match explicit target origin')
        policy = SafetyPolicy(args.target,args.active,args.authorized,24,5,0.5)
        ctx = Context(ROOT,output=out)
        summary = run_active(ctx,parents,policy,registry=Registry((SQLInjection(),UnsafeReflection(),AccountEnumeration())),runtime=runtime)
        checks = comparison(spec.payload,ctx.artifacts['active_validation_results.json'])
        ctx.artifacts['benchmark_comparison.json'] = checks
        write_report(ctx,parents,{'controlled_benchmark':len(parents)}, {p.evidence_id:'controlled_benchmark' for p in parents},active_summary=summary)
        print(f'Benchmark: {len(parents)} declared candidates; {summary["requests_used"]} requests. Evidence: {out}')
        if args.active and not all(r['matched'] is True for r in checks):
            return 2  # Includes skipped/error results, never counts those as negatives.
        return 0
    except (ValueError, OSError, KeyError, TypeError):
        print('Benchmark failed: invalid scope/context/output or bounded execution configuration',file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
