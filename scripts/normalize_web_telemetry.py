#!/usr/bin/env python3
"""Offline capability inspection. Export diagnostics/numeric outputs, never raw events."""
import argparse
import json
from pathlib import Path
import shutil
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'src'), str(ROOT)]
from platform_normalization import ingest, adapter
from platform_normalization.bridge import predict


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--input', required=True)
    p.add_argument('--format', choices=['json', 'jsonl', 'csv', 'apache', 'nginx', 'access'])
    p.add_argument('--mapping', help='JSON field mapping; no custom Python required')
    p.add_argument('--platform', choices=['generic_web', 'moodle'], default='generic_web')
    p.add_argument('--routes', help='Optional JSON exact path -> existing semantic category mapping')
    p.add_argument('--predict', action='store_true', help='Saved-model inference only when the minimum telemetry contract passes')
    p.add_argument('--out', required=True, help='New diagnostic JSON; existing files are never overwritten')
    a = p.parse_args()
    out = Path(a.out)
    if shutil.disk_usage(ROOT).free < 500_000_000: p.error('Disk safety threshold reached')
    if out.exists(): p.error('Refuse overwrite')
    file = Path(a.input)
    if file.stat().st_size > 8_000_000: p.error('Source size limit')
    mapping = json.loads(Path(a.mapping).read_text()) if a.mapping else {}
    platform = adapter(a.platform, **({'routes': json.loads(Path(a.routes).read_text())} if a.routes else {}))
    batch = ingest(file.read_bytes(), format=a.format, mapping=mapping, source_reference=file.name, platform=a.platform)
    result = batch.diagnostics(platform)
    if a.predict:
        from behavioral_runtime.package import load
        from platform_normalization.dependencies import behavioral_contract
        if behavioral_contract(batch)['execution_allowed']:
            model = load(ROOT / 'outputs/branch2/accepted_behavioral_v2')
            inferred = predict(batch, model, platform=platform, explain=False)
            result['predictions'] = [{k: v for k, v in r.items() if k not in ('source_file',)} for r in inferred['predictions']]
            result['model_package_id'] = model.accepted_manifest['package_id']
            result['model_domain_caution'] = inferred['compatibility_semantics']
        else: result['model_execution'] = 'BLOCKED_INSUFFICIENT_TELEMETRY'
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open('x') as f: json.dump(result, f, indent=2, sort_keys=True, allow_nan=False); f.write('\n')
    print(json.dumps({'state': batch.state, 'events': len(batch.events), 'output': str(out),
        'behavioral': result['capabilities']['behavioral']['state'], 'training_performed': False}))


if __name__ == '__main__': main()
