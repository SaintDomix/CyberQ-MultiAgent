#!/usr/bin/env python3
"""Read-only application render fixture from real locked evidence; writes /tmp only."""
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from demo.backend.config import Config
from demo.backend.services import Application


def export():
    app = Application(Config())
    result = {}
    for name, options in [('attack', {}), ('benign', {'replay': 'BENIGN_TEST'}), ('empty', {'mode': 'LIVE_LAB'})]:
        value = app.snapshot(**options)
        result[name] = {k: ([r.model_dump(by_alias=True) for r in v] if isinstance(v, list) else
            v.model_dump(by_alias=True) if hasattr(v, 'model_dump') else v)
            for k, v in value.items() if k != 'artifacts'}
    result['research'] = app.research()
    path = Path('/tmp/product_api_test_payload.json')
    path.write_text(json.dumps(result, sort_keys=True) + '\n')
    print(str(path))


if __name__ == '__main__': export()
