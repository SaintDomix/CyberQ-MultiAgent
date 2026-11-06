#!/usr/bin/env python3
"""Export existing accepted benign TRAIN reference; never fit or alter a model."""
import json
from pathlib import Path
import sys
ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / 'src')]
from behavioral_runtime.package import verify
from behavioral_v2.data import sha
from demo.backend.explainability import canonical, digest, REFERENCE
from demo.backend.feature_catalog import CATALOG


def build(root=ROOT):
    accepted = root / 'outputs/branch2/accepted_behavioral_v2'
    manifest = verify(accepted)
    ref = json.loads((accepted / 'model/benign_reference.json').read_text())
    schema = json.loads((accepted / 'model/feature_schema.json').read_text())
    config = json.loads((accepted / 'model/config.json').read_text())
    preprocessing = json.loads((accepted / 'preprocessing.json').read_text())
    if set(CATALOG) != set(ref['feature_order']) or ref['fit_partition'] != 'TRAIN BENIGN only':
        raise ValueError('Catalog/reference identity mismatch')
    value = {'version': 'explanation-reference-1.0', 'package_id': manifest['package_id'],
        'package_root_sha256': manifest['root_sha256'], 'schema_version': schema['version'],
        'schema_sha256': schema['sha256'], 'source': 'outputs/branch2/accepted_behavioral_v2/model/benign_reference.json',
        'source_sha256': sha(accepted / 'model/benign_reference.json'),
        'preprocessing_sha256': sha(accepted / 'preprocessing.json'),
        'method': 'Reuse frozen TRAIN BENIGN median and MAD. Scale: 1.4826*MAD if positive; else IQR/1.349 if positive; else max(abs(median)*0.1,1). No recomputation or fitting.',
        'method_source': 'src/behavioral_v2/inference.py:robust_reference; src/behavioral_v2/study31.py:develop',
        'reference_scope': '101 benign TRAIN windows from the accepted experimental laboratory; not a population range',
        'benign_train_windows': preprocessing['benign_train_windows'], 'benign_train_run_ids': config['benign_fit_ids'],
        'features': {name: {'median': ref['median'][i], 'MAD': ref['MAD'][i], 'scale': ref['scale'][i]}
                     for i, name in enumerate(ref['feature_order'])}}
    value['sha256'] = digest(value)
    return value


if __name__ == '__main__':
    value = build(); content = canonical(value) + '\n'
    if REFERENCE.exists() and REFERENCE.read_text() != content:
        raise SystemExit('Refuse to overwrite a different reference sidecar')
    REFERENCE.write_text(content)
    print(json.dumps({'path': str(REFERENCE.relative_to(ROOT)), 'canonical_sha256': value['sha256'],
                      'file_sha256': sha(REFERENCE), 'features': len(value['features']), 'training_performed': False}))
