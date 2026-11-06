"""Immutable versioned artifact packages; load trusted local model files only."""
import hashlib
import json
from pathlib import Path
import joblib
import numpy as np
import sklearn
from .features import matrix
from .inference import ModelPackage


def write_json(path, value):
    with Path(path).open('x',encoding='utf-8') as f: json.dump(value,f,indent=2,sort_keys=True,allow_nan=False);f.write('\n')


def new_output(path, project):
    path=Path(path).resolve();root=Path(project).resolve()
    allowed=[root/'outputs/branch2',root/'data/branch2_v2']
    if not any(path.is_relative_to(p) and path!=p for p in allowed): raise ValueError('Use a new subdirectory of outputs/branch2 or data/branch2_v2')
    if path.exists(): raise ValueError('Refusing to overwrite any previous artifact directory')
    return path


def save(package, path, split, metrics, predictions, dataset_hash, *, extra_artifacts=None):
    path=Path(path)
    if path.exists(): raise ValueError('Artifact directory must be new')
    path.mkdir(parents=True)
    joblib.dump(package.isolation_forest,path/'isolation_forest.joblib')
    versions={'numpy':np.__version__,'sklearn':sklearn.__version__,'joblib':joblib.__version__}
    if package.classifier is not None:
        import xgboost
        versions['xgboost']=xgboost.__version__
        package.classifier.save_model(path/'xgboost.json')
    values={'feature_schema.json':package.feature_schema,'class_mapping.json':package.classes,
        'reconciliation.json':package.reconciliation,'benign_reference.json':package.reference,
        'training_metadata.json':{**package.metadata,'library_versions':versions,'dataset_sha256':dataset_hash},
        'train_run_manifest.json':package.metadata['training_run_manifest'],
        'test_run_manifest.json':package.metadata['test_run_manifest'],
        'split_manifest.json':split,'metrics.json':metrics,'predictions.json':predictions,
        'explanations.json':[{'run_id':p['run_id'],'window_start':p['window_start'],'robust':p['robust_explanation'],'shap':p['shap_explanation']} for p in predictions]}
    if extra_artifacts:
        if set(extra_artifacts)&set(values):raise ValueError('Duplicate artifact names')
        if any(Path(name).name!=name for name in extra_artifacts):raise ValueError('Artifact name must be a basename')
        values.update(extra_artifacts)
    for name,value in values.items(): write_json(path/name,value)
    hashes={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(path.iterdir())}
    write_json(path/'package_manifest.json',{'version':'branch2-model-package-1.0',
        'complete_parallel_package':package.classifier is not None,'files_sha256':hashes})


def load(path):
    path=Path(path);manifest=json.loads((path/'package_manifest.json').read_text())
    if manifest['version']!='branch2-model-package-1.0': raise ValueError('Unsupported package version')
    for name,digest in manifest['files_sha256'].items():
        if Path(name).name!=name or hashlib.sha256((path/name).read_bytes()).hexdigest()!=digest: raise ValueError('Artifact integrity mismatch')
    read=lambda name:json.loads((path/name).read_text())
    feature_schema=read('feature_schema.json')
    matrix([],feature_schema) # Validate feature order/hash before deserializing model.
    classifier=None
    if manifest['complete_parallel_package']:
        from xgboost import XGBClassifier
        classifier=XGBClassifier();classifier.load_model(path/'xgboost.json')
    return ModelPackage(joblib.load(path/'isolation_forest.joblib'),classifier,feature_schema,read('class_mapping.json'),
        read('benign_reference.json'),read('reconciliation.json'),read('training_metadata.json'))
