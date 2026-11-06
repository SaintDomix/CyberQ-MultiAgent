"""Hash-pinned accepted research projection. Never execute an experiment or load a model."""
import hashlib
import json
from pathlib import Path
from fastapi import APIRouter
from .config import ROOT
from .runtime import SourceUnavailable

BENCHMARK_ROOT='8ee2a0fe37c4e64760c4bc9a6041718de15716f18d7b82d3e3c19a75e46b7c6a'
ACCEPTED_ROOT='59a8c7c5d3d51632d0afe45f8cd2fe50570b7af2943d26bb313888327ea9f436'
CLASSIFIER_SHA='9d3acb8e87d44d13f2b62ede413e073fb51c3f264db48a6d4d229964f0e6150d'

def benchmark(project=ROOT):
    base=Path(project)/'outputs/behavioral/task2b_benchmark_01'
    try:
        m=json.loads((base/'hashes.json').read_text());files=m['files_sha256']
        root=hashlib.sha256(json.dumps({k:v for k,v in m.items() if k!='root_sha256'},sort_keys=True,separators=(',',':')).encode()).hexdigest()
        if root!=BENCHMARK_ROOT or m['root_sha256']!=root:raise ValueError('identity')
        for name,expected in files.items():
            p=base/name
            if Path(name).is_absolute() or '..' in Path(name).parts or p.is_symlink() or not p.resolve().is_relative_to(base.resolve()):raise ValueError('scope')
            if hashlib.sha256(p.read_bytes()).hexdigest()!=expected:raise ValueError('hash')
        read=lambda n:json.loads((base/n).read_text())
        result=read('pipeline_results.json');decision=read('selection_decision.json');config=read('benchmark_config.json')
        if set(result['pipelines'])!={'A','B','C'} or config['accepted_root']!=ACCEPTED_ROOT:raise ValueError('protocol')
        if any(p['classifier_sha256']!=CLASSIFIER_SHA for p in result['pipelines'].values()):raise ValueError('classifier')
        splits=read('split_receipt.json')
        return {'version':'accepted-benchmark-projection-1.0','integrity':'HASH_VERIFIED','root_sha256':root,
            'source':'outputs/behavioral/task2b_benchmark_01','pipelines':result['pipelines'],
            'classification':read('confusion_matrix.json'),'decision':decision,'config':config,'splits':splits,
            'score_semantics':result['novelty_score_semantics'],
            'limitations':['Six benign sessions; two controlled attack runs per class.','Windows within runs are correlated; no population-level significance claim.',
                'Moodle laboratory validation; equal accuracy on other LMS is not demonstrated.'],
            'experiments_executed':False}
    except (OSError,ValueError,KeyError,TypeError):
        raise SourceUnavailable('Accepted benchmark integrity unavailable; no substitute metrics supplied') from None

router=APIRouter(prefix='/api/research')
@router.get('/benchmark')
def accepted_benchmark():return benchmark()


def pinned_read(relative,expected):
    try:
        p=ROOT/relative
        if p.is_symlink():raise ValueError('scope')
        body=p.read_bytes()
        if hashlib.sha256(body).hexdigest()!=expected:raise ValueError('hash')
        return body
    except (OSError,ValueError):raise SourceUnavailable('Accepted research reference integrity unavailable') from None

@router.get('/normalization-example')
def normalization_example():
    body=pinned_read('outputs/normalization/task2c_03/capability_acceptance.json','cfeab4ba939658c05d5f6192dd8322a53bc895e4f3d287b642c06ef5b186d5f0')
    return {'evidence_type':'ACCEPTED_GENERIC_FIXTURE; no new ingestion or inference',
        'source':'outputs/normalization/task2c_03/capability_acceptance.json',
        'value':json.loads(body)['sources']['GENERIC_RICH_FIXTURE']}

@router.get('/cqi-method')
def cqi_method():
    from fastapi.responses import Response
    body=pinned_read('docs/research/CQI_MATHEMATICAL_MODEL.md','2004a0be578d573003423a18110656d12abde4e5632777f4c4d7de11eebb98a5')
    return Response(body,media_type='text/plain; charset=utf-8')

@router.get('/cqi-sensitivity')
def cqi_sensitivity():
    body=pinned_read('outputs/cqi/task3a_02/sensitivity.json','a35d8a2f890176b2e8c3046dab0e01c59555dae9965aaa37c8569f366c9ab0ec')
    return {'evidence_type':'ACCEPTED_COUNTERFACTUAL_SENSITIVITY; not a live remediation experiment',
        'source':'outputs/cqi/task3a_02/sensitivity.json','result':json.loads(body)}
