"""Hash-bound acceptance copy and saved inference, never model fitting."""
import json
from pathlib import Path
import shutil

from behavioral_v2.data import sha, write
from behavioral_v2.model31 import load as load_saved
from branch2.live_storage import digest

VERSION = 'accepted-behavioral-v2-1.0'
ORIGIN_ROOT = '0493bd3ec93b58d288269a736abb51a400c89cf66a05e44bd45e75a2e65cc6c1'
PROJECT = Path(__file__).resolve().parents[2]


def verify(path, project=PROJECT):
    path = Path(path).resolve()
    m = json.loads((path / 'accepted_manifest.json').read_text())
    core = {k: v for k, v in m.items() if k not in ('root_sha256', 'package_id')}
    root = digest(core)
    if (m.get('version') != VERSION or m.get('root_sha256') != root
            or m.get('package_id') != 'behavioral-v2-' + root[:20]
            or m.get('decision') != 'A' or m.get('candidate_root_sha256') != ORIGIN_ROOT):
        raise ValueError('Accepted package identity mismatch')
    expected = set(m['files_sha256']) | {'accepted_manifest.json'}
    actual = {str(p.relative_to(path)) for p in path.rglob('*') if p.is_file()}
    if actual != expected:
        raise ValueError('Accepted package file membership mismatch')
    for name, expected_hash in m['files_sha256'].items():
        original = path / name
        p = original.resolve()
        if not p.is_relative_to(path) or original.is_symlink() or sha(p) != expected_hash:
            raise ValueError('Accepted artifact integrity mismatch')
    for name, expected_hash in m['code_sha256'].items():
        p = (Path(project) / name).resolve()
        if not p.is_relative_to(Path(project).resolve()) or sha(p) != expected_hash:
            raise ValueError('Frozen inference implementation changed')
    origin = json.loads((path / 'candidate_freeze.json').read_text())
    if (digest({k: v for k, v in origin.items() if k != 'root_sha256'}) != ORIGIN_ROOT
            or origin['root_sha256'] != ORIGIN_ROOT or origin['candidate_id'] != m['candidate_origin_id']):
        raise ValueError('Accepted origin mismatch')
    for name, expected_hash in origin['artifact_files_sha256'].items():
        if name.startswith('v2_final_candidate/'):
            if sha(path / 'model' / Path(name).name) != expected_hash:
                raise ValueError('Accepted model differs from frozen candidate')
    return m


def load(path):
    manifest = verify(path)
    package = load_saved(Path(path) / 'model')
    if (package.config != manifest['frozen_config']
            or package.feature_schema['sha256'] != manifest['schema_sha256']
            or len(package.feature_schema['feature_order']) != 83
            or package.config['selected_model'] != 'OCSVM'
            or package.config['confidence_threshold'] != .8
            or package.config['persistence'] != 2):
        raise ValueError('Accepted configuration differs from freeze')
    package.accepted_manifest = manifest
    return package


def accept(candidate, decision_path, benign_metrics, attack_metrics, out):
    """Explicit research decision required; no automatic post-hoc performance cutoff."""
    from behavioral_v2.study31 import verify_freeze
    candidate, out = Path(candidate), Path(out)
    f, _ = verify_freeze(candidate / 'freeze_manifest.json')
    decision = json.loads(Path(decision_path).read_text())
    if f['root_sha256'] != ORIGIN_ROOT or decision['decision'] != 'A':
        raise ValueError('Promotion requires decision A and the unchanged candidate')
    if decision['candidate_root_sha256'] != f['root_sha256']:
        raise ValueError('Decision origin mismatch')
    out.mkdir(parents=True, exist_ok=False)
    shutil.copytree(candidate / 'v2_final_candidate', out / 'model')
    for source, name in ((candidate / 'freeze_manifest.json', 'candidate_freeze.json'),
                         (candidate / 'preprocessing.json', 'preprocessing.json'),
                         (candidate / 'validation_metrics.json', 'development_metrics.json'),
                         (Path(decision_path), 'acceptance_decision.json'),
                         (Path(benign_metrics), 'blind_benign_metrics.json'),
                         (Path(attack_metrics), 'fresh_attack_metrics.json')):
        shutil.copyfile(source, out / name)
    limitations = [
        'Validated on the current local Moodle laboratory, student-role browser protocols and seven controlled attempt-pattern classes.',
        'Six fresh benign sessions and two fresh runs per attack class provide limited support; no statistical significance or population generalization claim.',
        'Independent controlled runs are not independent real users. Additional human replication remains future work.',
        'Other LMS accuracy and genuinely unseen threat-class sensitivity have not been validated.',
        'Apache combined logs omit POST bodies. SQLI/XSS/PATH mean URL-visible attempts, never successful exploitation.',
        'XGBoost confidence and novelty scores are uncalibrated; explanations are not causal.',
        'Persistence two applies to UNKNOWN_ANOMALY escalation. Confident known patterns can alert after one window, exactly as frozen.',
        'Model v1 and the candidate freeze remain separate immutable baselines.']
    write(out / 'limitations.json', limitations)
    code = dict(f['code_sha256'])
    for name in ('src/branch2/adapters/apache.py', 'src/branch2/events.py',
                 'src/branch2/windowing.py', 'src/branch2/live.py',
                 'src/branch2/live_reader.py', 'src/branch2/live_storage.py'):
        code[name] = sha(PROJECT / name)
    core = {'version': VERSION, 'decision': 'A', 'candidate_origin_id': f['candidate_id'],
            'candidate_root_sha256': f['root_sha256'], 'schema_sha256': f['schema_sha256'],
            'adapter': f['adapter'], 'frozen_config': f['config'], 'runtime': f['runtime'],
            'no_retraining': True, 'no_holdout_based_tuning': True,
            'confidence_calibrated': False, 'successful_exploitation_confirmed': False,
            'root_convention': 'SHA256 of canonical manifest excluding root_sha256 and package_id; manifest does not hash itself',
            'code_sha256': code,
            'files_sha256': {str(p.relative_to(out)): sha(p) for p in sorted(out.rglob('*')) if p.is_file()}}
    root = digest(core)
    write(out / 'accepted_manifest.json', {**core, 'root_sha256': root,
                                         'package_id': 'behavioral-v2-' + root[:20]})
    return verify(out)
