"""Server-controlled sources. Browser requests never select filesystem paths."""
from dataclasses import dataclass
import os
from pathlib import Path
import json

ROOT = Path(__file__).resolve().parents[2]
SOURCE_HASHES = {k: v['sha256'] for k, v in json.loads((ROOT / 'demo/artifact_sources.json').read_text())['sources'].items()}


def confined(root, value):
    raw = Path(value)
    if '..' in raw.parts:
        raise ValueError('Traversal rejected')
    result = (Path(root) / raw).resolve()
    if not result.is_relative_to(Path(root).resolve()):
        raise ValueError('Path outside repository')
    return result


@dataclass(frozen=True)
class Config:
    repository: Path = ROOT
    accepted: str = 'outputs/branch2/accepted_behavioral_v2'
    posture: str = 'outputs/branch1_m1d_acceptance_lab_run02/findings.json'
    benign: str = 'outputs/branch2/m5_final_day/blind_benign_test_01/evaluation'
    attack: str = 'outputs/branch2/m5_final_day/fresh_attack_holdout_01'
    runtime_session: str | None = None
    apache_source: str = '/var/log/apache2/access.log'
    lookback: int = 300
    mode: str = 'ACCEPTED_REPLAY'
    expected_root: str = '59a8c7c5d3d51632d0afe45f8cd2fe50570b7af2943d26bb313888327ea9f436'

    def __post_init__(self):
        for name in ('accepted', 'posture', 'benign', 'attack'):
            confined(self.repository, getattr(self, name))
        if self.runtime_session:
            path = confined(self.repository, self.runtime_session)
            roots=[Path(self.repository).resolve()/name for name in ('runtime/behavioral_v2','runtime/coursework/behavioral_v2')]
            if not any(path!=base and path.is_relative_to(base) for base in roots):
                raise ValueError('Only accepted v2 runtime sessions allowed')
        if self.mode not in ('LIVE_LAB', 'ACCEPTED_REPLAY') or not 1 <= self.lookback <= 86400:
            raise ValueError('Invalid mode/horizon')

    @classmethod
    def environment(cls):
        return cls(mode=os.getenv('PRODUCT_MODE', 'ACCEPTED_REPLAY'),
                   runtime_session=os.getenv('PRODUCT_RUNTIME_SESSION') or None)
