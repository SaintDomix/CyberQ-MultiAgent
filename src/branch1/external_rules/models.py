"""Ported from first_branch_v22; see docs/BRANCH1_PIPELINE.md for changes."""
from dataclasses import dataclass, asdict


@dataclass
class Finding:
    finding_id: str
    category: str
    indicator: str
    status: str
    severity: str
    confidence: str
    finding_family: str
    observed: str
    expected: str
    evidence: str
    reason: str
    recommendation: str

    def to_dict(self):
        return asdict(self)
