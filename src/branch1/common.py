"""Evidence loading and canonical finding construction, without collection."""
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path

from evidence_contracts import Provenance, SecurityFinding, deterministic_id
from evidence_contracts.models import record_digest


def json_bytes(payload):
    return (json.dumps(payload, indent=2, ensure_ascii=False, allow_nan=False) + "\n").encode()


@dataclass
class Document:
    path: str
    sha256: str
    payload: object

    @classmethod
    def load(cls, path, project=None):
        path = Path(path).resolve()
        data = path.read_bytes()
        name = str(path)
        if project is not None and path.is_relative_to(Path(project).resolve()):
            name = str(path.relative_to(Path(project).resolve()))
        return cls(name, hashlib.sha256(data).hexdigest(), json.loads(data))

    @classmethod
    def generated(cls, path, payload):
        return cls(str(path), hashlib.sha256(json_bytes(payload)).hexdigest(), payload)


def finding(document, source, fid, category, title, result, confirmation, severity,
            observed=None, expected=None, explanation=None, recommendation=None,
            evidence=None, asset=None, component=None, index=0):
    raw = {"finding_id": fid, "category": category, "indicator": title,
           "check_result": result, "confirmation_status": confirmation,
           "severity": severity, "observed": observed, "expected": expected,
           "reason": explanation, "recommendation": recommendation, "evidence": evidence}
    provenance = Provenance(document.path, document.sha256, index, record_digest(raw),
                            source, source_record_id=fid,
                            mapping_notes=["Derived posture rule; raw_record contains rule inputs/results; source file is retained by reference."])
    return SecurityFinding(evidence_id=deterministic_id(source, document.path, raw),
                           finding_id=fid, evidence_source=source, provenance=provenance,
                           category=category, finding_type=title, check_result=result,
                           confirmation_status=confirmation, severity=severity,
                           observed_value=observed, expected_value=expected,
                           explanation=explanation, recommendation=recommendation,
                           evidence=evidence, affected_asset=asset, affected_component=component,
                           raw_record=raw)


def boolean(value):
    if isinstance(value, str):
        value = value.strip().lower()
    if isinstance(value, bool):
        return value
    if value in (0, "0", "false", "off", "no", ""):
        return False
    if value in (1, "1", "true", "on", "yes"):
        return True
    return None
