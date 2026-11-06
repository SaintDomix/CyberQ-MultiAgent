"""Versioned, JSON-compatible evidence contracts; no scoring or inference."""

from dataclasses import asdict, dataclass, field
from enum import Enum
import hashlib
import json
import math
from typing import Any

SCHEMA_VERSION = "1.0"


class Branch(str, Enum):
    BRANCH_1 = "BRANCH_1"
    BRANCH_2 = "BRANCH_2"


class CheckResult(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    PARTIAL = "PARTIAL"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    NOT_TESTED = "NOT_TESTED"
    ERROR = "ERROR"
    DISMISSED = "DISMISSED"


class ConfirmationStatus(str, Enum):
    CONFIRMED = "CONFIRMED"
    VERSION_BASED = "VERSION_BASED"
    LIKELY = "LIKELY"
    CONTEXTUAL = "CONTEXTUAL"
    NOT_CONFIRMED = "NOT_CONFIRMED"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    NOT_TESTED = "NOT_TESTED"
    FALSE_POSITIVE = "FALSE_POSITIVE"


class Severity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class AnomalyAssessment(str, Enum):
    NORMAL = "NORMAL"
    ANOMALOUS = "ANOMALOUS"


@dataclass
class Confidence:
    """Optional evidence-confidence estimate, never an attack probability."""

    value: float | None = None
    label: str | None = None
    method: str | None = None

    def __post_init__(self):
        if self.value is not None and (
            isinstance(self.value, bool)
            or not isinstance(self.value, (int, float))
            or not math.isfinite(self.value)
            or not 0 <= self.value <= 1
        ):
            raise ValueError("confidence.value must be finite and in [0, 1]")


@dataclass
class Provenance:
    source_file: str
    source_sha256: str
    record_index: int
    record_sha256: str
    adapter: str
    adapter_version: str = "1.0"
    source_record_id: str | None = None
    mapping_notes: list[str] = field(default_factory=list)


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False)


def record_digest(record: dict) -> str:
    return hashlib.sha256(canonical_json(record).encode("utf-8")).hexdigest()


def deterministic_id(source: str, source_file: str, record: dict) -> str:
    """Identity of a source observation, not a deduplication/root-cause key."""
    identity = [SCHEMA_VERSION, source, source_file, record]
    return "evidence-" + hashlib.sha256(canonical_json(identity).encode("utf-8")).hexdigest()


@dataclass(kw_only=True)
class EvidenceRecord:
    evidence_id: str
    branch: Branch
    evidence_source: str
    provenance: Provenance
    category: str | None = None
    finding_type: str | None = None
    affected_asset: str | None = None
    affected_component: str | None = None
    check_result: CheckResult | None = None
    confirmation_status: ConfirmationStatus | None = None
    severity: Severity | None = None
    confidence: Confidence | None = None
    observed_value: Any = None
    expected_value: Any = None
    root_cause: str | None = None
    evidence: Any = None
    explanation: str | None = None
    recommendation: str | None = None
    start_utc: str | None = None
    end_utc: str | None = None
    raw_record: dict[str, Any] = field(default_factory=dict)
    schema_version: str = SCHEMA_VERSION

    def __post_init__(self):
        if self.schema_version != SCHEMA_VERSION:
            raise ValueError(f"Unsupported schema version: {self.schema_version}")
        for name, enum in [("branch", Branch), ("check_result", CheckResult),
                           ("confirmation_status", ConfirmationStatus), ("severity", Severity)]:
            value = getattr(self, name)
            if value is not None:
                setattr(self, name, enum(value))
        if not isinstance(self.provenance, Provenance):
            raise TypeError("provenance must be Provenance")
        if self.confidence is not None and not isinstance(self.confidence, Confidence):
            raise TypeError("confidence must be Confidence or None")
        # Reject unsupported values and non-finite numbers before export.
        canonical_json(asdict(self))

    def to_dict(self) -> dict:
        # JSON conversion also turns str enums into plain strings.
        return json.loads(canonical_json(asdict(self)))

    def to_json(self) -> str:
        return canonical_json(self.to_dict())

    @classmethod
    def from_dict(cls, payload: dict):
        values = dict(payload)
        values["provenance"] = Provenance(**values["provenance"])
        if values.get("confidence") is not None:
            values["confidence"] = Confidence(**values["confidence"])
        return cls(**values)

    @classmethod
    def from_json(cls, payload: str):
        return cls.from_dict(json.loads(payload))


@dataclass(kw_only=True)
class SecurityFinding(EvidenceRecord):
    finding_id: str
    branch: Branch = Branch.BRANCH_1
    record_type: str = "security_finding"

    def __post_init__(self):
        super().__post_init__()
        if self.branch != Branch.BRANCH_1 or self.record_type != "security_finding":
            raise ValueError("SecurityFinding must be a Branch 1 security_finding")


@dataclass(kw_only=True)
class BehavioralSecurityEvent(EvidenceRecord):
    event_id: str
    branch: Branch = Branch.BRANCH_2
    record_type: str = "behavioral_security_event"
    anomaly_assessment: AnomalyAssessment | None = None
    raw_anomaly_score: float | None = None
    anomaly_severity_score: float | None = None
    threat_class: str | None = None
    threat_probability: float | None = None
    model_reference: str | None = None
    feature_schema_version: str | None = None
    features: dict[str, float] | None = None

    def __post_init__(self):
        if self.anomaly_assessment is not None:
            self.anomaly_assessment = AnomalyAssessment(self.anomaly_assessment)
        super().__post_init__()
        if self.branch != Branch.BRANCH_2 or self.record_type != "behavioral_security_event":
            raise ValueError("BehavioralSecurityEvent must be a Branch 2 behavioral_security_event")
        for name, maximum in [("anomaly_severity_score", 100), ("threat_probability", 1)]:
            value = getattr(self, name)
            if value is not None and (
                isinstance(value, bool) or not isinstance(value, (int, float))
                or not math.isfinite(value) or not 0 <= value <= maximum
            ):
                raise ValueError(f"{name} must be finite and in [0, {maximum}]")


def evidence_from_dict(payload: dict) -> EvidenceRecord:
    types = {"security_finding": SecurityFinding,
             "behavioral_security_event": BehavioralSecurityEvent}
    try:
        cls = types[payload["record_type"]]
    except KeyError as exc:
        raise ValueError("Unknown or missing record_type") from exc
    return cls.from_dict(payload)
