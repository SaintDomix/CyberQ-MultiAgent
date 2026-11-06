"""Offline adapters for saved Branch 1 results; never execute source tools."""

from copy import deepcopy
import hashlib
import json
from pathlib import Path
from urllib.parse import urlsplit

from .models import (
    CheckResult, ConfirmationStatus, Provenance, SecurityFinding, Severity,
    deterministic_id, record_digest,
)

BASELINE_SOURCES = {
    "external_mvp": "outputs/security_scan_local/security_assessment.json",
    "deep_v2": "evidence/baseline/branch1/deep_v2_results/deep_v2_assessment.json",
    "role_review_v3": "evidence/baseline/branch1/role_access_review_v3.json",
}


def _enum_or_none(enum, value, notes, name):
    if value is None:
        return None
    if enum is CheckResult and value in {"N/A", "NA"}:
        value = "NOT_APPLICABLE"
    try:
        return enum(value)
    except ValueError:
        notes.append(f"Unmapped {name}: retained only in raw_record.")
        return None


def _confirmation(record, result, notes):
    # Known version-only checks cannot be promoted by an overloaded source token.
    tag = record.get("confidence")
    if tag in {"VERSION-BASED", "VERSION_BASED"} or str(record.get("finding_id", "")).startswith(("ADV-", "PATCH-")):
        notes.append("Version/advisory evidence establishes a version match, not exploitation.")
        return ConfirmationStatus.VERSION_BASED
    if result == CheckResult.NOT_APPLICABLE:
        return ConfirmationStatus.NOT_APPLICABLE
    if result == CheckResult.NOT_TESTED:
        return ConfirmationStatus.NOT_TESTED
    if result == CheckResult.ERROR:
        return ConfirmationStatus.NOT_TESTED
    if tag == "HEURISTIC":
        notes.append("HEURISTIC has no supported confidence magnitude; confirmation remains NOT_CONFIRMED.")
        return ConfirmationStatus.NOT_CONFIRMED
    if tag is not None:
        mapped = _enum_or_none(ConfirmationStatus, tag, notes, "source confidence token")
        if mapped == ConfirmationStatus.CONFIRMED:
            notes.append("CONFIRMED preserves the source observation claim; it does not assert exploitation.")
        return mapped
    return None


def _explicit_url(value):
    """Use only an entire, explicit HTTP(S) URL; do not guess deployment targets."""
    if not isinstance(value, str) or any(c.isspace() for c in value):
        return None
    parsed = urlsplit(value)
    return value if parsed.scheme in {"http", "https"} and parsed.netloc else None


def adapt_record(record: dict, *, source: str, provenance: Provenance) -> SecurityFinding:
    if source not in BASELINE_SOURCES:
        raise ValueError(f"Unsupported baseline source: {source}")
    raw = deepcopy(record)
    notes = provenance.mapping_notes
    identity = deterministic_id(source, provenance.source_file, raw)
    if source == "role_review_v3":
        assessment = raw.get("assessment")
        if assessment == "DISMISSED_LIKELY_GENERIC":
            result, confirmation = CheckResult.DISMISSED, ConfirmationStatus.FALSE_POSITIVE
            notes.append("FALSE_POSITIVE refers to the dismissed role-access candidate, not platform-wide assurance.")
        elif assessment in {"STRONG_REVIEW", "WEAK_REVIEW"}:
            result, confirmation = CheckResult.PARTIAL, ConfirmationStatus.NOT_CONFIRMED
            notes.append("Review strength is not confirmation or confidence magnitude.")
        else:
            result, confirmation = None, None
            notes.append("Unknown role assessment retained only in raw_record.")
        notes.append("HTTP status is response evidence, not check_result; severity/confidence are unavailable.")
        return SecurityFinding(
            evidence_id=identity, finding_id=identity, evidence_source=source,
            provenance=provenance, category="Access Control",
            finding_type="role_access_review", affected_asset=_explicit_url(raw.get("final_url")),
            check_result=result, confirmation_status=confirmation,
            evidence={key: raw[key] for key in (
                "role", "endpoint", "status", "title", "privileged_links_total",
                "privileged_links_unique_vs_anonymous", "privileged_links_overlap_with_admin",
                "same_as_admin", "snapshot_file",
            ) if key in raw}, explanation=raw.get("reason"), raw_record=raw,
        )
    result = _enum_or_none(CheckResult, raw.get("status"), notes, "status")
    confirmation = _confirmation(raw, result, notes)
    severity = _enum_or_none(Severity, raw.get("severity"), notes, "severity")
    if raw.get("confidence") is not None:
        notes.append("Source confidence encodes evidence semantics, not a calibrated confidence estimate; confidence=null.")
    evidence = raw.get("evidence")
    if source == "deep_v2":
        evidence = {key: raw[key] for key in ("observed", "context") if key in raw}
        notes.append("Deep results provide no explicit asset, expected value or evidence reference; none inferred.")
    return SecurityFinding(
        evidence_id=identity, finding_id=raw.get("finding_id") or identity,
        evidence_source=source, provenance=provenance,
        category=raw.get("category"), finding_type=raw.get("indicator"),
        affected_asset=_explicit_url(raw.get("evidence")) if source == "external_mvp" else None,
        check_result=result, confirmation_status=confirmation, severity=severity,
        observed_value=raw.get("observed"), expected_value=raw.get("expected"),
        evidence=evidence, explanation=raw.get("reason"),
        recommendation=raw.get("recommendation"), raw_record=raw,
    )


def load_baseline_source(project: Path, source: str) -> list[SecurityFinding]:
    relative = BASELINE_SOURCES[source]
    data = (project / relative).read_bytes()
    records = json.loads(data)
    if not isinstance(records, list) or any(not isinstance(r, dict) for r in records):
        raise ValueError(f"{relative}: expected a JSON list of objects")
    digest = hashlib.sha256(data).hexdigest()
    findings = []
    for index, raw in enumerate(records):
        provenance = Provenance(
            source_file=relative, source_sha256=digest, record_index=index,
            record_sha256=record_digest(raw), adapter=source,
            source_record_id=raw.get("finding_id"),
        )
        findings.append(adapt_record(raw, source=source, provenance=provenance))
    return findings


def normalize_baseline(project: Path) -> list[SecurityFinding]:
    findings = [finding for source in BASELINE_SOURCES
                for finding in load_baseline_source(project, source)]
    if len({f.evidence_id for f in findings}) != len(findings):
        raise ValueError("Duplicate source observations: preserve and resolve before exporting")
    return findings
