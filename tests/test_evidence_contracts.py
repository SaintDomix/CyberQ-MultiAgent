"""Focused contract and real-baseline regression tests; no external services."""

import csv
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from evidence_contracts import (
    AnomalyAssessment, BehavioralSecurityEvent, Branch, CheckResult, Confidence,
    ConfirmationStatus, Provenance, SecurityFinding, deterministic_id, evidence_from_dict,
)
from evidence_contracts.baseline import BASELINE_SOURCES, adapt_record, load_baseline_source, normalize_baseline
from evidence_contracts.models import record_digest

spec = importlib.util.spec_from_file_location("normalize_cli", ROOT / "scripts/normalize_baseline_evidence.py")
cli = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cli)


class EvidenceContractTests(unittest.TestCase):
    def provenance(self, raw=None):
        return Provenance(source_file="source.json", source_sha256="a" * 64,
                          record_index=0, record_sha256=record_digest(raw or {}), adapter="test")

    def test_finding_json_round_trip(self):
        finding = SecurityFinding(
            evidence_id="test-id", finding_id="source-id", evidence_source="test",
            provenance=self.provenance(), check_result=CheckResult.FAIL,
            confirmation_status=ConfirmationStatus.VERSION_BASED,
            confidence=Confidence(value=0.7, method="fixture"),
            observed_value={"version": 12}, raw_record={"extra": [True, None]},
        )
        self.assertEqual(SecurityFinding.from_json(finding.to_json()), finding)
        self.assertEqual(evidence_from_dict(json.loads(finding.to_json())), finding)
        self.assertEqual(finding.to_dict()["check_result"], "FAIL")
        self.assertEqual(finding.to_dict()["confirmation_status"], "VERSION_BASED")

    def test_behavioral_json_round_trip_and_separate_scores(self):
        event = BehavioralSecurityEvent(
            evidence_id="event", event_id="event", evidence_source="test-model",
            provenance=self.provenance(), anomaly_assessment=AnomalyAssessment.ANOMALOUS,
            raw_anomaly_score=-0.1, anomaly_severity_score=62.0,
            threat_class="UNKNOWN_ANOMALY", threat_probability=None,
            confirmation_status=ConfirmationStatus.NOT_CONFIRMED,
            features={"request_count": 12},
        )
        self.assertEqual(BehavioralSecurityEvent.from_json(event.to_json()), event)
        self.assertEqual(evidence_from_dict(event.to_dict()), event)
        self.assertIsNone(event.confidence)
        self.assertIsNone(event.check_result)
        self.assertEqual(event.branch, Branch.BRANCH_2)

    def test_reject_invalid_values_and_version(self):
        for value in [-0.1, 1.1, float("nan"), True]:
            with self.assertRaises(ValueError):
                Confidence(value=value)
        with self.assertRaises(ValueError):
            SecurityFinding(evidence_id="x", finding_id="x", evidence_source="x",
                            provenance=self.provenance(), check_result="CONFIRMED")
        with self.assertRaises(ValueError):
            SecurityFinding(evidence_id="x", finding_id="x", evidence_source="x",
                            provenance=self.provenance(), schema_version="future")
        for field, value in [("anomaly_severity_score", 101), ("threat_probability", 2)]:
            with self.assertRaises(ValueError):
                BehavioralSecurityEvent(evidence_id="x", event_id="x", evidence_source="x",
                                        provenance=self.provenance(), **{field: value})

    def test_deterministic_ids_ignore_dict_order(self):
        first = {"finding_id": "A", "status": "FAIL"}
        second = {"status": "FAIL", "finding_id": "A"}
        self.assertEqual(deterministic_id("source", "file.json", first),
                         deterministic_id("source", "file.json", second))
        self.assertNotEqual(deterministic_id("other", "file.json", first),
                            deterministic_id("source", "file.json", first))


class BaselineAdapterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.findings = normalize_baseline(ROOT)

    def test_actual_source_counts_and_provenance(self):
        self.assertEqual(len(self.findings), 40)
        for source, expected in [("external_mvp", 23), ("deep_v2", 16), ("role_review_v3", 1)]:
            path = ROOT / BASELINE_SOURCES[source]
            raw = json.loads(path.read_bytes())
            records = load_baseline_source(ROOT, source)
            self.assertEqual(len(records), expected)
            for index, (finding, record) in enumerate(zip(records, raw)):
                self.assertEqual(finding.raw_record, record)
                self.assertEqual(finding.provenance.record_index, index)
                self.assertEqual(finding.provenance.record_sha256, record_digest(record))
                self.assertEqual(finding.provenance.source_sha256, hashlib.sha256(path.read_bytes()).hexdigest())
                self.assertEqual(SecurityFinding.from_json(finding.to_json()), finding)

    def test_status_separation_and_no_fabricated_confidence(self):
        tls = next(f for f in self.findings if f.finding_id == "TLS-001")
        self.assertEqual(tls.check_result, CheckResult.FAIL)
        self.assertEqual(tls.confirmation_status, ConfirmationStatus.CONFIRMED)
        self.assertIsNone(tls.confidence)
        for finding in self.findings:
            self.assertIsNone(finding.root_cause)
            self.assertIsNone(finding.start_utc)
            self.assertIsNone(finding.end_utc)
            self.assertIsNone(finding.affected_component)

    def test_all_version_matches_remain_version_based(self):
        version_findings = [f for f in self.findings if f.raw_record.get("confidence") == "VERSION-BASED"]
        self.assertEqual(len(version_findings), 11)
        self.assertTrue(all(f.confirmation_status == ConfirmationStatus.VERSION_BASED for f in version_findings))
        self.assertTrue(all(f.check_result == CheckResult.FAIL for f in version_findings))

    def test_advisory_cannot_be_promoted_by_source_token(self):
        raw = {"finding_id": "ADV-test", "status": "FAIL", "confidence": "CONFIRMED"}
        finding = adapt_record(raw, source="deep_v2", provenance=EvidenceContractTests().provenance(raw))
        self.assertEqual(finding.confirmation_status, ConfirmationStatus.VERSION_BASED)

    def test_dismissed_role_is_not_vulnerability(self):
        role = next(f for f in self.findings if f.evidence_source == "role_review_v3")
        self.assertEqual(role.check_result, CheckResult.DISMISSED)
        self.assertEqual(role.confirmation_status, ConfirmationStatus.FALSE_POSITIVE)
        self.assertEqual(role.evidence["status"], "200")
        self.assertIsNone(role.severity)
        self.assertIsNone(role.confidence)
        self.assertEqual(role.raw_record["assessment"], "DISMISSED_LIKELY_GENERIC")

    def test_heuristic_not_upgraded(self):
        records = [f for f in self.findings if f.raw_record.get("confidence") == "HEURISTIC"]
        self.assertTrue(records)
        self.assertTrue(all(f.confirmation_status == ConfirmationStatus.NOT_CONFIRMED for f in records))

    def test_unknown_fields_and_tokens_are_preserved(self):
        raw = {"finding_id": "other", "status": "UNRECOGNIZED", "confidence": "95-ish",
               "severity": "MAYBE", "custom": {"payload": [1, 2]}}
        finding = adapt_record(raw, source="external_mvp", provenance=EvidenceContractTests().provenance(raw))
        self.assertIsNone(finding.check_result)
        self.assertIsNone(finding.confirmation_status)
        self.assertIsNone(finding.severity)
        self.assertEqual(finding.raw_record, raw)

    def test_ids_stable_across_repeated_loading(self):
        self.assertEqual([f.evidence_id for f in self.findings],
                         [f.evidence_id for f in normalize_baseline(ROOT)])
        self.assertEqual(len({f.evidence_id for f in self.findings}), 40)

    def test_assets_not_inferred_from_generic_evidence(self):
        self.assertTrue(all(f.affected_asset is None for f in self.findings if f.evidence_source == "deep_v2"))
        header = next(f for f in self.findings if f.finding_id == "HDR-002")
        self.assertIsNone(header.affected_asset)

    def test_cli_exports_offline_and_preserves_existing_files(self):
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory)
            for relative in BASELINE_SOURCES.values():
                destination = project / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes((ROOT / relative).read_bytes())
            output = project / "outputs/normalized_baseline"
            with patch("socket.socket", side_effect=AssertionError("Network forbidden")):
                cli.write_outputs(project, output)
                before = {p.name: p.read_bytes() for p in output.iterdir()}
                cli.write_outputs(project, output)
            self.assertEqual(before, {p.name: p.read_bytes() for p in output.iterdir()})
            rows = json.loads((output / "findings.json").read_text())
            self.assertEqual(len(rows), 40)
            with (output / "findings.csv").open(newline="") as handle:
                csv_rows = list(csv.DictReader(handle))
            self.assertEqual(len(csv_rows), 40)
            self.assertEqual([r["evidence_id"] for r in csv_rows], [r["evidence_id"] for r in rows])
            self.assertEqual(json.loads(csv_rows[0]["raw_record"]), rows[0]["raw_record"])
            summary = json.loads((output / "normalization_summary.json").read_text())
            self.assertEqual(summary["total_records"], 40)
            for relative in BASELINE_SOURCES.values():
                self.assertEqual((project / relative).read_bytes(), (ROOT / relative).read_bytes())
            (output / "findings.json").write_text("preserve this evidence")
            with self.assertRaises(ValueError):
                cli.write_outputs(project, output)
            self.assertEqual((output / "findings.json").read_text(), "preserve this evidence")
            for unsafe in [project / "legacy", project / "outputs/security_scan_local"]:
                with self.assertRaises(ValueError):
                    cli.write_outputs(project, unsafe)


if __name__ == "__main__":
    unittest.main()
