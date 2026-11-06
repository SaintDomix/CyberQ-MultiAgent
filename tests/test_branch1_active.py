"""Active validation uses mocked HTTP only; no lab network access."""
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
import requests
from branch1 import Context, run
from branch1.common import Document, finding
from branch1.active import Registry, SafetyPolicy, run_active
from branch1.active.models import Decision, Outcome, RequestSpec
from branch1.active.safety import Executor, Response, SafetyError
from branch1.active.validators import SensitivePath, OpenRedirect
from branch1.active.redaction import redact
from branch1.reporting import write_report
from evidence_contracts import SecurityFinding

TARGET = "http://127.0.0.1/moodle/"


def parent(title="Exposed Git metadata", category="Exposure", url="http://127.0.0.1/.git/HEAD", evidence=None, confirmation="LIKELY"):
    return finding(Document.generated("fixture.json", {}), "fixture", "fixture-parent", category, title,
                   "PARTIAL", confirmation, "LOW", asset=url, evidence=evidence)


def response(status=200, body="", headers=None, url="http://127.0.0.1/.git/HEAD"):
    return Response(status, url, headers or {}, body.encode())


def executor(replies, budget=20):
    session = MagicMock()
    queue = []
    for item in replies:
        if isinstance(item, Exception):
            queue.append(item)
        else:
            mocked = MagicMock()
            mocked.__enter__.return_value = mocked
            mocked.status_code, mocked.headers = item.status, item.headers
            mocked.iter_content.return_value = [item.body]
            queue.append(mocked)
    session.get.side_effect = queue
    sleep = MagicMock()
    result = Executor(SafetyPolicy(TARGET, True, True, budget), session=session, clock=lambda: 0, sleep=sleep)
    return result, session, sleep


class PlanningTests(unittest.TestCase):
    def test_offline_zero_network_deterministic_parent_preservation(self):
        with patch("socket.socket", side_effect=AssertionError("No network")), patch("requests.Session", side_effect=AssertionError("No client")):
            parents, _, _ = run(Context(ROOT))
            original = copy.deepcopy([p.to_dict() for p in parents])
            first, second = Context(ROOT), Context(ROOT)
            summary = run_active(first, parents, SafetyPolicy())
            self.assertEqual(summary, run_active(second, parents, SafetyPolicy()))
        self.assertEqual(first.artifacts, second.artifacts)
        self.assertEqual(original, [p.to_dict() for p in parents])
        self.assertEqual(summary["candidate_count"], 40)
        self.assertEqual(summary["applicability_counts"], {"NOT_APPLICABLE":26, "MISSING_CONTEXT":9, "APPLICABLE":5})
        self.assertEqual(summary["requests_used"], 0)
        self.assertEqual(first.artifacts["active_validation_findings.json"], [])
        self.assertTrue(all(r["confirmation_status"] == "NOT_TESTED" for r in first.artifacts["active_validation_results.json"]))
        dismissed = next(p for p in first.artifacts["active_validation_plan.json"] if p["parent_confirmation_status"] == "FALSE_POSITIVE")
        self.assertEqual(dismissed["applicability"], "NOT_APPLICABLE")
        self.assertEqual(sum(p["parent_confirmation_status"] == "VERSION_BASED" for p in first.artifacts["active_validation_plan.json"]), 11)

    def test_registry_extension(self):
        class Future:
            name = "future"
            def propose(self, p): return Decision("UNSUPPORTED", "Not implemented")
        registry = Registry((Future(),))
        plans = registry.plan([parent()], SafetyPolicy())
        self.assertEqual(plans[0].proposed_validator, "future")
        self.assertEqual(plans[0].confirmation_status, "NOT_TESTED")
        with self.assertRaises(ValueError): Registry((Future(), Future()))

    def test_context_gates(self):
        registry = Registry()
        outside = parent(url="http://example.invalid/.git/HEAD")
        self.assertEqual(registry.plan([outside], SafetyPolicy(TARGET))[0].applicability, "NOT_APPLICABLE")
        unknown = parent(url=None)
        self.assertEqual(registry.plan([unknown], SafetyPolicy())[0].applicability, "NOT_APPLICABLE")
        redirect = parent("Open redirect", "HTTP Configuration", evidence={"active_context": {"url": TARGET}})
        self.assertEqual(registry.plan([redirect], SafetyPolicy())[0].applicability, "NOT_APPLICABLE")

    def test_cli_rejects_active_without_flags_and_live_planning(self):
        for args in [("--active",), ("--plan-active", "--active"),
                     ("--plan-active", "--active", "--authorized"),
                     ("--plan-active", "--active", "--target", TARGET),
                     ("--plan-active", "--mode", "live-passive")]:
            result = subprocess.run([sys.executable, "-B", str(ROOT/"scripts/run_branch1.py"), *args], capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)

    def test_redacted_report_and_provenance(self):
        parents, counts, assignments = run(Context(ROOT))
        original = copy.deepcopy([p.to_dict() for p in parents])
        with tempfile.TemporaryDirectory() as directory:
            ctx = Context(Path(directory), output=Path(directory)/"outputs/plan")
            summary = run_active(ctx, parents, SafetyPolicy())
            report = write_report(ctx, parents, counts, assignments, active_summary=summary)
            for row in json.loads((ctx.output/"findings.json").read_text()):
                SecurityFinding.from_dict(row)
            self.assertEqual(report["total_records"], 40)
            self.assertNotIn("kdudh0i859j1930b1ms0h7cg4c", (ctx.output/"findings.json").read_text())
            self.assertEqual(report, write_report(ctx, parents, counts, assignments, active_summary=summary))
        self.assertEqual(original, [p.to_dict() for p in parents])

    def test_active_plan_does_not_mutate_source_evidence(self):
        parents, _, _ = run(Context(ROOT))
        sources = {ROOT/p.provenance.source_file for p in parents}
        before = {str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in sources}
        run_active(Context(ROOT), parents, SafetyPolicy())
        self.assertEqual(before, {str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in sources})


class SafetyTests(unittest.TestCase):
    def test_authorization_required_even_for_executor_construction(self):
        for policy in [SafetyPolicy(), SafetyPolicy(TARGET, False, True), SafetyPolicy(TARGET)]:
            with self.assertRaises(SafetyError): Executor(policy)
        for options in [(None, True, True), (TARGET, True, False)]:
            with self.assertRaises(SafetyError): SafetyPolicy(*options)

    def test_bounds_and_off_target(self):
        for kwargs in [{"request_budget":0}, {"request_budget":41}, {"timeout":float("nan")}, {"timeout":11}, {"requests_per_second":1}]:
            with self.assertRaises(SafetyError): SafetyPolicy(**kwargs)
        policy = SafetyPolicy(TARGET, True, True)
        for url in ["http://other.invalid/a", "https://127.0.0.1/a", "http://127.0.0.1:8080/a", "http://user:password@127.0.0.1/a", "http://127.0.0.1/delete.php", "http://127.0.0.1/a?token=secret", "http://127.0.0.1/%2e%2e/a"]:
            with self.assertRaises(SafetyError): policy.check(RequestSpec(url, "fixture"))
        with self.assertRaises(SafetyError): policy.check(RequestSpec(TARGET, "fixture", "POST"))

    def test_budget_rate_timeout_redirect_and_cookies(self):
        ex, session, sleep = executor([response(), response()], 2)
        ex.get(RequestSpec(TARGET, "fixture"))
        ex.get(RequestSpec(TARGET, "fixture"))
        with self.assertRaises(SafetyError): ex.get(RequestSpec(TARGET, "fixture"))
        self.assertEqual(session.get.call_count, 2)
        self.assertEqual(session.get.call_args.kwargs, {"timeout":5.0, "allow_redirects":False, "stream":True})
        sleep.assert_called_once_with(4.0)
        self.assertEqual(session.cookies.clear.call_count, 4)
        self.assertFalse(session.trust_env)

    def test_timeout_consumes_budget_and_redacts_error(self):
        ex, session, _ = executor([requests.Timeout("token=do-not-export")], 1)
        with self.assertRaises(requests.Timeout): ex.get(RequestSpec(TARGET, "fixture"))
        self.assertEqual(ex.remaining, 0)
        self.assertEqual(ex.transcript[0]["error"], "Timeout")
        self.assertNotIn("do-not-export", json.dumps(ex.transcript))

    def test_response_size_and_total_deadline(self):
        ex, _, _ = executor([Response(200, TARGET, {}, b"x"*65537)])
        with self.assertRaises(requests.RequestException): ex.get(RequestSpec(TARGET, "fixture"))
        ex, _, _ = executor([response()])
        ex.clock = MagicMock(side_effect=[0, 6])
        with self.assertRaises(requests.RequestException): ex.get(RequestSpec(TARGET, "fixture"))

    def test_secrets_redaction(self):
        values = {"Authorization":"Bearer bearer-secret", "Set-Cookie":"Custom=custom-secret", "password":"password-secret",
                  "url":"http://user:credential-secret@127.0.0.1/a?token=query-secret",
                  "text":"Cookie: Custom=text-secret; Other=other-secret\nMoodleSession=session-secret; password='quoted-secret'\n<input value='hidden-secret' name='sesskey'>\nlink http://a.invalid/?token=embedded-secret"}
        serialized = json.dumps(redact(values))
        for secret in ["bearer-secret", "custom-secret", "password-secret", "credential-secret", "query-secret", "text-secret", "other-secret", "session-secret", "quoted-secret", "hidden-secret", "embedded-secret"]:
            self.assertNotIn(secret, serialized)
        evidence = response(body="DB_PASSWORD=body-secret", headers={"Set-Cookie":"Custom=cookie-secret"}).evidence()
        self.assertNotIn("body-secret", json.dumps(evidence))
        self.assertNotIn("cookie-secret", json.dumps(evidence))


class ValidatorTests(unittest.TestCase):
    def candidate(self, p): return Registry().plan([p], SafetyPolicy(TARGET))[0]

    def test_path_positive_signatures(self):
        fixtures = [("/.git/HEAD", "ref: refs/heads/main\n"), ("/.env", "DB_PASSWORD=fixture-secret\n"),
                    ("/phpinfo.php", "<html><title>phpinfo()</title>PHP Version 8.2</html>"),
                    ("/server-status", "Apache Server Status Server uptime: 42"),
                    ("/moodle/", "<title>Index of /moodle/</title><a href='a'>a</a>")]
        for path, body in fixtures:
            p = parent("Directory listing" if path == "/moodle/" else "Exposed diagnostic", url="http://127.0.0.1"+path)
            c = self.candidate(p)
            outcome = SensitivePath().evaluate(c, [response(body=body), response(404, "not found")])
            self.assertEqual(outcome.confirmation_status, "CONFIRMED")
            self.assertEqual(outcome.check_result, "FAIL")

    def test_path_not_found_and_auth(self):
        c = self.candidate(parent())
        for resp, expected in [(response(404), "NOT_FOUND"), (response(410), "NOT_FOUND"),
                               (response(403), "AUTH_DENIED"), (response(302, headers={"Location":"/login/index.php"}), "AUTH_DENIED"),
                               (response(body="<input name='password'>"), "AUTH_DENIED")]:
            outcome = SensitivePath().evaluate(c, [resp, response(404)])
            self.assertEqual(outcome.outcome, expected)
            self.assertEqual(outcome.confirmation_status, "NOT_CONFIRMED")

    def test_path_200_generic_and_soft404_inconclusive(self):
        c = self.candidate(parent())
        for first, control in [(response(body="<title>Home | Moodle</title>"), response(404)),
                               (response(body="ref: refs/heads/main"), response(body="ref: refs/heads/main")),
                               (response(500, "ref: refs/heads/main"), response(404)), (response(), response(404))]:
            self.assertEqual(SensitivePath().evaluate(c, [first, control]).outcome, "INCONCLUSIVE")

    def redirect_candidate(self):
        return self.candidate(parent("Open redirect", "HTTP Configuration", url=TARGET+"redirect.php", evidence={"active_context":
            {"url":TARGET+"redirect.php", "redirect_parameter":"returnurl", "read_only":True}}))

    def test_redirect_controlled_external(self):
        c = self.redirect_candidate()
        specs = OpenRedirect().requests(c)
        self.assertIn("branch1-validation.invalid", specs[1].url)
        destination = "https://branch1-validation.invalid/return/" + c.candidate_id
        result = OpenRedirect().evaluate(c, [response(url=specs[0].url), response(302, headers={"Location":destination}, url=specs[1].url)])
        self.assertEqual(result.confirmation_status, "CONFIRMED")

    def test_redirect_internal_negative_and_unrelated_external(self):
        c = self.redirect_candidate()
        for resp, expected in [(response(302, headers={"Location":"/moodle/login/index.php"}), "INTERNAL_OR_NO_REDIRECT"),
                               (response(200), "INTERNAL_OR_NO_REDIRECT"), (response(302, headers={"Location":"https://sso.invalid/"}), "INCONCLUSIVE")]:
            result = OpenRedirect().evaluate(c, [response(), resp])
            self.assertEqual(result.outcome, expected)
            self.assertEqual(result.confirmation_status, "NOT_CONFIRMED")

    def test_transport_redirect_not_open_redirect(self):
        p = parent("HTTP to HTTPS redirection", "Transport Security")
        self.assertIsNone(OpenRedirect().propose(p))

    def test_linked_positive_keeps_version_parent_and_canonical_evidence(self):
        p = parent(confirmation="VERSION_BASED")
        original = copy.deepcopy(p.to_dict())
        ctx = Context(ROOT, output=ROOT/"outputs/fixture-active")
        ex, _, _ = executor([response(body="ref: refs/heads/main"), response(404)])
        summary = run_active(ctx, [p], ex.policy, executor=ex)
        self.assertEqual(original, p.to_dict())
        self.assertEqual(summary["active_evidence_count"], 1)
        linked = SecurityFinding.from_dict(ctx.artifacts["active_validation_findings.json"][0])
        self.assertEqual(linked.to_dict()["confirmation_status"], "CONFIRMED")
        self.assertEqual(linked.evidence["parent_evidence_id"], p.evidence_id)
        self.assertEqual(linked.evidence["parent_finding_id"], p.finding_id)
        self.assertEqual(linked.provenance.source_sha256, Document.generated(ctx.artifact_path("active_validation_evidence.json"),ctx.artifacts["active_validation_evidence.json"]).sha256)

    def test_incomplete_budget_does_not_start_check(self):
        ex, session, _ = executor([], 1)
        ctx = Context(ROOT)
        summary = run_active(ctx, [parent()], ex.policy, executor=ex)
        session.get.assert_not_called()
        self.assertEqual(summary["requests_used"], 0)
        self.assertEqual(ctx.artifacts["active_validation_results.json"][0]["outcome"], "BUDGET_EXHAUSTED")

    def test_timeout_linked_error_not_confirmation(self):
        ex, _, _ = executor([requests.Timeout("secret=fixture")])
        ctx = Context(ROOT, output=ROOT/"outputs/fixture-active")
        run_active(ctx, [parent()], ex.policy, executor=ex)
        result = ctx.artifacts["active_validation_results.json"][0]
        self.assertEqual(result["confirmation_status"], "NOT_TESTED")
        self.assertEqual(result["check_result"], "ERROR")

    def test_exported_active_transcript_hash_and_secret_redaction(self):
        ex, _, _ = executor([response(body="ref: refs/heads/main", headers={"Set-Cookie":"Private=never-export"}), response(404)])
        p = parent()
        with tempfile.TemporaryDirectory() as directory:
            ctx = Context(Path(directory), output=Path(directory)/"outputs/active")
            summary = run_active(ctx, [p], ex.policy, executor=ex)
            write_report(ctx, [p], {"fixture":1}, {p.evidence_id:"fixture"}, active_summary=summary)
            transcript = (ctx.output/"active_validation_evidence.json").read_bytes()
            linked = json.loads((ctx.output/"active_validation_findings.json").read_text())[0]
            self.assertEqual(linked["provenance"]["source_sha256"], hashlib.sha256(transcript).hexdigest())
            self.assertNotIn(b"never-export", transcript)

    def test_negative_keeps_confirmed_parent(self):
        p = parent(confirmation="CONFIRMED")
        original = p.to_dict()
        ex, _, _ = executor([response(404), response(404)])
        ctx = Context(ROOT, output=ROOT/"outputs/fixture-active")
        run_active(ctx, [p], ex.policy, executor=ex)
        self.assertEqual(p.to_dict(), original)
        self.assertEqual(ctx.artifacts["active_validation_results.json"][0]["confirmation_status"], "NOT_CONFIRMED")

    def test_unsupported_never_executes(self):
        ex, session, _ = executor([])
        p = parent("SQL injection", "Vulnerability Intelligence", confirmation="VERSION_BASED")
        ctx = Context(ROOT)
        run_active(ctx, [p], ex.policy, executor=ex)
        session.get.assert_not_called()
        self.assertEqual(ctx.artifacts["active_validation_results.json"][0]["confirmation_status"], "NOT_TESTED")
        self.assertEqual(ctx.artifacts["active_validation_findings.json"], [])


if __name__ == "__main__":
    unittest.main()
