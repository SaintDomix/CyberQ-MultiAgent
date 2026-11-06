"""Production wrapper around locally ported external posture rules."""
import requests

from .client import Client, redact_cookie
from .common import Document, finding
from .external_rules.cookies import cookie_findings
from .external_rules.generic_rules import GenericRules
from .external_rules.moodle_rules import MoodleRules
from .external_rules.tls import run_tls


def assess(target, artifact_path, timeout=8, client=None, extra_rules=()):
    client = client or Client(target, timeout)
    observations, errors = [], []
    try:
        base = client.get(target)
        observations.extend(run_tls(target, timeout))
        generic = GenericRules(client, target)
        observations.extend(generic.transport_and_headers(base))
        observations.extend(cookie_findings(base))
        observations.extend(generic.cors_methods_exposure())
        matrix = generic.endpoint_matrix()
        observations.append(generic.endpoint_header_finding(matrix))
        moodle, components = MoodleRules(client, target).run()
        observations.extend(moodle)
        for rule in extra_rules:
            observations.extend(rule(client, target))
    except requests.RequestException as exc:
        errors.append(str(exc))
    rows = [o.to_dict() for o in observations]
    for row in rows:
        # Only cookie values are removed; individual attribute checks remain intact.
        if row["finding_id"].startswith("COOKIE-"):
            row["evidence"] = redact_cookie(row["evidence"])
    payload = {"target": target, "observations": rows, "requests": client.transcript,
               "errors": errors, "endpoint_matrix": locals().get("matrix"),
               "components": locals().get("components")}
    document = Document.generated(artifact_path, payload)
    results = []
    for i, raw in enumerate(rows):
        status, tag = raw["status"], raw["confidence"]
        confirmation = "NOT_APPLICABLE" if status == "NOT_APPLICABLE" else "NOT_TESTED" if status in {"ERROR","NOT_TESTED"} else "NOT_CONFIRMED" if tag == "HEURISTIC" else tag
        results.append(finding(document, "external", raw["finding_id"], raw["category"], raw["indicator"],
                               status, confirmation, raw["severity"], raw["observed"], raw["expected"],
                               raw["reason"], raw["recommendation"], evidence={"observation": raw, "request_transcript": document.path},
                               asset=target, index=i))
    for error in errors:
        results.append(finding(document, "external", "EXTERNAL-ERROR", "Collection", "Incomplete external assessment",
                               "ERROR", "NOT_TESTED", None, explanation=error, index=len(results)))
    return results, payload
