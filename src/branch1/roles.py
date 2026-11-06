"""Offline consumption and cross-role comparison of explicit role evidence."""
import csv
import hashlib
import json
from pathlib import Path

from evidence_contracts import Provenance
from evidence_contracts.baseline import adapt_record
from evidence_contracts.models import record_digest
from .common import Document, boolean, finding

ADMIN_ENDPOINTS = {"admin_home", "environment", "security_report", "scheduled_tasks", "manage_users", "webservices_overview"}


def review_json(document):
    if not isinstance(document.payload, list):
        raise ValueError("Role reviews must be a list")
    return [adapt_record(raw, source="role_review_v3", provenance=Provenance(
        document.path, document.sha256, i, record_digest(raw), "role_review_v3"))
        for i, raw in enumerate(document.payload)]


def load_csv(path, project):
    data = Path(path).read_bytes()
    rows = list(csv.DictReader(data.decode("utf-8-sig").splitlines()))
    name = str(Path(path).resolve())
    if Path(name).is_relative_to(project):
        name = str(Path(name).relative_to(project))
    if not rows or len({r.get("role") for r in rows}) != 1:
        raise ValueError("Each role CSV must contain observations for exactly one role")
    if len({r.get("endpoint") for r in rows}) != len(rows):
        raise ValueError("Duplicate endpoints in role CSV")
    return {"source_file": name, "source_sha256": hashlib.sha256(data).hexdigest(), "rows": rows}


def compare(inputs, artifact_path):
    by_role = {}
    for item in inputs:
        role = item["rows"][0]["role"]
        if role in by_role:
            raise ValueError("Duplicate role evidence")
        by_role[role] = {r["endpoint"]: r for r in item["rows"]}
    reviews = []
    for role in sorted(set(by_role) - {"anonymous", "admin", "administrator"}):
        for endpoint in sorted(ADMIN_ENDPOINTS):
            row = by_role[role].get(endpoint)
            if row is None:
                continue
            anon = by_role.get("anonymous", {}).get(endpoint)
            admin = by_role.get("admin", by_role.get("administrator", {})).get(endpoint)
            blocked = boolean(row.get("login_required")) is True or boolean(row.get("permission_denied")) is True or "login/index.php" in row.get("final_url", "")
            result, confirmation = "NOT_TESTED", "NOT_TESTED"
            explanation = "Cross-role comparison is incomplete or response status is inconclusive."
            comparisons = {}
            if boolean(row.get("authenticated")) is not True:
                explanation = "The supplied non-admin observation does not establish successful authentication."
            elif blocked:
                result, confirmation = "PASS", "CONFIRMED"
                explanation = "Supplied role evidence records a login or permission barrier."
            elif row.get("status") in {"404", "ERROR"}:
                explanation = "Missing/error response does not establish authorization or endpoint absence."
            elif anon and admin and anon.get("status") not in {"ERROR", "404"} and admin.get("status") not in {"ERROR", "404"} and boolean(admin.get("authenticated")) is True and boolean(admin.get("login_required")) is False and boolean(admin.get("permission_denied")) is False:
                parsed = [json.loads(r.get("privileged_links") or "[]") for r in [row, anon, admin]]
                if any(not isinstance(p, list) or any(not isinstance(v, str) for v in p) for p in parsed):
                    raise ValueError("privileged_links must be JSON lists of strings")
                role_links, anon_links, admin_links = map(set, parsed)
                unique, overlap = role_links-anon_links, (role_links-anon_links)&admin_links
                same = bool(row.get("body_sha256") and row["body_sha256"] == admin.get("body_sha256"))
                comparisons = {"unique_vs_anonymous": sorted(unique), "overlap_with_admin": sorted(overlap), "same_as_admin": same}
                if not unique:
                    result, confirmation = "DISMISSED", "FALSE_POSITIVE"
                    explanation = "No privileged-link evidence beyond the anonymous response; candidate dismissed."
                else:
                    result, confirmation = "PARTIAL", "NOT_CONFIRMED"
                    explanation = "Privileged-looking links require capability/content review; no unauthorized function confirmed."
            reviews.append({"role": role, "endpoint": endpoint, "observation": row,
                            "comparisons": comparisons, "check_result": result,
                            "confirmation_status": confirmation, "explanation": explanation})
    payload = {"inputs": inputs, "reviews": reviews}
    document = Document.generated(artifact_path, payload)
    results = [finding(document, "roles", f"ROLE-{r['role']}-{r['endpoint']}", "Access Control", "Cross-role content comparison",
                       r["check_result"], r["confirmation_status"], None, observed=r["observation"],
                       explanation=r["explanation"], evidence=r, asset=r["observation"].get("final_url"), index=i)
               for i, r in enumerate(reviews)]
    return results, payload
