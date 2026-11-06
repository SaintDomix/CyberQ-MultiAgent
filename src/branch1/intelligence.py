"""Pinned advisory/version analysis; matching never establishes exploitation."""
from decimal import Decimal, InvalidOperation
from .common import boolean, finding


def base_version(value):
    try:
        number = Decimal(str(value))
        return int(number) if number.is_finite() and number > 0 else None
    except (InvalidOperation, ValueError, TypeError):
        return None


def assess(document, catalog, patch_baseline=None):
    ev = document.payload
    core, settings = ev.get("core", {}), ev.get("settings", {})
    version, branch = base_version(core.get("version")), str(core.get("branch") or "")
    results = [finding(document, "intelligence", "CORE-001", "Patch & Vulnerability Intelligence",
                       "Installed Moodle core", "PASS" if version is not None else "NOT_TESTED",
                       "CONFIRMED" if version is not None else "NOT_TESTED", "INFO" if version is not None else None,
                       observed=core, explanation="Core version from supplied collector evidence.")]
    if version is None or not branch:
        return results
    if patch_baseline is not None:
        baseline = base_version(patch_baseline)
        if baseline is None:
            raise ValueError("Invalid explicit patch baseline")
        results.append(finding(document, "intelligence", "PATCH-001", "Patch & Vulnerability Intelligence",
                               "Explicit Moodle patch baseline", "FAIL" if version < baseline else "PASS",
                               "VERSION_BASED", "HIGH" if version < baseline else "INFO",
                               observed={"installed": version, "branch": branch}, expected=baseline,
                               explanation="Comparison to operator-supplied baseline, not a claim about the current latest release.", index=len(results)))
    records = catalog.payload
    if not isinstance(records, list):
        raise ValueError("Advisories must be a list")
    for index, advisory in enumerate(records):
        if str(advisory["branch"]) != branch:
            continue
        upper = base_version(advisory["affected_max"])
        lower = base_version(advisory.get("affected_min"))
        if upper is None or ("affected_min" in advisory and lower is None):
            raise ValueError("Invalid advisory affected range")
        if version > upper or (lower is not None and version < lower):
            continue
        webservices = boolean(settings.get("enablewebservices"))
        context = "Exposure not established by a version match."
        if advisory.get("surface") == "webservice":
            context = ("Web services disabled; direct exposure reduced, version-based condition retained."
                       if webservices is False else "Web services enabled; exposed functions/tokens not established."
                       if webservices is True else "Web-service configuration unknown.")
        evidence = {"advisory": advisory, "catalog_file": catalog.path, "catalog_sha256": catalog.sha256,
                    "catalog_record_index": index, "core": core, "context": context,
                    "enablewebservices": settings.get("enablewebservices")}
        results.append(finding(document, "intelligence", "ADV-"+advisory["id"],
                               "Patch & Vulnerability Intelligence", advisory["title"], "FAIL", "VERSION_BASED",
                               "HIGH" if advisory["risk"] == "Serious" else "LOW",
                               observed={"installed": version, "branch": branch},
                               expected={"fixed_release": advisory["fixed_release"]},
                               explanation="Installed build matches the supplied affected range; exploitability is not confirmed.",
                               recommendation=f"Review upgrade to {advisory['fixed_release']} or later in branch {branch}.",
                               evidence=evidence, index=len(results)))
    return results
