"""Configuration observations from explicitly supplied collector JSON."""
from .common import boolean, finding


def assess(document, webserver_uid=None, extra_rules=()):
    ev = document.payload
    if not isinstance(ev, dict):
        raise ValueError("Internal evidence must be an object")
    settings, fs, runtime = (ev.get(k, {}) for k in ("settings", "filesystem", "runtime"))
    results = []

    def emit(fid, title, value, result, severity="MEDIUM", category="Runtime Hardening", reason=None, evidence=None):
        known = result is not None
        recommendations = {
            "FS-001": "Make config.php non-writable by the web-server account; verify collector identity.",
            "FS-002": "Keep application code read-only to the web-server account.",
            "FS-003": "Keep dataroot outside the application root and verify web-server denial.",
            "CFG-001": "Disable Moodle debug display in production.",
            "PHP-001": "Verify web-SAPI display_errors separately; do not infer it from CLI configuration.",
            "CFG-003": "Define required executable paths and lock them from the admin UI where feasible.",
            "SESSION-INT-001": "Validate HTTPS/proxy configuration and explicit Secure-cookie enforcement.",
            "SESSION-INT-002": "Enable HttpOnly for session cookies and verify emitted attributes.",
            "AUTH-INT-001": "Disable no-authentication unless a documented isolated need exists.",
            "AUTH-INT-002": "Enable an institutional local-password policy.",
            "AUTH-INT-003": "Verify the complete lockout/rate-limiting control set, including external identity providers.",
            "AUTH-INT-004": "Review registration approval and anti-abuse controls.",
            "PRIV-001": "Require authentication for profiles unless public profiles are intended.",
            "PRIV-002": "Disable search-engine guest access unless deliberate.",
            "CFG-002": "Disable EMBED/OBJECT content unless required.",
            "CFG-004": "Disable framing or constrain allowed ancestors.",
            "SSRF-DEF-001": "Review blocked hosts and network egress controls; no SSRF test performed.",
            "SSRF-DEF-002": "Restrict server-side fetch ports where compatible.",
            "PLUGIN-001": "Review and complete pending component upgrades.",
            "PLUGIN-002": "Review plugin provenance, maintenance and advisories.",
        }
        results.append(finding(document, "internal", fid, category, title,
                               result if known else "NOT_TESTED",
                               "NOT_APPLICABLE" if result == "NOT_APPLICABLE" else "CONFIRMED" if known else "NOT_TESTED",
                               ("INFO" if result in {"PASS", "NOT_APPLICABLE"} else severity) if known else None,
                               value, explanation=reason or ("Configuration value collected." if known else "Required evidence is missing or uninterpretable."),
                               recommendation=recommendations.get(fid), evidence=evidence, index=len(results)))

    for fid, key, title, severity in [
        ("FS-001", "config_writable_by_collector_user", "config.php writable by collector account", "CRITICAL"),
        ("FS-002", "dirroot_writable_by_collector_user", "Moodle code root writable by collector account", "HIGH"),
    ]:
        value = boolean(fs.get(key))
        context = {"filesystem": fs, "collector_euid": runtime.get("collector_euid"), "expected_webserver_uid": webserver_uid}
        result = None if value is None else "FAIL" if value else "PASS"
        if webserver_uid is not None and runtime.get("collector_euid") != webserver_uid:
            result = None
        emit(fid, title, fs.get(key), result, severity, "Server-side Configuration",
             "Writability applies to the collector account; web-server equivalence requires explicit matching UID." if result else None, context)
    placement = boolean(fs.get("dataroot_inside_dirroot"))
    emit("FS-003", "Dataroot inside application root", fs.get("dataroot_inside_dirroot"),
         None if placement is None else "FAIL" if placement else "PASS", "CRITICAL", "Server-side Configuration", evidence=fs)

    # Preserve useful auth/privacy/content/egress rules without treating null as false.
    rules = [
        ("AUTH-INT-002", "passwordpolicy", "Password policy enabled", False, "FAIL", "Authentication & Access", "MEDIUM"),
        ("PRIV-001", "forceloginforprofiles", "Login required for profiles", False, "PARTIAL", "Privacy & Exposure", "MEDIUM"),
        ("PRIV-002", "opentogoogle", "Open-to-Google mode", True, "FAIL", "Privacy & Exposure", "MEDIUM"),
        ("CFG-002", "allowobjectembed", "EMBED/OBJECT allowed", True, "FAIL", "Runtime Hardening", "MEDIUM"),
        ("CFG-003", "preventexecpath", "Executable paths locked from admin UI", False, "PARTIAL", "Runtime Hardening", "MEDIUM"),
        ("CFG-004", "allowframembedding", "Frame embedding allowed", True, "PARTIAL", "Runtime Hardening", "MEDIUM"),
    ]
    for fid, key, title, weak, status, category, severity in rules:
        value = boolean(settings.get(key))
        emit(fid, title, settings.get(key), None if value is None else status if value == weak else "PASS", severity, category)
    auth = ev.get("enabled_auth_plugins")
    emit("AUTH-INT-001", "No-authentication plugin enabled", auth,
         None if not isinstance(auth, list) or "__collector_error__" in auth else "FAIL" if "none" in auth else "PASS",
         "HIGH", "Authentication & Access")
    for fid, key, title, severity, category in [
        ("AUTH-INT-003", "lockoutthreshold", "Login lockout threshold", "MEDIUM", "Authentication & Access"),
        ("AUTH-INT-004", "registerauth", "Self-registration configured", "MEDIUM", "Authentication & Access"),
        ("SSRF-DEF-001", "curlsecurityblockedhosts", "cURL blocked-hosts list", "MEDIUM", "Network Egress / SSRF Defense"),
        ("SSRF-DEF-002", "curlsecurityallowedport", "cURL allowed-ports list", "LOW", "Network Egress / SSRF Defense"),
    ]:
        value = settings.get(key)
        weak = bool(value) if key == "registerauth" else value in ("", "0", 0)
        emit(fid, title, value, None if value is None else "PARTIAL" if weak else "PASS", severity, category)

    # Restored checks distinguish Moodle configuration from CLI-only PHP context.
    debugdisplay = boolean(settings.get("debugdisplay"))
    emit("CFG-001", "Moodle debug display", {"debug": settings.get("debug"), "debugdisplay": settings.get("debugdisplay")},
         None if debugdisplay is None else "FAIL" if debugdisplay else "PASS",
         reason="debug alone does not prove browser disclosure; debugdisplay controls Moodle display.")
    php_display = boolean(runtime.get("display_errors"))
    if str(runtime.get("display_errors", "")).lower() in {"stderr", "stdout"}:
        php_display = True
    emit("PHP-001", "PHP display_errors in collector runtime", runtime,
         None if php_display is None else "PARTIAL" if php_display else "PASS",
         reason="This is collector runtime configuration, not proof of web-SAPI behavior or remote disclosure.")
    secure = boolean(settings.get("cookiesecure"))
    wwwroot = settings.get("wwwroot")
    secure_result = None
    if isinstance(wwwroot, str) and wwwroot.startswith("http://"):
        secure_result = "NOT_APPLICABLE"
    elif isinstance(wwwroot, str) and wwwroot.startswith("https://") and secure is not None:
        secure_result = "PASS" if secure else "FAIL"
    emit("SESSION-INT-001", "Internal Secure-cookie configuration", {"wwwroot": wwwroot, "cookiesecure": settings.get("cookiesecure"), "sslproxy": settings.get("sslproxy")}, secure_result, category="Authentication & Session",
         reason="HTTP transport must be addressed first; on HTTPS this checks explicit configuration, not actual Set-Cookie behavior.")
    httponly = boolean(settings.get("cookiehttponly"))
    emit("SESSION-INT-002", "Internal HttpOnly configuration", settings.get("cookiehttponly"),
         None if httponly is None else "PASS" if httponly else "FAIL", category="Authentication & Session")

    plugins = ev.get("plugins")
    if isinstance(plugins, list):
        for fid, title, selected, severity in [
            ("PLUGIN-001", "Plugin disk/database version mismatch", [p for p in plugins if p.get("versiondisk") is not None and p.get("versiondb") is not None and str(p["versiondisk"]) != str(p["versiondb"])], "MEDIUM"),
            ("PLUGIN-002", "Additional/non-standard plugins present", [p for p in plugins if p.get("standard") is False], "INFO"),
        ]:
            if selected:
                emit(fid, title, selected, "PARTIAL", severity, "Component Inventory")
    for rule in extra_rules:
        results.extend(rule(document))
    return results
