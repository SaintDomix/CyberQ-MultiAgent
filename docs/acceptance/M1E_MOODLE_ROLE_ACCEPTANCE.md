# Milestone 1E Moodle authenticated role acceptance

Prepared only: no server, login or active HTTP request was executed during
implementation. Runtime acceptance is a later experiment, not a completed result.
Moodle-specific login stays in `branch1/adapters/moodle_sessions.py`; generic
validators have no Moodle credentials, login forms or benchmark shortcuts.

## Reviewed target and evidence

GET `http://192.168.226.132/moodle/report/security/index.php`, no query parameter.
Installed report/security/index.php calls admin_externalpage_setup('reportsecurity'),
renders a security check table and records a normal report-view audit event.
report/security/settings.php requires `report/security:view` in system context;
report/security/db/access.php defines a read capability (manager archetype allowed;
lab site administrator allowed). Student is expected to be denied under the saved
role configuration. This read-only report performs no grade/course/configuration
changes or privileged actions; normal session access times and audit events remain
observable side effects, as for other authenticated GET observations.

Historical evidence: `evidence/baseline/branch1/role_v3_student/` and
`role_v3_admin/` security_report HTML/CSV. Student receives `Access denied` (404,
129581 bytes); administrator receives a security-report table (200,159681 bytes).
The selected unchanged canonical parent is ROLE-student-security_report from
outputs/branch1_unified_live_smoke/findings.json. It is not the dismissed /admin/
parent, not a report-builder advisory, and not a claim of a new vulnerability.
Fresh identity/content checks must reproduce the expectations; historical roles
and capabilities are not proof of current assignments.

Exact markers supported by saved snapshots:

- Student own-profile URL: `http://192.168.226.132/moodle/user/profile.php?id=3`
- Administrator own-profile URL: `http://192.168.226.132/moodle/user/profile.php?id=2`
- Privileged report content: `id="securityreporttable"` (also rendered by installed
  lib/classes/check/table.php). Marker is actual table content, not merely a link.
- Barriers: explicit access denied/permission denied text, HTTP 401/403, or
  login/auth redirects. A bare 404 or 200 never proves the expected role policy.

The active engine keeps redirects disabled. Repeated student barriers must have
an independently verified admin comparator with its own identity and report
content. If the admin comparator is missing/wrong/denied/generic, the comparison
is NOT_TESTED rather than a successful acceptance. Unexpected restricted-role
privileged content remains LIKELY, not confirmed function execution.

## Explicit size bound

The default 64 KiB cap was insufficient for these existing role pages and the
239253-byte admin identity dashboard. This acceptance explicitly selects 262144
bytes (256 KiB), now the maximum allowed cap; the generic engine default remains
65536. Full responses over the bound are rejected, never truncated and called
negative. Timeout=5s and request rate=0.25/s remain enforced. Fresh larger pages,
redirects or different identity markers cause acceptance failure, not an automatic
cap increase or endpoint switch. This is a documented bounded transport setting,
not a changed detection or scoring method.

## Ephemeral bootstrap

`run_branch1_moodle_acceptance.py` uses the existing runtime mapping/session
interface in one process. It never prints cookies or requires a cookie handoff
file. The adapter performs one credential POST per role, without retries:

1. GET local login/index.php, parse the login form and logintoken in memory.
2. Require POST form action to be the exact authorized login URL.
3. Submit username/password/logintoken once, with environment proxy/netrc disabled.
4. Follow up to four same-origin/base-path redirects using GET; never replay POST
   credentials across redirects, never follow external login/SSO or mutating paths.
5. Independently GET /my/ and require the exact expected own-profile marker and
   absence of the other role's marker. A generic HTTP 200 is insufficient.
6. Require one unexpired host-only MoodleSession cookie with appropriate path.
   Student/admin sessions and accounts must be distinct. Separate cookie jars are
   used, then closed/cleared. Publish cookie values only in this process's scoped
   B1_STUDENT_COOKIE/B1_ADMIN_COOKIE env entries; restore/clear them afterward.
7. Run four role-comparison requests through the existing Active Executor using
   those ephemeral references. Export only non-secret bootstrap counts/verified
   role metadata and the normal sanitized/hash-only active evidence.

Total budget=20 covers bootstrap plus comparison, with four requests reserved for
the comparison. The same scope/response/time/rate bounds apply to bootstrap; a
shared rate checkpoint preserves spacing into active execution. Login failure,
unconfirmed account, required password changes/MFA/SSO, missing markers, swapped
accounts or identical sessions abort without password retries. These restrictions
fit the lab's manually authenticated test accounts; do not loosen them silently.

Inputs (never put literal credential values in command arguments, history or files):

- B1_ACTIVE_CONTEXT: non-secret JSON from m1e_moodle_role_context.template.json.
- B1_STUDENT_USERNAME / B1_STUDENT_PASSWORD
- B1_ADMIN_USERNAME / B1_ADMIN_PASSWORD
- B1_STUDENT_COOKIE / B1_ADMIN_COOKIE: generated only inside the runner; do not
  populate manually or export their values to the terminal.

Use --interactive for hidden username/password prompts when credential environment
variables are absent. Environment credentials are optional; do not include them in
shared shell transcripts. Passwords, login tokens and raw response bodies are
never saved. No lifecycle/logout acceptance is forced: effective authenticated
Set-Cookie can be absent for existing sessions, and rotation/invalidation requires
a separately reviewed experiment. Dedicated sessions expire normally; no unrelated
session is invalidated by this runner.

## Proposed exact Kali commands (not executed)

Use the synchronized source-of-truth checkout on Kali; preserve outputs back to
Ubuntu afterward through the usual reviewed workflow. Do not edit legacy evidence.

```bash
export B1_ACTIVE_CONTEXT="$(cat docs/acceptance/m1e_moodle_role_context.template.json)"
.venv/bin/python -B scripts/run_branch1_moodle_acceptance.py \
  --target http://192.168.226.132/moodle/ --out outputs/branch1_m1e_roles_plan01
.venv/bin/python -B scripts/run_branch1_moodle_acceptance.py \
  --target http://192.168.226.132/moodle/ --active --authorized --interactive \
  --budget 20 --response-cap 262144 --out outputs/branch1_m1e_roles_run01
```

Planning creates no HTTP client and requires no credentials. Missing sessions
remain MISSING_CONTEXT/NOT_TESTED. Active commands require explicit authorization
and a new empty output directory. Exit 0 on a real run requires ROLE_DENIED /
PASS / NOT_CONFIRMED with a verified privileged comparator. Exit 1 is a bootstrap/
configuration failure; exit 2 is incomplete/unexpected active acceptance. Retain
all outputs; neither benchmark success nor this one role comparison demonstrates
overall Moodle security or confirms the unresolved SQLi/XSS advisories.
