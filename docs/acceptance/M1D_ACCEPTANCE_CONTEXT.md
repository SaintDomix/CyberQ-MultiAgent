# Milestone 1D acceptance context — authorized Moodle lab

Target: `http://192.168.226.132/moodle/`. External acceptance worker: Kali
`192.168.226.129`. This review used local source and saved evidence only: no
HTTP requests, PHP application bootstrap, database queries or active validation.
No validators were changed. The installed `version.php` matches saved evidence:
Moodle 4.5.11+ (Build: 20260519), version 2024100711.03, branch 405.

The exact per-candidate record, evidence IDs, prerequisites, supported interfaces,
capabilities, interpretation and skip reasons are in `m1d_lab_acceptance_matrix.json`.
`m1d_lab_source_manifest.json` records hashes of the 41 relevant inputs. Source
references are installed-source file/line locations, not claims of upstream
advisory verification. The packaged catalog lacks affected function/parameter and
upstream patch provenance. Do not identify an affected function solely by title.

Configuration is from `evidence/live_smoke/internal_evidence.json`. Direct read
of `/var/www/html/moodle/config.php` was denied; no elevation or secret-bearing
configuration export was performed. No current database configuration was queried.
Saved settings must be rechecked through separately authorized, sanitized
configuration collection before final lab acceptance. File/source existence does
not prove an enabled runtime feature or a current role capability assignment.

## Readiness

| Validator | Parent finding | Readiness | Safe approach / missing prerequisite |
|---|---|---|---|
| SQLi | ADV-MSA-26-0031 | Blocked | No source-to-advisory affected function/input binding. Saved REST services disabled. Related AJAX requires POST JSON/session/sesskey, outside this engine's GET interface. |
| XSS | ADV-MSA-26-0020 | Blocked | Feedback import processes uploaded XML and adds/deletes activity items; no read-only affected input. |
| XSS | ADV-MSA-26-0021 | Blocked | Grade idnumber is a POST edit/persistent form field; current gate blocks edit paths. |
| Account enumeration | AUTH-005 (saved live smoke) | Blocked | Recovery submission creates reset records/sends mail. GET only displays form. No supported lookup-only endpoint or verified test identifiers. |
| Access | ADV-MSA-26-0029 | Blocked | Fragment callback needs POST JSON, sesskey, report/context IDs and reviewed role policy; no GET mapping. |
| Access | Historical student /admin/ review | Dismissed | Preserve FALSE_POSITIVE; never retarget or reactivate. |
| Access | ROLE-student-security_report (saved live smoke) | Blocked | Source-supported read-only report; bodies 129581/159681 bytes exceed 65536-byte cap. Fresh dedicated sessions/capability policy needed. |
| Session | COOKIE-MoodleSession-SECURE | Ready for bounded anonymous observation | GET login page twice, inspect effective Secure/transport; no secret inputs. |
| Session | COOKIE-MoodleSession-HTTPONLY | Ready for bounded anonymous observation | GET login page twice, inspect effective HttpOnly; no secret inputs. |
| Session | COOKIE-MoodleSession-SAMESITE | Ready for bounded anonymous observation | GET login page twice, inspect effective SameSite; no secret inputs. |
| Session | SESSION-001 | Skip distinct predicate | Parent concerns login cache headers; current validator checks cookie attributes. Do not substitute predicates. |
| SSRF context | ADV-MSA-26-0030 | Ready for contextual assessment | Saved enabled URL repository plus installed fetch code. No requests or fetch target. Current accessibility/advisory binding unverified. |

Readiness is an acceptance-planning state, not a canonical confirmation status.
The template keeps blocked contexts incomplete or `read_only=false`; these cannot
execute merely because an environment variable or session is later populated.

## Exact source-supported interfaces

All paths below are relative to the authorized `/moodle/` base.

- SQLi: **no affected endpoint/parameter established**. The related registered read
  function `core_question_get_random_question_summaries` is implemented in
  `question/classes/external.php:132-214`: `categoryid`, `includesubcategories`,
  `tagids[]`, `contextid`, `limit`, `offset` are typed integers/booleans. It checks
  `moodle/question:viewall`. Its AJAX registration does not identify it as the
  advisory's vulnerable function. `/lib/ajax/service.php` reads POST JSON with
  `methodname`/`args`; logged-in functions require sesskey. `/webservice/rest/server.php`
  dispatches `wsfunction` with token authentication (`wstoken`); saved
  enablewebservices=0/webserviceprotocols=null prevents REST. **Disabled REST does
  not rule out AJAX.** Do not map numeric validation failures to SQLi or invent IDs.
- Feedback XSS: `/mod/feedback/import.php`, `id` is a course-module ID;
  `choosefile` is the uploaded-file/filepicker input. XML ITEM/@TYPE contributes to
  `type (...) not found` error output. `mod/feedback:edititems` and a course session
  are required. Import can delete/add items; no GET quote/marker test is authorized.
  No actual feedback activity ID was established.
- Grade XSS: `/grade/edit/tree/item.php`, `courseid` and grade-item `id` select
  resources; form `idnumber` uses PARAM_RAW. `moodle/grade:manage` is required.
  POST form processing writes grade items. No course/item IDs or benign affected
  value were established. Do not use `1` as a guessed resource identifier.
- Enumeration: `/login/forgot_password.php` accepts POST form `username` or
  `email`. Processing can generate/update reset tokens and send mail even when
  `protectusernames=1`. `/login/index.php?username=...` is form prefill, not a safe
  account-existence check; GET requests cannot be substituted for recovery POST.
- Report-builder access: `/lib/ajax/service.php`, JSON `methodname=core_get_fragment`,
  `component=core_reportbuilder`, `callback=filters_form`/`audience_form`, `contextid`,
  and named args `reportid`, `parameters`/`classname`. Installed form code checks
  report-view/report-edit policy. No report/context ID, reviewed class or GET
  interface is established. Do not instantiate arbitrary audience classes.
- Separate role-content check: `/report/security/index.php`, GET with no input
  parameter; capability `report/security:view` in system context. Saved profile
  links identify student user ID 3 and administrator user ID 2; administrator
  report contains `id="securityreporttable"`. These are non-secret snapshot
  markers, not proof of fresh session identity or current capability assignments.
  Saved pages exceed the engine's cap; do not weaken the cap in this task.
- Session: `/login/index.php`, GET with **no parameter**; cookie name
  `MoodleSession` is supported by historical emitted-cookie evidence. Saved
  anonymous login response is 23304 bytes, below the 65536-byte cap. Both requests
  must emit the cookie consistently; absence means NOT_TESTED. PHP can omit a new
  Set-Cookie for existing authenticated sessions, so anonymous observation must not
  be relabeled as authenticated rotation/invalidation acceptance.
- SSRF context: `/repository/repository_ajax.php` routes authenticated POST actions
  using `repo_id`, `ctx_id`, `action` and sesskey; repository_url accepts `file`.
  `action=list` can invoke downloader HEAD/GET work. `repository/url:view` and
  repository/context permissions apply. Plugin enabled=true is saved evidence;
  actual repository instance/context and current accessibility are not verified.
  Template assessment sends **zero requests** and provides no fetch URL. Saved
  blocked-host/port settings are context, not verified runtime enforcement.

Source defaults explain why `cookiesecure=1` is not unconditional Secure:
`lib/sessionlib.php:93` requires HTTPS or sslproxy. On the saved HTTP target with
sslproxy=null, the effective flag may be false. HttpOnly defaults to 1 in source;
SameSite is Lax for non-mobile clients. Defaults/configuration are not observations.
The template deliberately does not invent configured HttpOnly/SameSite estimates
from saved null values or an expected effective Secure flag from conditional logic.

## Non-secret template and ephemeral inputs

`m1d_lab_runtime_context.template.json` is valid for `RuntimeContext.from_env`.
Mappings use stable parent finding IDs; the matrix additionally records exact
observation/evidence IDs. Three anonymous session candidates and one SSRF
context candidate have sufficient context. All blocked families remain missing
context and cannot execute; the historical dismissed candidate remains excluded.

`AUTH-005` and `ROLE-student-security_report` are saved-live-smoke parents and are
not in the 40-record offline baseline. Their reserved mappings are documented,
but offline replay does not create missing parents. These mappings currently
remain blocked even if supplied to a later fresh posture run.

No password, cookie, token, account username/email or secret placeholder value is
stored in this template. Optional future role sessions reference environment names
only:

- `B1_ACTIVE_CONTEXT`: JSON loaded from the non-secret template.
- `B1_STUDENT_COOKIE`: optional full Cookie header for the existing dedicated
  student test identity; never persisted or printed.
- `B1_ADMIN_COOKIE`: optional full Cookie header for the existing dedicated
  administrator test identity; never persisted or printed.

No session secrets are needed for the ready anonymous-cookie/context subset.
No web-service token, password, sesskey or recovery-token input is requested:
their corresponding interfaces remain blocked. Obtain future role sessions
through an independently reviewed authorized login workflow; use private input,
not literal credentials in shell commands/history. Do not create credential files.

## Proposed commands — not executed as active validation

Load the non-secret template and plan locally (no HTTP/client construction):

```bash
export B1_ACTIVE_CONTEXT="$(cat docs/acceptance/m1d_lab_runtime_context.template.json)"
.venv/bin/python -B scripts/run_branch1.py --mode offline --plan-active \
  --target http://192.168.226.132/moodle/ --active-context-env B1_ACTIVE_CONTEXT \
  --out outputs/branch1_m1d_acceptance_context_plan
```

Proposed later authorized lab execution from Kali, after reviewed configuration
refresh and explicit acceptance authorization, using a new empty output directory:

```bash
.venv/bin/python -B scripts/run_branch1.py --mode offline --plan-active \
  --active --authorized --target http://192.168.226.132/moodle/ \
  --active-context-env B1_ACTIVE_CONTEXT --active-budget 20 \
  --active-timeout 5 --active-rate 0.25 \
  --out outputs/branch1_m1d_acceptance_lab_run01
```

The existing CLI also includes five historical sensitive-path candidates, which
remain unchanged. This later command can make up to ten path requests and six
anonymous cookie requests; SSRF context uses zero. It cannot execute the blocked
SQLi/XSS/enumeration/access mappings. Do not present it as six-family runtime
acceptance. For a focused subset, use the existing Registry/run_active Python API
with selected canonical parents/validators; no separate validation pipeline is
needed. Session failures/negative observations do not imply overall safety.

Offline context review: 40 baseline candidates, APPLICABLE 9 (5 path, 3 anonymous
session, 1 SSRF contextual), MISSING_CONTEXT 5, NOT_APPLICABLE 26. All unexecuted
results remain NOT_TESTED. The source manifest and template can be validated with
network construction patched to fail, without touching Moodle or its configuration.
