# Dynamic operational posture

Historical accepted Branch 1 is the immutable **RESEARCH BASELINE**. The original
40 findings/results and research CQI remain unchanged in ACCEPTED_REPLAY.
Operational check catalogs may reuse check IDs/category/title, never old results,
severity or confirmation as fresh evidence.

## Execution and snapshots

`POST /api/posture/assessments` creates a unique assessment, executes real native
rules, optionally runs the passive provider, normalizes source records, takes
reviewed-control maxima, and writes a new immutable snapshot under
`runtime/posture/posture-<UTC>-<unique>/`. Existing snapshots are never overwritten.
GET requests never execute scans. Native/ZAP states are independent:
QUEUED/RUNNING/COMPLETE/FAILED/UNAVAILABLE/SKIPPED. Overall status may be PARTIAL.
Jobs interrupted before a complete manifest are reported INTERRUPTED and never
selected as current successful snapshots. Corrupt snapshots fail visibly.

New snapshots (manifest 1.1): request.json, native.json, zap.json,
active_validation.json, snapshot.json, artifact_manifest.json. Old 1.0 snapshots
remain readable and unchanged.
Raw-provider files contain sanitized observations only. Every final file/range
has a hash; the manifest excludes itself. Current output is operational evidence,
not automatically accepted dissertation research evidence.

### Bounded operational HTTP timeouts

Native collection and the ZAP proxy use a 3-second connect limit and an
8-second read limit, replacing the previous 3-second connect/read pair. ZAP
control/API calls use the same limits, replacing their previous 3-second scalar
timeout. Each call uses Requests' supported urllib3 `Timeout` object with a
shared initial connect/read budget of at most 8 seconds, capped by the remaining
provider assessment budget. Connection time reduces the available initial read
time. Monotonic checks at headers, body chunks and completion reject responses
arriving after the request or assessment deadline, including empty responses.

Requests read timeouts bound socket inactivity; they are not a hard real-time
process cancellation mechanism. Streaming checks also bound accepted elapsed
time, but a blocking read can return after a deadline before the check rejects
it. No late result is accepted and no further request is sent after expiry.
There are no transport retries or new sleeps. ZAP retains its 60-second assessment budget and 20-request maximum. Native now
uses the source-derived complete-plan budget documented below. Both preserve
response-size caps; the ZAP availability probe is inside its assessment budget. Passive queue
polling remains bounded by that same deadline.

Provider errors and request transcripts use fixed sanitized reason codes:
`CONNECT_TIMEOUT`, `READ_TIMEOUT`, `HTTP_ERROR`, `TARGET_UNREACHABLE`,
`ZAP_API_UNAVAILABLE`, `ZAP_PROXY_FAILURE`, `PASSIVE_QUEUE_TIMEOUT` and
`SCOPE_INTEGRITY_FAILURE`. Budget, response-size and malformed-protocol failures
also have explicit codes. ZAP `cause_code` distinguishes the underlying API or
proxy transport failure. Native `provenance.failure_codes` retains individual
request failures even when native rules return partial check coverage. HTTP
error statuses remain usable check evidence where the unchanged native rules
expect them; an unavailable base page still fails collection. Raw exception
messages, response bodies, cookies and API keys are never exported as errors.
Historical findings are never substituted on failure. Scope, redirect, mode,
canonical mapping and scoring policies are unchanged.

The default native provider now reuses the accepted `branch1.external.assess`
(GenericRules, cookies, TLS and MoodleRules), `branch1.internal.assess` and
`branch1.intelligence.assess`. No frozen Branch1 implementation is edited.
Native probes use a literal list of the original module endpoints on the exact
authorized host, including its original read-only host-root exposure probes.
GET, OPTIONS and the existing credential-free TRACE check are supported for
native checks; this does not expand ZAP's five-page GET-only policy. No crawler,
form submission, mutation action, arbitrary URL or off-origin redirect is allowed.
The installer GET requires an existing local config.php; its source-backed
`admin/index.php?lang=en` redirect is explicitly reviewed. Anonymous security
report requests encounter Moodle's admin authentication gate; the native client
does not inherit operator/browser authenticated cookies.

OPTIONS/TRACE and the Moodle module are collected first. The accepted external
wrapper reuses only this execution's completed in-memory responses, including
validated cached redirect destinations. This avoids spending the shared budget
again on home/login/course/admin pages. Uncached requests and redirects consume the calculated Native allowance: 43
requests / 364 seconds. ZAP remains independently capped at 20 / 60.
Checks that exceed either bound remain NOT_REEVALUATED with a specific reason.
Response caching never uses historical results or a preceding assessment.

The existing PHP collector runs without sudo only when config.php is readable
by the demo account, with a 15-second limit within the native deadline. Its JSON
is allowlisted before retention: database credentials and collector error text
are never exported. Without collector access, readable current version.php
literals still feed the existing intelligence rules and pinned advisory catalog.
This is a fresh installed-version observation, not a current-release claim.
PATCH-001 additionally requires explicit `POSTURE_PATCH_BASELINE`. No baseline
is guessed from historical results. Plugin/configuration/auth/privacy/dataroot
checks need collector evidence; filesystem web-server assertions require the
collector UID to equal www-data; CLI PHP does not establish web-SAPI settings.

The observed host has readable version.php, PHP available, demo UID 1000,
www-data UID 33 and config.php unreadable to the demo. The UI therefore exposes
`MOODLE_CONFIG_NOT_READABLE_BY_DEMO_UID` for affected internal checks. No Linux
permissions/groups or privileged helpers are changed by the application.

The accepted active framework now runs once after fresh Native/ZAP
canonicalization, with a separately derived safe-validation budget. The Native
provider records DEFERRED and does not send a second optional set of active
requests. The old POSTURE_ENABLE_EXISTING_ACTIVE flag does not gate this new
explicitly authorized current stage. Runtime context continues to use the
existing server-only B1_ACTIVE_CONTEXT contract; no automatic credential login
is added. Parent results and CQI never consume active confirmation as a scoring
multiplier. See SAFE_CURRENT_ACTIVE_VALIDATION.md for the eight-validator audit,
strict applicability, request plan, privacy and support/status mapping.

Every new assessment includes the complete source-backed check inventory in
`check_coverage`; see `BRANCH1_CURRENT_CHECK_INVENTORY.md`. Missing verdicts have
`current_state=NOT_AVAILABLE` and a concrete prerequisite/budget reason. Existing
HTTPS-only rules on this HTTP target and pinned advisories outside a freshly
observed affected range are explicitly NOT_APPLICABLE, without inventing PASS.

In the canonical research-facing adapter NOT_REEVALUATED becomes
NOT_TESTED/NOT_TESTED with operational_status=NOT_REEVALUATED for presentation.
It contributes no risk; unknown severity remains None. Provider unavailability
never implies PASS. Coverage reports skipped checks and unmapped rules.

## API and UI

- POST /api/posture/assessments: body `{target_id:"moodle-local",mode:"PASSIVE_BASELINE",zap_enabled:true}`.
- GET /api/posture/assessments, /latest, /{assessment_id}.
- GET /api/posture/findings and /{finding_id}: view=current|historical,
  assessment_id, source, status, dimension, severity, multi_source and pagination.
- GET /api/scanners, /api/scanners/zap, /status, /findings.
- POST /api/scanners/zap/passive-assessment: the same native+optional-ZAP workflow,
  so ZAP evidence enters the same canonical snapshot rather than an unrelated view.

All mutations require the existing loopback control header and accepted local
Origin. Bodies reject extra fields, arbitrary URLs/targets and active modes.
Only one posture job runs at once. GET list/detail recomputes no experiment.

Dashboard Posture has CURRENT and RESEARCH BASELINE tabs, a real execution
button, provider progress, assessment timestamps, source/status/dimension/severity
filters, member evidence and conflict indicators. System/Evidence shows scanner
availability and PASSIVE BASELINE ONLY / ACTIVE SCANNER DISABLED. A missing
runtime displays unavailable; no fake scan or metrics are substituted.

## Current CQI vs research CQI

ACCEPTED_REPLAY uses unchanged historical posture and accepted saved behavior,
labelled RESEARCH_CQI. LIVE_LAB uses the latest completed current operational attempt (COMPLETE/PARTIAL)
and current saved-model journal, labelled CURRENT_CQI. A running, interrupted or
failed latest attempt does not fall back to an older success as fresh evidence;
older snapshots remain accessible through explicit history/retained views. With no current posture,
all check identities are NOT_REEVALUATED; no historical risk is mixed in. With no
behavior, a current posture-only partial CQI may be shown and D6 is unavailable.
Missing dimensions are excluded/renormalized exactly as the frozen policy
specifies, never assigned 100. Incomplete provider/check coverage marks overall
CURRENT CQI PARTIAL even if a dimension contains some scoreable evidence.
Dimensions with both observed and NOT_REEVALUATED controls are individually
marked PARTIAL_EVIDENCE without changing their numerical contribution. A partial
current score is not evidence of improvement over the full research score.

Assessment detail includes a before/after **posture-only** CQI projection against
the preceding successful operational snapshot (same absent D6); it is explicitly
not a paired live-behavior experiment. Differences come from canonical evidence,
not weight changes. Research CQI is never rewritten. The UI distinguishes the
posture-only projection from LIVE_LAB current CQI.

Drift NEW/RESOLVED claims are intentionally not implemented: provider absence,
failed checks or NOT_REEVALUATED cannot establish resolution. Snapshots/check IDs
support a future reviewed drift adapter without fabricating resolved findings.

## Commands

```bash
cd /home/saintdomix/dissertation_model
.venv/bin/python -B scripts/run_posture.py status
.venv/bin/python -B scripts/run_posture.py assess --authorized --without-zap
# Optional ZAP-configured run (see ZAP_PASSIVE_INTEGRATION.md):
.venv/bin/python -B scripts/run_posture.py assess --authorized
# Dashboard uses the same service, not a shell command:
./scripts/start_demo.sh --mode ACCEPTED_REPLAY
```

In the dashboard open Posture → CURRENT POSTURE → RUN POSTURE ASSESSMENT. Select
LIVE_LAB for current Fusion/CQI and explicitly start saved-model monitoring for
new behavior. No attack generation is part of this workflow. Accepted replay
remains separately available. No commit/tag or promotion is automatic.

Initial operational snapshots retain parent evidence IDs in a legacy source-ID
slot. The application derives source finding IDs from their retained members
and exposes member_evidence_ids separately; stored snapshot bytes are unchanged.
New snapshots write both fields explicitly. No evidence is dropped or relabelled.

## ZAP reachability, readiness and retained evidence

`/api/scanners/zap/status` separates runtime AVAILABLE/UNAVAILABLE, readiness
READY/POLICY_BLOCKED, latest attempt and last successful assessment. A reachable
owned runtime with previous history is READY for automatic session replacement;
GET readiness never mutates it. Legacy snapshots may still show
FRESH_SESSION_REQUIRED. Shared/unowned runtimes remain POLICY_BLOCKED.

Each assessment checks safe mode/no active scan/no spider, calls the narrowly
allowlisted `core/action/newSession` with **no parameters** (ZAP 2.17 creates a
new unnamed session), verifies empty target history, empty target alerts and an
empty passive queue, then executes only the same five reviewed GETs without
following redirects. Mode/scope/history/transcript/queue guards remain in force.
New-session failure returns FAILED/ZAP_SESSION_CREATION_FAILED with no findings;
Native still runs and overall coverage is PARTIAL. A no-op session creation or
remaining stale history/alerts fails scope integrity before collection.

Only the explicitly configured dedicated ephemeral runtime may be replaced
(`POSTURE_ZAP_OWNED_EPHEMERAL=1`, loopback API, runtime API key). No filename,
overwrite, session loading, alert deletion, active scan or spider API is exposed.
The operator must keep the dedicated ZAP home on volatile storage. New unnamed
sessions replace only that daemon's current volatile session; repository
historical snapshots and accepted evidence are never reset or overwritten.
Source semantics: [ZAP 2.17 CoreAPI newSession](https://github.com/zaproxy/zaproxy/blob/v2.17.0/zap/src/main/java/org/zaproxy/zap/extension/api/CoreAPI.java#L656).

`zap.json` records version, assessment/session correlation ID (not a fabricated
ZAP filesystem name), lifecycle state, pre-creation message count, zero target
messages before collection, fresh requests/alerts, mapped/unmapped counts,
passive queue completion and final scope result. No raw API payload, cookie,
API key or body is exported. ZAP retains its 20-request/60-second limits; Native uses its complete-plan
budget. The 3-second connect / 8-second request controls and response caps remain
unchanged.

The latest ZAP COMPLETE snapshot is selected independently of the latest native
assessment or failed/skipped ZAP attempt. Its complete artifact manifest is
hash-verified on read. `/api/scanners/zap/findings?view=retained` returns its source
findings with `assessment_scope=RETAINED_ZAP_EVIDENCE` and
`counted_as_fresh_in_current_cqi=false`. The default current view still uses only
the current canonical snapshot. Retained rows are never merged into the current
job, Fusion or CQI. If integrity fails they are not presented as hash verified.

The UI shows runtime/readiness/current-run status, fresh counts, a last-success
card and a separate retained-evidence inspector. Source badges are NATIVE, ZAP
and MULTI-SOURCE. Native NOT_REEVALUATED is presented as **NOT CHECKED IN THIS
RUN — Historical result is intentionally not reused**; a fresh unmapped alert is
**UNMAPPED ZAP RULE — Observed by ZAP but not mapped to a CQI control; excluded
from scoring**. These remain separate coverage/filter categories. Stored source
statuses, canonical mapping, maximum-source dedup and CQI coefficients remain
unchanged.

Restart the product after rebuilding the frontend:

```bash
cd /home/saintdomix/dissertation_model
./scripts/stop_demo.sh
./scripts/start_demo.sh --mode LIVE_LAB
./scripts/demo_status.sh
```

Open http://127.0.0.1:8000. Existing ZAP environment configuration must be present
in the terminal starting the backend. A used daemon is truthfully reported as
requiring a fresh session; the retained successful assessment remains visible.

If behavioral monitoring is also running, ordinary requests made by an authorized
posture assessment may appear in its telemetry. Interpret those observations
with the assessment provenance; no automatic benign relabeling, suppression or
model/threshold changes are introduced.


## TASK 1A.1: complete finite Native HTTP plan

`src/posture/native_plan.py` enumerates 24 distinct plain GET URLs from the
accepted external modules: five home/login/dashboard/course/admin pages, three
read-only access endpoints, six Moodle deployment artifacts, installer, two
dataroot candidates, six host-root exposure endpoints and the original missing
page. Four distinct method/header variants add CORS GET, plain OPTIONS, CORS
preflight OPTIONS and the original credential-free TRACE: **28 planned requests**.
Origin headers are input to the existing CORS check, never external destinations.

TLS/header/cookie/component/form controls share these responses; the five-page
header matrix and repeated Moodle module invocation share the same fresh cache.
Only completed responses are cached by method, URL and explicit headers, including
redirect hops. Each assessment constructs a new anonymous client/cache. Responses
with different CORS headers or methods are never interchanged. No authenticated
role response or historical observation enters this cache.

The existing exact allowlist has three additional GET redirect destinations:
`admin/index.php`, its existing fixed `lang=en` installer transition, and
`admin/index.php?cache=1`. The last is emitted by this installed Moodle
`admin/index.php:800`, then reaches `require_login(0, false)` at line 804. It is
ordinary anonymous admin navigation, not an upgrade action. No cache=0, sesskey,
upgrade key, arbitrary query or external destination is permitted. Thus
plain GET can consume at most 24+3 unique sends. Each of the four method/header
variants can consume at most its initial send plus three redirects, preserving
the accepted four-iteration rule. The finite hard ceiling is therefore
**(24+3) + 4*(1+3) = 43 requests**. This is a calculated redirect allowance,
not permission for extra probes or retries. Normal dispatch without redirects is
28; the source-backed installer transition commonly makes it 29.

The accepted per-request limit remains 8 seconds (connect 3). Native deadline:
43*8 + existing collector timeout 15 + bookkeeping margin 5 = **364 seconds**.
This permits the complete plan at bounded ordinary lab latency instead of
truncating it at 60 seconds. Requests, redirects, bytes, elapsed time and scope
remain enforced. Errors, exceeded bounds and unsupported redirects still fail
closed. The independently constructed ZAP PassivePolicy remains **20 / 60**;
its five-page GET-only behavior, safe mode, no-follow and no-active/spider policy
are unchanged. `provider_budgets`, `native.json.provenance.policy` and
`assessment_budget` expose exact planned/actual budgets and cache counts.

Internal configuration, version/advisory matching, plugin checks, filesystem
checks and role comparison itself require zero outbound HTTP requests. Their
existing collector/identity/session/baseline prerequisites remain explicit.
Missing CSP makes its token subchecks NOT_APPLICABLE, retaining the parent
missing-CSP FAIL. The cookie-absence branch is NOT_APPLICABLE when fresh cookie
attributes exist. Neither condition is fabricated as a transport failure/PASS.
