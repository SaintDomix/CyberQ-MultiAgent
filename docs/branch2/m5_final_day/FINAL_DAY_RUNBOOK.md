# Final-day behavioral research and demonstration runbook

## Status and scope

Accepted Model v1 (`30aa494`, `milestone-3-end-to-end`) remains the operational
baseline. M4B is preserved on `m4-demo-ui` (`a3f9100`). Existing M5 is still a
trade-off/inconclusive research candidate; its reused TEST results are not new
evidence. No accepted source, data, saved model or previous output is replaced.

This extension prepares genuine browser capture and a fresh evaluation boundary.
No authenticated capture or candidate promotion is asserted by implementing it.
Missing credentials block capture, not offline implementation/testing. An absent
dataset, freeze or metric artifact means unavailable, never a synthetic result.

The pre-work backup is recorded in `outputs/branch2/m5_final_day/implementation_status.json`.
It includes the original M5 source, scripts, documentation, artifacts, dataset and
tests, excluding environments and caches. SHA256 inventories protect every
pre-existing file under data/evidence/outputs, including earlier M5 results.

## Installed browser and privacy

The environment initially contained no browser, Playwright or Selenium. A single
Playwright Chromium **headless shell** and Python driver were installed. Fourteen
small missing runtime packages were extracted under `.tools/chromium-runtime`;
no system packages were installed. The launcher supplies their library path to
Chromium. A real sandbox-enabled Chromium in-memory DOM test passed with HTTP
blocked. No Moodle session or authentication is implied by that smoke test.

Prefer an existing system Chromium/Chrome if one is present; otherwise the local
shell is detected automatically. Optional `M5_BROWSER_EXECUTABLE` selects a trusted
local executable. `.tools/` is disposable and excluded from staging; it is not a
model package. Playwright is pinned in `requirements/m5-browser.txt`.

Credentials are read only from environment; no screenshot, HAR, trace, storage
state, password, cookie or raw Apache slice is exported. Browser child-process
environment excludes password/token/cookie variables. Debug logging is refused.
The origin and application mount are fixed to the authorized local lab. Requests
off origin, outside the application, over budget or past deadline are rejected.
WebSockets and service workers are blocked. Credentials are submitted only to a
source-supported POST login form with one nonempty token; the installed distinct
hidden guest-login form is excluded structurally. Each login gets fresh state.
The wrong-password protocol makes exactly one wrong submission and stops on
lockout warnings; this is not brute forcing.

## Supply one actual available test role

The current reserved plan requests the existing student role only. No teacher
account is presumed. Use hidden input; do not paste credentials into chat or put
them into shell history, JSON or command arguments.

```bash
cd /home/saintdomix/dissertation_model
export M5_MOODLE_URL='http://192.168.226.132/moodle/'
read -r -p 'Authorized student username: ' M5_STUDENT_USERNAME
read -r -s -p 'Authorized student password: ' M5_STUDENT_PASSWORD
printf '\n'
export M5_STUDENT_USERNAME M5_STUDENT_PASSWORD
export M5_STUDENT_IDENTITY_MARKER='http://192.168.226.132/moodle/user/profile.php?id=3'
.venv/bin/python -B scripts/run_m5_browser_capture.py readiness
```

The profile URL above comes from existing student role evidence. If using a
different account, supply its actual own-profile URL or an independently verified
distinctive identity marker. Authentication requires the marker plus logout
function evidence; HTTP200 is not identity verification. Account role is an
operator-authorized configuration, not a role inferred from Apache logs.

Additional roles use `M5_TEACHER_USERNAME/PASSWORD/IDENTITY_MARKER` or
`M5_ADMIN_USERNAME/PASSWORD/IDENTITY_MARKER`. Include them only in a NEW plan
before capture, using `plan --roles student,admin --seed NEW_SEED --root NEW_M5_ROOT`.
Do not edit or overwrite the current plan, move TEST to TRAIN, or relabel failed
captures. A new seed gives new session IDs. Do not create roles merely to claim
coverage.

## Reserved browser plan

`outputs/branch2/m5_final_day/predeclared_capture_plan.json` reserves 24 sessions:
12 TRAIN, 6 VALIDATION, 6 fresh TEST. The seed is20261014; estimated runtime is
55minutes including nominal overhead. Session IDs, protocol, role, cache policy,
duration, request budget and split are recorded before model output exists.

TRAIN covers BROWSER-B01 through B10, plus extra rapid/dashboard sessions:
login/dashboard/logout; course navigation; content activity; profile; quiz
information; one wrong password then login; rapid legitimate navigation; slow
browsing; AJAX/dashboard refresh; logout/login again. Only real discovered
course/content/quiz links are used. No quiz start/submit, grading, editing,
enrollment, security-report navigation or intentional state-changing action is
performed beyond the test account's own login/logout. Normal Moodle view/audit
bookkeeping may occur, as in real browsing.

All sessions use fresh browser contexts. Strict request routing disables HTTP
cache: `WARM_PAGE_STATE` means an additional counted dashboard visit, **not** a
claim of warm disk cache. Timing and available course choice vary by fixed seed.
These are independent controlled browser sessions, not independent users.

```bash
# Offline; zero HTTP and zero log reads.
.venv/bin/python -B scripts/run_m5_browser_capture.py capture --partition TRAIN --dry-run

# First real acceptance: one reserved TRAIN session only.
.venv/bin/python -B scripts/run_m5_browser_capture.py capture --partition TRAIN --only-session-id M5FD-20261014-001 --authorized

# For remaining DEVELOPMENT collection, use collect-development below.
# The historical --resume-completed command refuses INVALID attempts; do not
# delete them to make that command proceed.
```

Execution requires explicit `--authorized`. Missing credentials are rejected
before browser launch or log reads. `--resume-completed` checks manifest and
feature hashes; INVALID or partial sessions are never silently retried/reused.
An unavailable resource invalidates that protocol rather than inventing a view.
Stop and review missing resources before the full batch. Any methodological
change requires a new prospective plan/root/seed, preserving the original.

### Scope guard and single-session retry

Playwright 1.64.0 `Request.is_navigation_request()` distinguishes frame navigation
from browser subresources without depending on `Request.frame`, which can be
unavailable during early navigation. All off-scope frame navigations (including
child frames/popups) fail closed with `OFF_SCOPE_NAVIGATION`. The authorized
origin and `/moodle/` mount are unchanged. Off-scope subresources, including
same-host resources outside `/moodle/`, are aborted locally, never sent, and do
not alone invalidate a capture. Unexpected methods, request/deadline bounds,
unavailable request classification and real protocol failures remain fatal.

Capture manifests record `blocked_off_scope_requests_count`, at most 100
`blocked_off_scope_requests` diagnostic entries, and an omitted-entry count.
Entries contain only scheme, hostname without userinfo, resource type,
navigation flag and a conservative path: `/`, `/favicon.ico`, `/robots.txt`, or
`[REDACTED]`. Queries, fragments, arbitrary paths, credentials, bodies and
exception text are never copied. These diagnostics are not feature inputs;
the request budget still counts continued requests, and time/budget/method
guards also apply before blocking off-scope requests. Ambient log records are
excluded only by the explicit attribution policy below; their provenance remains.

`M5FD-20261014-001` and `M5FD-20261014-002` are preserved INVALID. The latter
completed its browser protocol but was rejected under the original strict
foreign-record policy; it is not retrospectively salvaged. The next unused
reserved TRAIN session is `M5FD-20261014-003` (BROWSER-B03, student). It uses its
original protocol, not a replacement/relabeling of either failure. Do not move
VALIDATION/TEST IDs.
Use the existing operator-terminal credential environment and execute only:

```bash
.venv/bin/python -B scripts/run_m5_browser_capture.py readiness --roles student
.venv/bin/python -B scripts/run_m5_browser_capture.py capture --partition TRAIN --only-session-id M5FD-20261014-003 --dry-run
.venv/bin/python -B scripts/run_m5_browser_capture.py capture --partition TRAIN --only-session-id M5FD-20261014-003 --authorized
.venv/bin/python -B scripts/run_m5_browser_capture.py verify --only-session-id M5FD-20261014-003
```

Review this one capture before further collection. Do not reuse 001/002 or regenerate
the plan. The broader workflow below remains deferred until operator acceptance.

## Exact telemetry and contamination

Capture starts at Apache EOF and records device/inode, offsets, server UTC bounds,
whole-slice SHA256 and every record's byte range/hash. A real-browser user agent
retains its actual browser prefix plus a unique `M5Capture/<session>` suffix.
New manifests use `m5-browser-capture-1.1` and attribution policy
`capture-marker-and-actor-v1`. Only successfully parsed observations matching
the declared actor, exact browser user-agent hash, final whitespace-delimited
`M5Capture/<session_id>` marker, and bounded capture time enter feature rows.
Infrastructure dummy requests never enter features. Time bounds retain Apache's
one-second resolution: start rounded down, end rounded down plus one second,
with the upper boundary exclusive. No time-bound relaxation is introduced.

Raw-slice provenance retains **every** record's byte range/hash, whole-slice
hash, offsets, device/inode and observed count. Accepted-session provenance adds
`accepted_records`, `accepted_source_byte_ranges`, marker/id/hash, expected actor
and user-agent hashes, `ambient_traffic_present`, `ownership_filtering_enabled`,
`filtering_applied`, and the policy version. Foreign records are non-fatal when
owned records exist; they are never labelled BENIGN or included in feature rows.
Malformed/out-of-time records, rotation, truncation, partial records, protocol
errors and absence of owned observations remain fatal. Raw/accepted counts on
INVALID captures describe ownership candidates, not authorized training data.

`authenticated_identity_verified` reports the actual protocol verification state,
independently of later integrity failures. It does not infer role from logs.
Independent `verify` rereads the bounded raw slice, validates all raw and accepted
ranges/counts, reproduces ownership filtering and recomputes both feature sets;
ambient traffic alone does not prevent verification. Legacy foreign-contaminated
manifests cannot be accepted under the new policy by changing only their status.
No previous INVALID capture is rewritten or relabelled.

Only numerical v1/v3.1 windows and sanitized protocol/provenance metadata persist;
raw queries, tokens, cookies, user-agent strings and bodies do not. Capture does
not invoke a model or inspect TEST decisions. Source bytes remain on the server;
per-record hashes preserve authoritative linkage without exporting secrets.

## Dataset, fit and freeze

### Development-only collection checkpoint

Session 004 completed BROWSER-B04 and was independently verified by the operator.
001 (scope failure), 002 (old contamination policy) and 003 (missing discovered
content/resource) remain immutable INVALID evidence. All original reservations
use the student role. No teacher/admin account is assumed. The original plan,
its hash, seeds and TEST reservations are unchanged.

Run exactly one collection command from the credential-bearing operator terminal:

```bash
.venv/bin/python -B scripts/run_m5_browser_capture.py collect-development --authorized
```

The coordinator processes TRAIN then VALIDATION only, in stable session-ID order.
It never probes a TEST directory or opens TEST results. Before new requests, it
independently replays every existing COMPLETE development capture, including
004. Verified captures are skipped; existing INVALID attempts are preserved and
excluded. An existing partial directory, changed membership or failed verification
stops execution. Nothing is overwritten, salvaged or relabelled.

Every new COMPLETE capture is independently verified immediately. A new
`REQUIRED_RESOURCE_UNAVAILABLE` is retained INVALID and counted as unavailable;
collection may proceed to the next reservation without substituting actions.
All other new protocol, infrastructure or integrity failures stop the command.
Missing credentials stop before browser launch, source-log replay or new outputs.
`--dry-run` is deterministic and performs no requests, source-log reads or writes.

Each authorized invocation saves a new immutable
`development_collection_runs/collection_NNN/summary.json` with per-partition
counts, session dispositions, independent verification receipts and hashes of
verified capture manifests. Repeating the command creates another summary and
re-verifies COMPLETE captures without regenerating their traffic. Session files
are never altered by the coordinator, including after a verification failure.

`COMPLETE_WITH_EXCLUSIONS` means collection ended, **not** that a model is ready
or that original target counts were met. Unavailable is a subset of INVALID.
Review the summary before dataset work. Construction and fitting require a PASS
`development_review.json`. The authorized development review explicitly excludes
immutable INVALID 001–003 and independently replays included 004–018, binding all
source hashes. This is an explicit exclusion decision, not a silent drop or a
replacement of failed evidence. No new IDs or TEST reassignment is made. See
[DEVELOPMENT_FREEZE_PROTOCOL.md](DEVELOPMENT_FREEZE_PROTOCOL.md) for the exact
review/build/freeze commands, unchanged selection rule and integrity convention.
Resource discovery failure establishes that the protocol's observable resource
precondition was unmet for that account; it does not prove that all Moodle content
or quizzes are absent. No replacements are selected from model results, and no
amendment is inferred from unavailable credentials.

This collector never constructs a dataset, fits a detector, freezes a package,
evaluates TEST or runs attack holdouts. When credentials are unavailable to the
implementation process, work stops at this prepared collection command.

```bash
.venv/bin/python -B scripts/run_m5_final_day.py build
.venv/bin/python -B scripts/run_m5_final_day.py train-freeze
```

Build refuses missing/invalid development sessions. `data/branch2_v3/final_day_01`
contains development data only: historical M2C TRAIN/VALIDATION plus the18 new
development sessions. Historical TEST remains excluded from fitting/selection;
fresh six-session TEST features are not opened. The October9 manual session
never enters training. All eight classes must exist in TRAIN and VALIDATION.
Run membership, capture hashes, byte ranges and window identities are checked.

Only after verified new browser development data exists will training run. It
produces `candidate_01/v2_final_candidate`, validation artifacts and a write-once
`freeze_manifest.json` root pointer. Freeze seals model/package, schema/adapter,
thresholds, seed, reconciliation, persistence and implementation hashes before
fresh TEST. No accepted v1 model is overwritten. Saved reload must exactly match.

The83 retained columns use canonical platform categories. No extra complexity is
added for appearance. Login/admin/AJAX/API path counters now derive from the
adapter; reports/preferences are mapped explicitly. Raw query lexical indicators
remain intact. TRAIN-only variance/correlation/robust/reference/XGB importance
and category-specific JSON/quote/encoding counts support feature review.

Novelty/scaling/reference fit BENIGN TRAIN only. IF, OCSVM and novelty-LOF use
the same rows/schema. Threshold grids1/2/5/10% use benign VALIDATION order
statistics, strict score<cutoff and equality normal. Only targets<=5% with
observed validation benign FPR<=5% are eligible. Select highest validation
novelty attack recall, lower benign any-alert session rate, higher attack
episode recall, shorter persistence, then IF/OCSVM/LOF and lower target ties.
This is declared policy, not empirically calibrated population risk.

XGB retains bounded v1 settings (200 depth3 trees, learning_rate .05, seed42,
n_jobs1, eight classes); confidence threshold .8 remains uncalibrated. All
validation candidates, including unsuccessful ones, are retained. IF seeds
42/43/44 and warm runtime/model-size measurements are descriptive validation
reports; no seed, threshold or model is selected using TEST.

## Open fresh BENIGN TEST after freeze

```bash
.venv/bin/python -B scripts/run_m5_browser_capture.py capture --partition TEST --freeze outputs/branch2/m5_final_day/freeze_manifest.json --authorized
.venv/bin/python -B scripts/run_m5_final_day.py evaluate-fresh
```

The API and CLI both require the matching freeze. All six reserved sessions must
verify. Reports compare v1/candidate on identical observed windows, including
BENIGN/novel/disagreement/known-pattern counts, false alert episodes per session,
and observed fresh-session false-alert rate. Retrospective alert-window coverage
is separate from actual wall-clock alert duration, which is unavailable in
offline evaluation. Persistence adds a nominal10seconds per additional window;
this is not a measured instantaneous detection claim. Offline processing time
and unavailable post-window live latency are reported separately.

## Fresh controlled attack holdout — only after freeze

On Ubuntu:

```bash
.venv/bin/python -B scripts/run_m5_final_day.py attack-plan
```

The prepared plan has two fresh runs per seven attempt classes. It reuses the
unchanged M2B generator within its actual offset/budget bounds, selecting fresh
IDs at71 and above. Do not substitute `--run-offset200`: the frozen planner
correctly rejects it. The wrapper consumes the prepared plan rather than
changing safety guards or executing a larger schedule. Current selection:
AP/RB/SQ/XS/PT run71–72, S02 run73–74, S01 run74–75.

On the authorized Kali worker, fetch only the wrapper and non-secret plan:

```bash
cd ~/dissertation_model
mkdir -p outputs/branch2/m5_final_day
scp saintdomix@192.168.226.132:/home/saintdomix/dissertation_model/scripts/run_m5_fresh_attacks.py scripts/
scp -r saintdomix@192.168.226.132:/home/saintdomix/dissertation_model/outputs/branch2/m5_final_day/fresh_attack_plan_01 outputs/branch2/m5_final_day/
export B2_FICTITIOUS_PASSWORD="$(python3 -c 'import secrets; print(secrets.token_urlsafe(24))')"
.venv/bin/python -B scripts/run_m5_fresh_attacks.py --plan outputs/branch2/m5_final_day/fresh_attack_plan_01/schedule.json --binding outputs/branch2/m5_final_day/fresh_attack_plan_01/freeze_binding.json --dry-run
.venv/bin/python -B scripts/run_m5_fresh_attacks.py --plan outputs/branch2/m5_final_day/fresh_attack_plan_01/schedule.json --binding outputs/branch2/m5_final_day/fresh_attack_plan_01/freeze_binding.json --authorized
unset B2_FICTITIOUS_PASSWORD
```

The wrapper verifies the source-of-truth server freeze through read-only SSH
before using existing M2B orchestration. No model is copied to Kali. Its frozen
generator source must match the server; mismatches fail closed. All attempted
authentication identities are fictitious; no password compromise/lockout bypass,
destructive query, arbitrary JavaScript, real sensitive traversal target or
availability-impact test is performed. The dashboard never generates traffic.

On Ubuntu after capture:

```bash
.venv/bin/python -B scripts/run_branch2_capture.py verify --root evidence/branch2_captures/m5_final_day_attack01
.venv/bin/python -B scripts/run_m5_final_day.py evaluate-attacks --capture-root evidence/branch2_captures/m5_final_day_attack01
.venv/bin/python -B scripts/run_m5_final_day.py evaluate-old-external
```

Attack evaluation requires verified slices, all seven classes, unused IDs and
start times after freeze. No training follows the result. October9 is an
additional diagnostic, not blind evidence; unavailable rotated source bytes
fail closed rather than approximate features. No label, FPR or accuracy is
invented for that unadjudicated session.

## Human holdout H1/H2/H3

Do not automate the human actions. With the model already frozen, on Ubuntu:

```bash
.venv/bin/python -B scripts/run_m5_final_day.py human-start --session-id H1 --actor-ip 192.168.226.129 --authorized
```

On Kali, launch a fresh incognito Chrome window with a unique user-agent suffix
while retaining a Chrome-compatible browser prefix:

```bash
chrome_version="$(google-chrome --version | sed -E 's/[^0-9]*([0-9.]+).*/\1/')"
google-chrome --incognito --disable-save-password-bubble --disable-background-networking --user-data-dir=/tmp/m5-human-H1 --user-agent="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${chrome_version} Safari/537.36 M5Human/H1" http://192.168.226.132/moodle/
```

Use the actually installed Chrome/Chromium command. H1: login→dashboard→real
course→logout. H2: login→dashboard→own profile/course→logout. H3: one wrong
password→correct login→ordinary navigation→logout. Use about three minutes;
record a non-secret action diary, no HAR or screenshots. Do not visit unrelated
sites. Use another actual actor IP only if it is the approved browser host.

After the browser finishes, on Ubuntu:

```bash
.venv/bin/python -B scripts/run_m5_final_day.py human-stop --session-id H1 --protocol-complete --authorized
```

Repeat start/browser/stop for H2 and H3, replacing all H1 identifiers, suffixes
and temporary profile names. Missing/foreign/unmarked traffic invalidates the
whole session. `--protocol-complete` is an explicit operator attestation, not
model-derived ground truth. Then:

```bash
.venv/bin/python -B scripts/run_m5_final_day.py evaluate-human
```

Never retune after H1/H2/H3. Their observed rate is not a population FPR.

## Promotion, live monitoring and Fusion

Promotion is a research decision after reviewing development, six fresh BENIGN
sessions, fourteen fresh attempts, per-class failures, episode trade-offs,
stability, latency, SHAP and human replication. There is no automatic numeric
promotion threshold. A/B/C means promote / trade-off keep v1 / worse; incomplete
fresh evidence means keep v1. Negative results and failed captures remain.

Candidate live monitoring, durable restart acceptance, M6 integration branch and
dashboard changes are intentionally gated on that decision. The saved candidate
supports inference without retraining, but this is not a claim that a new live
monitor has passed acceptance. Existing accepted v1 live/checkpoint/resume and
M4B stay available; no M2C package is overwritten.

`compat31.py` exercises the existing Fusion assembly without changing CQI math.
It requires actual emitted timestamps, IDs, byte provenance and matching model/
schema identity. The legacy `if_anomalous` field is explicitly annotated as the
selected novelty input; actual IF/OCSVM/LOF observations remain preserved.
Correlations remain contextual, non-causal and score_effect NONE. Raw novelty
observations still contribute under accepted Fusion policy; alert persistence
is a separate presentation layer, not a hidden CQI reduction or suppressed
disagreement. No real candidate Fusion output is asserted before acceptance.

## Application telemetry / portability

Moodle standard-store definitions are installed. Enabled state/retention and a
safe read-only DB export remain unverified. No secrets were extracted from
Moodle configuration or printed. Optional `audit-import` consumes a separately
approved JSON export with an environment HMAC key; it performs no DB query:

```bash
export M5_AUDIT_HMAC_KEY="$(.venv/bin/python -c 'import secrets; print(secrets.token_hex(32))')"
.venv/bin/python -B scripts/run_m5_final_day.py audit-import --input /secure/approved_audit_export.json --out outputs/branch2/m5_final_day/audit_import_01
```

The adapter drops raw user/IP/content/other fields, pseudonymizes actor/course/
context, preserves observed login failure versus success, and retains role only
when explicitly supplied. No session or historical role is guessed. Key storage
belongs in a secret manager; do not regenerate a study linkage key casually.

GenericHTTPBehaviorAdapter and MoodleBehaviorAdapter implement the same request/
application-event contract. Numerical feature/model code uses canonical categories
and an adapter/schema identity, not Moodle URL literals. Generic-path save/load/
inference tests demonstrate extensibility, not other-LMS accuracy. The claim is:
**platform-extensible canonical architecture, validated experimentally on Moodle**.
Other LMS platforms require an adapter and representative calibration/validation.

## Tests and defense fallback

```bash
.venv/bin/python -B -m unittest discover -s tests -v
git diff --check
git diff milestone-3-end-to-end -- src/branch1 src/branch2 src/fusion src/reporting
```

M4's preserved checkpoint was independently extracted under `/tmp` for69 backend
tests,9 frontend tests and production build, without merging it into M5 or
mutating accepted artifacts. Its refresh/reattach, new-prediction, duplicate-job,
safe-stop and crash/recovery tests remain synthetic; they do not establish new
candidate live acceptance. The available Node runtime in Playwright's driver
was reused for its build; no duplicate Node installation was needed.

If new-model acceptance cannot finish, use the accepted fallback transparently:
switch to preserved `m4-demo-ui` and run `.venv/bin/python -B scripts/run_demo.py`.
Use ACCEPTED_REPLAY for reproducible accepted results, or existing authorized
LIVE_LAB with **v1**, explicitly retaining its nuisance-anomaly limitation.
Do not call that an accepted v3.1 deployment. No commit/tag or M6 branch is made
until evidence and acceptance checks justify it.
