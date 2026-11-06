# Milestone 2B laboratory capture framework

Prepared only. No HTTP/SSH experiments, new captures or final model training were
performed in implementation. Test capture files are disposable mocked fixtures.

## Architecture and authority

Ubuntu `/home/saintdomix/dissertation_model` remains source of truth. Kali uses a
synchronized copy only to execute `run_branch2_capture.py run`. The Kali coordinator
uses SSH to invoke the Ubuntu capture agent before/after each run. HTTP originates
only from Kali 192.168.226.129, explicitly source-bound to that interface, with
exact origin http://192.168.226.132 and Moodle base path. Ubuntu stores byte slices,
server timestamps, generator source snapshot, manifests and hashes. No raw capture
is written into the Kali repository. SSH transfers non-secret plan/results only.
Use a reviewed SSH key/known-host entry; no password arguments or implicit host-key
acceptance. Generator source fingerprints must match on both hosts at initialization.

The coordinator does not invoke training/inference. Secret B2_* variables are
removed from the SSH child environment; they remain only in the Kali process. Import re-verifies captures
and stops on failures; the existing Dataset v2 builder then checks run-level
independence again. Offline model code and the 65-feature schema are unchanged.

## Schedule, variation and exact target

Seed42 derives a unique deterministic seed per run ID, shuffles the complete run
order, and records every URL, operation/time, query encoding and parameter profile.
All classes share the same UA format `Branch2-Lab/2.0 run=<run_id>`; its marker is
used only for capture correlation and excluded from model predictors. Each run
uses a fresh session/jar and an independent capture interval. This is experimental
repeat independence, **not** independent real-world users or environments.

| Class | Additional runs / IDs | Default profiles |
|---|---|---|
| BENIGN | 5: BN02-run01–02, B04-run01–03 | Public page/static-image retrieval; mixed ordinary navigation; authenticated administrator navigation. Seeded order and 18/20/22 GETs. |
| BRUTE_FORCE | 7: S01-run04–10 | 5/6/7 attempts, token GET + one POST each; three fictitious username suffixes per unique run prefix; varied spacing over 36 seconds. |
| ENUMERATION_RECONNAISSANCE | 8: S02-run03–10 | 18/20/22 GETs; shuffled known paths plus 3/5/7 run-specific nonexistent resources; varied breadth/order/jitter. |
| ADMIN_PROBING | 10: AP01-run01–10 | Read-only admin/index/security-report paths and 3/5/7 nonexistent privileged-looking paths; 18/20/22 GETs. No bypass. |
| REQUEST_BURST_DOS_LIKE | 8: RB01-run01–08 | Two separated waves, sequential low0.75/medium1.25/high2 requests/sec; 18/24/30 requests. No concurrency or availability-impact goal. |
| SQLI_ATTEMPT | 10: SQ01-run01–10 | Inert quotes, SELECT/UNION words, comment-like text; three lab parameter names, single/double encoding or literal delimiters; 18/20/22 GETs. No extraction/stacked statements. |
| XSS_ATTEMPT | 10: XS01-run01–10 | Inert svg/data/title/tag delimiters, no script/handlers/javascript; same parameter/encoding/rate variation. No browser execution or stored payload. |
| PATH_TRAVERSAL_ATTEMPT | 10: PT01-run01–10 | One/two/three ../ depths, encoded/mixed delimiter styles, only b2-fictitious-*.txt names in ignored query parameters; no filesystem retrieval. |

Total additional68; targets remain BENIGN12 and ten per attack class. New BN02 IDs avoid claiming that anonymous entry-page/static-image requests are quiz
submission or course-file browsing. RB01 avoids the historical S03/Nikto naming
conflict. Counts are unchanged; these are transparent scenario-ID adjustments.
`--counts` accepts an explicit JSON object with all eight class counts (0–30).
Partial plans remain marked target_reduced=true; partial import requires
--allow-partial and never silently becomes the 68-run final plan.

Each run lasts nominal44 seconds plus four seconds flush/cooldown: **3264 seconds
(54m24s)** overall, excluding SSH/start-boundary latency. Allow roughly55–65 minutes
in a stable local lab; per-request/deadline failures stop the schedule. Seed42
plans at most **1363 HTTP requests**, minimum1354 with the shortest permitted
administrator redirect chains. Admin redirect lengths are observed, not invented.
Every run spreads useful traffic across multiple 10-second bins; verification
requires at least two occupied temporal bins and at least one usable feature window.

Requested average/burst rate and per-request relative times are recorded; worker
results include attempted count, actual elapsed time, achieved mean/peak rates,
status codes, bounded observed response lengths and error status. No response
bodies, POST bodies, usernames/passwords, cookies or session IDs are serialized.

## Supported target context and secrets

Non-secret `experiments/branch2_lab_context.template.json` supplies source-supported
read-only routes, public Moodle images and existing administrator/student identity
markers. Installed index.php does not consume b2_lab_* query parameters. SQL/XSS/
traversal markers go only in those ignored parameters on the homepage; they label
URL-observable **attempt-like** traffic, not successful vulnerability exploitation.
HTTP preparation may percent-encode literal delimiters; Apache captures the actual
wire representation. No claim of raw executable browser payloads is made.

Course/resource/quiz object IDs are not invented. If richer normal browsing is
needed, provide a new non-secret context JSON with independently verified available
read-only course/view, mod/resource/view or mod/quiz/view URLs. The default captures
no quiz attempts/submissions or persistent application changes. Static image paths
are backed by existing Moodle files. Administrative navigation uses the previously
supported profile-id2 identity and security-report resource; fresh verification is
mandatory. Anonymous normal navigation and administrative browsing are distinct
protocols; natural browser/application traffic remains a future external-validity
requirement.

Kali secret inputs, only through environment or hidden input:

- B2_ADMIN_USERNAME / B2_ADMIN_PASSWORD: dedicated authorized administrator account.
- B2_FICTITIOUS_PASSWORD: one ephemeral value for the reserved, unprovisioned
  b2lab-fictitious-* namespace. Operator must ensure these usernames are not accounts.
  This is repeated controlled authentication traffic, not password discovery.

--interactive asks for these inputs once before initiating capture, using hidden
prompts; process-local generated entries are cleared afterward. Supplied environment
values are left under caller control. Do not put literal passwords in command
arguments, shell history, templates or copied artifacts. Cookies/tokens stay in
memory and jars are cleared/closed. Auth bootstrap allows one POST plus bounded
same-origin GET redirects including Moodle's numeric testsession route; independent
/my/ observation must show administrator identity and exclude student identity.
No MFA/SSO/password-change flow is guessed or bypassed. Failure stops capture.

Safety: concurrency1, absolute peak limit2 requests/sec, ≤40 attempts/run,
timeout5s, ≤256KiB response capture, deadline44+10s. No automatic retries, password
guessing against real users, redirects during experimental probes, external origin,
state-changing route/query, destructive SQL, script execution or sensitive-file
traversal. Server 5xx, missing authentication context or bounds abort the run.
Normal Moodle session/audit updates from authenticated navigation are expected;
no grade/course/configuration mutation is performed.

## Exact capture boundaries and verification

Ubuntu aligns start to the next server UTC second, records dev/inode/byte offset,
and reads only newly appended complete combined-log records at finish. A two-second
flush wait plus two-second coordinator cooldown separates runs. Floor/ceil UTC
intervals cover Apache's second-resolution timestamps; precise server timestamps
and exact byte offsets remain in every manifest. Log rotation/truncation, partial
records or >8MiB unexpected slices fail closed. Apache itself is never modified.

A shared agent lock and active-session marker prevent overlap even between separate
capture roots. Run evidence is immutable; only duplicated temporary coordination
state is cleared. Begin records are preserved. finish writes raw access.log,
manifest.json and manifest.sha256; init archives exact generator source/hashes.
Unexpected worker termination records unknown request accounting as null, not zero.

Verification checks the entire requested schedule, run/class/profile IDs, source/
manifest hashes, parseable nonempty events, valid nonoverlapping bounds, exact
Kali source/run-UA and method/URL/count/sequence accounting, successful worker
completion, sufficient temporal span/windows and duplicates. Foreign requests,
TEST/dummy traffic, errors, missing runs and extra manifests are rejected, never
silently filtered into a successful capture. Raw contaminated evidence is retained.
Keep browsers/background scanners quiet and prevent Apache rotation during a session;
if Apache emits internal dummy traffic, verification reports contamination rather
than hiding it. No successful class count or final dataset is asserted on failure.

## Ubuntu setup and commands

Run from the source-of-truth checkout. Ensure the source user has read permission
on /var/log/apache2/access.log and SSH key access from Kali. For an operator-approved
setup, adding the source user to adm is one option; do not make logs world-readable:

```bash
cd /home/saintdomix/dissertation_model
# Only if needed, operator-approved privilege setup; reconnect afterward:
sudo usermod -aG adm saintdomix
# Reconnect before checking permissions:
test -r /var/log/apache2/access.log
```

Do not execute capture setup/actions until the reviewed implementation is
synchronized to Kali (no Git commit is required). A proposed source sync, run on
Kali, uses no --delete and preserves Ubuntu authority:

```bash
rsync -a saintdomix@192.168.226.132:/home/saintdomix/dissertation_model/src/branch2/ src/branch2/
rsync -a saintdomix@192.168.226.132:/home/saintdomix/dissertation_model/scripts/run_branch2_capture.py scripts/
rsync -a saintdomix@192.168.226.132:/home/saintdomix/dissertation_model/experiments/branch2_lab_context.template.json experiments/
rsync -a saintdomix@192.168.226.132:/home/saintdomix/dissertation_model/requirements/branch2-capture.txt requirements/
```

## Kali dry-run and authorized capture — proposed, not executed

Use the synchronized worker checkout, an existing .venv and requests (no ML package
needed on Kali). Check SSH key/known-host provisioning separately. Optional dependency
setup, if requests is absent: `.venv/bin/python -m pip install -r requirements/branch2-capture.txt`.

```bash
.venv/bin/python -B scripts/run_branch2_capture.py run \
  --context experiments/branch2_lab_context.template.json --seed 42 --dry-run \
  > /tmp/branch2_session01_plan.json

.venv/bin/python -B scripts/run_branch2_capture.py run \
  --context experiments/branch2_lab_context.template.json --seed 42 \
  --authorized --interactive --ssh-host saintdomix@192.168.226.132 \
  --capture-root evidence/branch2_captures/session01
```

Dry-run performs no HTTP, SSH, log modifications or secret prompts and prints the
full schedule/counts/seeds/relative boundaries/estimates. Live execution creates
only Ubuntu capture evidence. No copying/import from Kali is necessary. For backup,
copy the completed Ubuntu evidence to Kali without making it authoritative:

```bash
rsync -a saintdomix@192.168.226.132:/home/saintdomix/dissertation_model/evidence/branch2_captures/session01/ /tmp/branch2_session01_backup/
```

## Ubuntu verify, import/build and later training

```bash
cd /home/saintdomix/dissertation_model
.venv/bin/python -B scripts/run_branch2_capture.py verify \
  --root evidence/branch2_captures/session01
.venv/bin/python -B scripts/run_branch2_capture.py import \
  --root evidence/branch2_captures/session01 --name session01
.venv/bin/python -B scripts/run_branch2.py build \
  --metadata experiments/branch2_session01_metadata.csv \
  --labels experiments/branch2_session01_labels.json \
  --out data/branch2_v2/session01_candidate
```

Run commands sequentially only after prior success. Import re-runs verification,
checks historical/new IDs and intervals, copies only new raw filenames with exclusive
creation, and writes new metadata/labels/receipt; it never appends/replaces historical
CSVs or changes the 65-feature schema. Final candidate expected count82 runs if all
68 new runs validate. Labels retain historical mapping/source caveats. Inspect the
builder inventory and class/window coverage and review final protocol/split before
training. A verified capture is not automatically a robust final evaluation.

**Later, only after candidate data validation/review**, the existing offline
training/evaluation command is:

```bash
.venv/bin/python -B scripts/run_branch2.py train \
  --dataset data/branch2_v2/session01_candidate/dataset.json \
  --seed 42 --confidence-threshold 0.8 \
  --out outputs/branch2/session01_reviewed_models
```

No automatic training is included. Current pipeline artifacts still label evaluations
provisional until final experimental protocol is accepted; do not rename results
into final claims silently. Classification labels represent controlled laboratory
traffic, not confirmed attacks/compromise. Generalization claims remain limited to
this dataset and controlled repeated experiments.

If a process/rotation fails leaving an active capture, inspect retained evidence.
Explicit authorized abort releases only transient coordination state and retains
begin/abort records, which remain unverifiable as complete captures:

```bash
# Replace the example run ID with the actual active run from begin.json:
printf '%s\n' '{"run_id":"SQ01-run01"}' | .venv/bin/python -B scripts/run_branch2_capture.py \
  agent abort --root evidence/branch2_captures/session01 --authorized
```

A failed session must not be overwritten or silently resumed into the planned final
counts. Preserve it; create a new reviewed schedule/capture root with unique run IDs
before a later experiment. Use --run-offset 20 (or another reviewed unused range)
for replacement sessions; previously attempted run IDs cannot be reused. Endpoint availability, permissions, clock consistency,
SSH and real authentication still require separate authorized lab acceptance.

## Targeted BRUTE_FORCE acceptance after the 303 protocol fix

The failed `S01-run06` evidence remains immutable. Its worker stopped because it
required POST status 200. Installed Moodle `login/index.php` lines 376–385 perform
POST/redirect/GET after password submission, directing to the login page with a
boolean `loginredirect` query. The failed combined log/result records 303 but does
not retain Location, so its exact destination cannot be independently recovered.

Only BRUTE_FORCE now accepts POST 302/303 to the exact authorized login endpoint,
with no query or exactly `loginredirect=0` / `loginredirect=1`. Relative Locations
are resolved against that endpoint; other origins, routes, fragments, queries,
missing/malformed Locations and other statuses fail closed. No redirect is followed
and no authentication success is inferred. Cookies are discarded after each
attempt; the next scheduled attempt obtains fresh cookies and exactly one nonempty
login token. Missing/ambiguous state aborts. Each attempt remains two requests;
there are no retries or changes to scheduling/rate/request bounds.

`--only-run-id` selects one run **after** generating the seeded schedule and applying
`--run-offset`. It preserves the profile/seed/steps/budget, rebases only schedule
start/end offsets, marks the schedule partial and retains the 68-run target counts.
An unknown ID fails before HTTP/SSH. Without this option full-session semantics
are unchanged. Partial verification checks the entire selected schedule; it is not
acceptance of the complete dataset.

On Kali, synchronize the patched generator from Ubuntu before any acceptance
(source hashes must match). These commands are proposed, not executed:

```bash
cd ~/dissertation_model
rsync -a saintdomix@192.168.226.132:/home/saintdomix/dissertation_model/src/branch2/capture/ src/branch2/capture/
rsync -a saintdomix@192.168.226.132:/home/saintdomix/dissertation_model/scripts/run_branch2_capture.py scripts/

# Offline exact failed-run profile: six attempts / twelve requests, no network.
.venv/bin/python -B scripts/run_branch2_capture.py run --seed 42 --only-run-id S01-run06 --dry-run

# New run ID: S01-run26, five fictitious attempts / ten requests, nominal 48 seconds.
# A previously attempted ID cannot be reused, even under a different capture root.
.venv/bin/python -B scripts/run_branch2_capture.py run --seed 42 --run-offset 20 --only-run-id S01-run26 --dry-run
.venv/bin/python -B scripts/run_branch2_capture.py run --seed 42 --run-offset 20 --only-run-id S01-run26 --authorized --interactive --ssh-host saintdomix@192.168.226.132 --capture-root evidence/branch2_captures/bruteforce_acceptance01
```

The targeted run prompts only for `B2_FICTITIOUS_PASSWORD` (hidden); attest that the
reserved fictitious namespace has no real accounts. No administrator credentials
are needed. No password should appear in a command or artifact. Ensure the new
root/ID has never been attempted and no retained active-capture lock exists; if
there is active state, review the existing abort procedure rather than deleting
failed evidence or bypassing the guard.

On Ubuntu verify this **one-run** capture:

```bash
cd /home/saintdomix/dissertation_model
.venv/bin/python -B scripts/run_branch2_capture.py verify --root evidence/branch2_captures/bruteforce_acceptance01
```

Only after it reports `verified: true`, prepare a fresh full 68-run session on Kali.
Offset 40 avoids both the original session's IDs and targeted offset-20 ID; it uses
existing deterministic run-offset semantics (new IDs derive new seeds/profiles).
No counts are reduced. Review the new dry-run estimates before execution:

```bash
cd ~/dissertation_model
.venv/bin/python -B scripts/run_branch2_capture.py run --seed 42 --run-offset 40 --dry-run
.venv/bin/python -B scripts/run_branch2_capture.py run --seed 42 --run-offset 40 --authorized --interactive --ssh-host saintdomix@192.168.226.132 --capture-root evidence/branch2_captures/session02_clean
```

Do not merge failed/partial acceptance into final Dataset v2 or train final models
on the basis of this targeted check. Full-session verification remains mandatory.

### Form-scoped token correction and fresh acceptance

The next real acceptance stopped on its GET: the page contained two global
`logintoken` inputs. The installed `lib/templates/loginform.mustache` defines
separate POST forms with the same `{{loginurl}}` action: `id="login"`, class
`login-form`, has a text username and password-type password; `id="guestlogin"`
has hidden username/password controls. Each has a hidden logintoken. This source
structure explains why page-wide token counting is inappropriate. The preserved
captures contain no raw page, so the rendered form details were not independently
re-fetched during implementation; no HTTP requests or real tokens were collected.

Both administrator and fictitious login now use the same form-scoped parser.
Only a complete POST form resolving exactly to the authorized login endpoint may
supply its token. The source-supported guest form is excluded only when its ID is
`guestlogin` and its username/password controls are both hidden; other competing
POST forms fail closed, even if tokens match. Unrelated tokens outside the form or
in other routes are ignored. Exactly one enabled nonempty token is required inside
the selected form. Off-origin/query/fragment/wrong actions, nested/unclosed forms,
duplicate attributes, base-URL ambiguity and external form associations fail
closed. Tokens stay in memory and are cleared after the login POST (including
failure). The prior redirect, fresh-cookie/token, authorization, rate, deadline and
request-budget restrictions are unchanged. Existing token-only positive test
fixtures now contain realistic form boundaries; their assertions are retained.

Preserve both previous failed sessions. After synchronizing the updated capture
source from Ubuntu to Kali using the rsync commands above, use a new ID/root:

```bash
# Kali: offline review, then one authorized run; proposed, not executed.
cd ~/dissertation_model
.venv/bin/python -B scripts/run_branch2_capture.py run --seed 42 --run-offset 21 --only-run-id S01-run27 --dry-run
.venv/bin/python -B scripts/run_branch2_capture.py run --seed 42 --run-offset 21 --only-run-id S01-run27 --authorized --interactive --ssh-host saintdomix@192.168.226.132 --capture-root evidence/branch2_captures/bruteforce_acceptance02

# Ubuntu: verify only this new capture.
cd /home/saintdomix/dissertation_model
.venv/bin/python -B scripts/run_branch2_capture.py verify --root evidence/branch2_captures/bruteforce_acceptance02
```

S01-run27 plans five fictitious attempts / ten requests and a nominal 48-second
capture including flush/cooldown. Its seed is derived from its fresh ID using the
existing offset mechanism. Do not reuse S01-run26, bruteforce_acceptance01, or any
other attempted ID/root. Confirm no unresolved active capture before execution.

### B04 BENIGN navigation correction and targeted acceptance

The real offset-40 session stopped at B04-run43 after successful administrator
bootstrap. Its security-report GET triggered server-originated MoodleBot/4.5 HEAD
requests, contaminating the slice. The report renders `core\check\table('security', ...)`
in installed `report/security/index.php`; it is security tooling, not an ordinary
BENIGN browsing destination. The worker records only BOUNDED_REQUEST_FAILURE, with
no status/byte count for that request. Timeout versus response-size failure cannot
be determined conclusively from retained evidence; no bounds are increased.

The non-secret `admin_navigation` context replaces only the security-report URL
with `/moodle/course/index.php`. This route is already in benign_resource/mixed
context and its installed source renders the course-category listing, including
normal access checks and a view event. B04 now browses home, `/my/`, and the course
listing as the authenticated administrator. The three-entry pool preserves seeded
shuffle/timing, request counts and all other class profiles. Default counts remain
68 runs / 1363 planned requests (offset 40: 1369); model/features/labels are unchanged.
The separate anonymous reconnaissance/probing report mappings are unchanged.
No MoodleBot filtering is introduced: foreign traffic remains a verification
failure and raw contaminated evidence is retained. Course-listing runtime behavior
must still pass the targeted real acceptance; offline source/mock tests do not
establish a fresh live result.

Next live step is **one B04 run only**, using a new ID/root. Preserve all four prior
sessions. Synchronize the updated context from Ubuntu to Kali, with the previously
accepted capture code present on both hosts:

```bash
# Kali — proposed only, not executed during implementation.
cd ~/dissertation_model
rsync -a saintdomix@192.168.226.132:/home/saintdomix/dissertation_model/experiments/branch2_lab_context.template.json experiments/
.venv/bin/python -B scripts/run_branch2_capture.py run --seed 42 --run-offset 60 --only-run-id B04-run63 --dry-run
.venv/bin/python -B scripts/run_branch2_capture.py run --seed 42 --run-offset 60 --only-run-id B04-run63 --authorized --interactive --ssh-host saintdomix@192.168.226.132 --capture-root evidence/branch2_captures/b04_acceptance01

# Ubuntu — verify this one-run schedule.
cd /home/saintdomix/dissertation_model
.venv/bin/python -B scripts/run_branch2_capture.py verify --root evidence/branch2_captures/b04_acceptance01
```

B04-run63 has 20 ordinary GETs plus bounded authentication: minimum 24, maximum /
planned 27 requests, nominal 48 seconds including flush/cooldown. Hidden prompts
require only B2_ADMIN_USERNAME and B2_ADMIN_PASSWORD for the dedicated authorized
administrator. Existing identity verification remains mandatory. Confirm unused
ID/root and no unresolved active capture before execution. No full-session retry
or final training is proposed before this targeted verification passes.
