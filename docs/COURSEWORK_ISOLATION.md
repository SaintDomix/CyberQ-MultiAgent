# Independent coursework isolation — 2026-11-06

This copy is `/mnt/assignment/cyberquality_multiagent`, on `/dev/sdb` ext4.
The dissertation at `/home/saintdomix/dissertation_model` remains immutable.
The initial isolation phase added no multi-agent implementation. No live lab traffic, training,
system configuration, remote SSH, Moodle changes, or ZAP commands were performed.
Offline functionality has been exercised; live functional parity remains BLOCKED
pending a separate authorized phase. Do not interpret replay as a new experiment.

## Audit and preservation

The initial byte inventory covered 15,322 files, including ignored/hidden files,
binary assets, virtualenv scripts, generated scripts, state and symlinks. It found
916 files containing original-repository path references. Historical evidence,
documentation, receipts and bytecode retain those references intentionally.
The local inventory contains paths/hashes only, not log records or credentials:
`coursework/initial_inventory.json` (ignored by Git).

Discovered risks and changes:

| Risk | Coursework action |
| --- | --- |
| Copied pip/uvicorn shebangs and activation files select original `.venv` | Do not execute or activate copied `.venv`. Created `.venv-coursework` with the system venv builder and an offline copy of its dependency payload; new Python binaries and bootstrap. |
| Capture orchestration invokes original repository via SSH/scp | Disabled `RemoteAgent`, fresh attack execution, capture-agent execution and operational shell entrypoints. Offline capture plan/verification code remains. |
| Startup decrypts settings from an external recovery tree | Disabled that launcher; no recovery files or secrets loaded. |
| Copied process/PID state could adopt unrelated services | Disabled legacy lifecycle start/stop/main and shell wrappers. New foreground server owns no old process. |
| Frontend development proxy selects port 8000 | Changed to 8001. Existing frontend builds contain no `:8000` reference. Builds preserved. |
| Copied runtime cursors, sessions, SQLite and posture snapshots | No copied state resumed as coursework ownership. All new Python writes limited to `runtime/coursework`. New posture state is `runtime/coursework/posture`; imported history has separate read-only endpoints. |
| SQLite can create SHM/WAL even on a read-only connection | Copied journal readers use `mode=ro&immutable=1` in coursework offline mode; only for frozen copied snapshots. Never use immutable mode for a changing live DB. |
| Ambient lab credentials/ownership flags | Bootstrap clears PRODUCT/POSTURE/B1/B2/M5 settings and proxy settings before imports. No secrets are printed or exported. |
| Shared ZAP profile resets global daemon state | All connections and operational starts are blocked. No ownership flags or credentials inherited. |

The preservation receipt covers 2,801 original copied artifact files under
`legacy`, `data`, `evidence`, `experiments`, `outputs`, `runtime`, and root archives.
Their bytes were unchanged at verification. Frozen accepted inference files and
manifests were not edited. Original source commit remained
`95513fc10dd4356352f9bc935ba8bcf63532a04e`; its initial and final Git status digests
matched. This means unchanged status, not an assertion that the original was clean.

Read-only host inspection observed original Python PID 415036 with cwd in the
dissertation repository, a loopback port 8000 listener, and port 80 listening.
Nothing was signaled or reconfigured. No host port 8081 listener was observed;
this says nothing about remote Kali ZAP availability. The execution sandbox hides
host processes, so host observations required a read-only check outside it.

All 23 symlinks resolved inside coursework storage except the imported venv's
system Python link (`/usr/bin/python3.10`). None resolved into the source repository.
The copied `.tools` Playwright link file contains an old path; it is not used.

## Write, database and dependency boundaries

Approved new state is `runtime/coursework/`: logs, temporary synthetic data,
test receipts, cache, UI test payloads and future coursework posture results.
There is no persistent live coursework DB yet because monitoring is locked.
Future monitoring needs a fresh coursework UUID, source cursor, checkpoint and
SQLite journal plus its WAL/SHM in that directory, never a copied cursor.
Apache `access.log` remains a future read-only input. Current bootstrap prevents
opening it at all until the separate live phase.

`coursework/isolation.py` installs a Python audit boundary before app imports:
new-state-only writes, confined SQLite, no source-repository opens, no outbound
connections/DNS, no subprocesses/external signals, no links, and port 8001 only.
It also checks cwd, Git root/remotes and mounted disk. The new venv loads it via
a `.pth` bootstrap; bootstrap failure exits Python. This is a boundary for reviewed
Python code, not an OS sandbox for hostile native extensions or arbitrary shell
commands. Use only the commands below. Do not bypass it with `-S` on the new venv.

The fresh venv was built offline without running old Python/pip or installing
system packages. Local wheel availability was limited to pip/setuptools, so
installed dependency payloads were copied into a fresh independent venv instead.
58 distributions were inventoried in `coursework/dependency_receipt.json`.
NumPy 2.2.6, scikit-learn 1.7.2, XGBoost 3.2.0 and FastAPI 0.142.4 imported.
The footprint is about 1.4 GB additional; available disk space was 26 GB before
and about 25 GB after preparation. The copied `.venv` is retained, unused.
System Node/npm are unavailable; frontend checks used Node v24.21.0 already
bundled in the new venv's Playwright dependency. No browser or package download. No runnable Chrome/Chromium executable was found in the copied `.tools` tree.
Vite refreshed a dependency-cache metadata file inside copied node_modules.

Git has no remotes and branch `main` has no initial commit. Nothing was staged,
committed or pushed. `.gitignore` now excludes dependencies, tools, runtime,
raw evidence/data, models, experiments, outputs, databases, secrets and builds.
Ordinary `git diff` is empty for an unborn repository of untracked files;
the initial hash inventory identifies edits, and read-only `git diff --no-index`
comparisons provide code review against matching original files.

## Start, stop and verify

Run from the exact coursework root:

```bash
cd /mnt/assignment/cyberquality_multiagent
/usr/bin/python3 -I -S scripts/coursework_prepare.py
/usr/bin/python3 -I -S scripts/coursework_check.py --preservation --source-proof
.venv-coursework/bin/python -I -B scripts/coursework_serve.py
```

Open `http://127.0.0.1:8001`. Stop with Ctrl-C in that same foreground terminal.
Do not use copied PID files, broad kill commands, original scripts, systemctl,
or the old `.venv`. The backend is left stopped after automated validation.

```bash
# Bounded HTTP verification starts and stops only its own coursework child.
/usr/bin/python3 -I -S scripts/coursework_http_check.py
# Host process observation is read-only and never grants lab ownership.
/usr/bin/python3 -I -S scripts/coursework_check.py --host-processes
# Offline synthetic tests, accepted replay, saved inference and exact TreeSHAP.
.venv-coursework/bin/python -I -B scripts/coursework_offline_check.py
```

The managed execution sandbox denies socket operations including asyncio thread
wakeups; HTTP and asynchronous validation required execution outside that network
sandbox. The application boundary remains installed. These scripts do not access
the lab. Test receipts and server logs are under `runtime/coursework`.

Reproduce the frontend unit and server-rendering checks:

```bash
.venv-coursework/bin/python -I -B scripts/coursework_export_ui.py
cd demo/frontend
PRODUCT_TEST_PAYLOAD=/mnt/assignment/cyberquality_multiagent/runtime/coursework/product-payload.json \
  ../../.venv-coursework/lib/python3.10/site-packages/playwright/driver/node \
  --test --experimental-test-isolation=none src/utils/data.test.js \
  src/utils/product.test.js scripts/product_render.test.mjs scripts/monitoring_controls.test.mjs
```

Imported scan history is available at `/api/coursework/history` (paginated summaries)
and `/api/coursework/history/{assessment_id}` (verified, sanitized detail).
The existing UI history APIs also retain imported assessments for explicit
historical selection, through a coursework adapter. Imported assessments never
become the latest/current coursework job and cannot grant process ownership.
Saved baseline, replay evidence and report links remain in the existing UI.

## Actual validation

| Capability | Status | Evidence / limit |
| --- | --- | --- |
| Workspace, mount, independent Git, symlinks, artifact bytes, original Git | PASS | Read-only diagnostic and initial inventory comparison. |
| New venv and safety gates | PASS | Imports, policy simulations, HTTP 423 for operational starts. No forbidden write attempted. |
| Native offline behavior | PASS | Mock HTTP provider timeout/scope/sanitization tests and saved posture projection. Live collector not executed. |
| ZAP profile policy/UI | PASS offline | Scanner readiness and profile UI rendering checked. No daemon commands. |
| ZAP STANDARD/PASSIVE/FULL execution | BLOCKED | Separate authorization and exclusive lab ownership required. |
| 83 features; OCSVM/XGBoost inference | PASS | Synthetic extraction plus saved-model inference, no fitting. |
| Behavioral engine and independent SQLite/cursors/resume | PASS synthetic | 15 runtime tests; all files in coursework temp directories. |
| Live Apache monitoring | BLOCKED | No shared log consumption or original monitor changes. |
| Explain / native exact TreeSHAP | PASS | Available; synthetic additivity error about 1.43e-6. Explanation API and UI rendering tested. |
| Incidents, CQI D1–D6, versioned CQI and product API | PASS offline | Unit/property tests, replay API and UI rendering. Scores are not attack probabilities. |
| Saved reports and imported evidence | PASS | Markdown/JSON/HTML HTTP responses; hash-verified archived scans; one actual retained journal read immutable (9 predictions, 2 incidents). |
| Python tests | PASS | 170 passed, 3 deselected. Two old monitor-start tests conflict with the intentional lock; one creates a symlink prohibited by the boundary. |
| Frontend units and React rendering | PASS | 65 checks on real saved-evidence payloads. |
| Real browser interaction/build regeneration | NOT TESTED | Existing built assets served; no browser automation or new build. |
| Live functional parity | BLOCKED | Not claimed; shared services intentionally untouched. |

Initial validation exposed a file-descriptor handling defect in the new guard;
it was fixed to recognize only descriptors resolving inside new coursework state.
Sandboxed async checks then stalled because socket wakeups were prohibited; those
runs were stopped/timed out, and the final guarded suite passed outside that network
sandbox. A diagnostic route ordering issue was also corrected before the HTTP pass.

## User-controlled shared-lab handoff — future authorized phase only

1. User explicitly authorizes the target, profile, time window and ownership
   transition in a separate phase. Coursework remains locked until then; there is
   no environment variable that unlocks this implementation.
2. User uses the original application's own controls to finish/cancel its jobs
   and stop monitoring. This task never stops the original backend or services.
   Original backend may remain on port 8000 with no lab workers active.
3. Read-only host and ZAP API checks must verify no original monitor, active scan,
   traditional/browser/client spider, pending passive work, or other lab owner.
   A port check or operator assertion alone is insufficient. No remote-repository
   SSH helper is permitted.
4. Retain/export the outgoing owner's ZAP evidence/session under user control.
   Existing providers call `core/newSession`, change daemon mode/global scanner
   options, and create contexts/policies. Those are daemon-global operations:
   a unique context alone cannot isolate concurrent applications. Never label
   the shared daemon owned merely by setting `POSTURE_ZAP_OWNED_EPHEMERAL=1`.
5. The next phase must implement a bounded, owner-specific lease checked at every
   scan/monitor entry and before any ZAP mutation. Use an exclusive coursework
   lock, finite lease, explicit handoff receipt, fresh session/context/run IDs and
   fail-closed expiry. Retain the lease until owned scans finish and cleanup is
   verified; never reset or stop a foreign scan on takeover. Read Apache only and
   keep all cursors/journals in fresh coursework state.
6. A coursework-only lock cannot force the unchanged original app to cooperate.
   The operator must keep its jobs disabled throughout, or arrange an approved
   exclusive access mechanism outside original code before enabling coursework.
   If that guarantee cannot be made, do not unlock live access.
7. On switching back, the user stops only coursework-owned workers, verifies
   quiescence, saves its evidence, releases its lease, and then resumes original
   monitoring through the original application's controls. No simultaneous owners.

This handoff is a plan, not an implemented or tested cross-application lease.
The implemented hard lock is the current enforceable safety gate.

## Changed source/configuration files

All paths are relative to the coursework root:

- `.gitignore`
- `demo/backend/app.py`, `demo/backend/runtime.py`, `demo/backend/services.py`
- `demo/operations.py`, `demo/frontend/vite.config.js`
- `src/posture/orchestration.py`, `src/branch2/capture/orchestration.py`
- `scripts/run_demo.py`, `scripts/start_cyberquality.py`
- `scripts/run_branch2_capture.py`, `scripts/run_m5_fresh_attacks.py`
- `scripts/capture_experiment.sh`, `scripts/run_m5_quick_attack_holdout.sh`
- `scripts/start_demo.sh`, `scripts/stop_demo.sh`, `scripts/demo_status.sh`
- Added `coursework/__init__.py`, `coursework/isolation.py`, `coursework/posture.py`
- Added `scripts/coursework_prepare.py`, `scripts/coursework_check.py`,
  `scripts/coursework_serve.py`, `scripts/coursework_http_check.py`,
  `scripts/coursework_offline_check.py`, `scripts/coursework_export_ui.py`
- Added this document. Generated ignored files: new venv, inventories/receipts,
  runtime test state/logs/payloads and Vite dependency-cache metadata.

No research algorithms, feature schema, taxonomy, scoring coefficients, split
protocol, status semantics, frozen models, benchmark outputs or experiment
receipts were changed. No original-repository or system files were written.

## Assignment 4 extension

The subsequent coursework-only multi-agent layer is documented in
`README.md` and `docs/assignment4/`. It adds no shared laboratory authorization.
Its own task database, audit events, generated reports and versioned frontend
builds remain under `runtime/coursework`. The launcher serves the new runtime
build when available, while preserving every saved frontend build. The original
finding/model/CQI implementations and this isolation boundary are unchanged.
