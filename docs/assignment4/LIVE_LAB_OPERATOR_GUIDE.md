# Coursework operation and laboratory handoff

> Historical operator runbook for the provisioned laboratory. Machine addresses,
> PID observations and blocker statements below describe that preparation phase.
> A later live task completed; re-establish all prerequisites before any new use.
> These commands do not provision a public clone or authorize a laboratory action.
> See the [current project summary](../../README.md) for release limitations.

## Stopped-original handoff update

The user has stopped the original through its own lifecycle. The coursework gate
now verifies port 8000 absence, original worker absence and the same system boot;
it does not require an original API response. Every allowed live operation and
controller heartbeat rechecks absence. No matching restart service/template/cron
entry was observed. This cannot prevent an operator manually restarting the
unchanged original: keep it stopped; a detected restart revokes coursework access.

Current blocker: read-only SSH authentication for `saintdomix@192.168.226.129` was
denied. ZAP authentication/Safe Mode/idle queues passed, but its isolated `-dir`
was not verified. No READY receipt, authorization or lease has been fabricated.

Ubuntu, read-only first (enter the SSH password locally if required; never paste it
into chat; the probe prints no API keys). The output file is currently absent:

```bash
cd /mnt/assignment/cyberquality_multiagent
( umask 077; ssh -o StrictHostKeyChecking=yes -o UpdateHostKeys=no saintdomix@192.168.226.129 'python3 -I -S -' < scripts/coursework_zap_directory_probe.py > runtime/coursework/lab/zap-directory.json )
/usr/bin/python3 -I -S scripts/coursework_lab.py check-stopped
```

Only a successful direct private-directory/socket-owner probe plus actual stopped,
restart, authenticated ZAP and Apache checks can produce READY. Otherwise stop.
**The following live commands require separate explicit user approval.**

```bash
/usr/bin/python3 -I -S scripts/coursework_lab.py authorize --seconds 3600
# Select STANDARD and confirm only after approval; hold in a separate terminal:
/usr/bin/python3 -I -S scripts/coursework_lab.py hold --seconds 3600
# Restart ONLY coursework: Ctrl-C its existing foreground server, then:
.venv-coursework/bin/python -I -B scripts/coursework_serve.py
# Another Ubuntu terminal — independently start the existing owned monitor:
curl -fsS -X POST http://127.0.0.1:8001/api/runtime/start -H 'X-Product-Control: 1' -H 'Content-Type: application/json' -d '{}'
curl -fsS http://127.0.0.1:8001/api/runtime/control
# Independent Native, then wait for its returned assessment ID to finish:
curl -fsS -X POST http://127.0.0.1:8001/api/posture/assessments -H 'X-Product-Control: 1' -H 'Content-Type: application/json' -d '{"target_id":"moodle-local","mode":"PASSIVE_BASELINE","zap_enabled":false}'
# Independent STANDARD, then wait for its returned ID to finish:
curl -fsS -X POST http://127.0.0.1:8001/api/posture/assessments -H 'X-Product-Control: 1' -H 'Content-Type: application/json' -d '{"target_id":"moodle-local","mode":"STANDARD","zap_enabled":true,"authorized":true}'
# After actual fresh monitor windows exist, full assessment (same active monitor):
curl -fsS -X POST http://127.0.0.1:8001/api/multiagent/tasks -H 'X-Product-Control: 1' -H 'Content-Type: application/json' -d '{"scenario":"attack_replay","mode":"LIVE_LAB","zap_profile":"STANDARD","fresh_posture":true}'
```

Poll `/api/posture/assessments/{returned_assessment_id}` between independent jobs.
Poll `/api/multiagent/tasks/{returned_task_id}`; verify `result.live_snapshot.session_id`
against the active session's `session_manifest.json` and the monitoring control's
session folder. Check five completed specialists, exact window references and
verification/CQI limitations. The full task neither starts nor stops monitoring.

Cleanup: finish/cancel only owned jobs while the lease is valid, then:

```bash
curl -fsS -X POST http://127.0.0.1:8001/api/runtime/stop -H 'X-Product-Control: 1' -H 'Content-Type: application/json' -d '{}'
# Ctrl-C in the hold terminal; it verifies idle coursework tasks and ZAP queues.
# Confirm RELEASE VERIFIED only after cleanup succeeds, leaving coursework up:
/usr/bin/python3 -I -S scripts/coursework_lab.py restart-check
# If the controller crashed instead: after cleanup, run recover, then restart-check:
# /usr/bin/python3 -I -S scripts/coursework_lab.py recover
```

`recover` refuses a held kernel lock or active work; it never signals/restarts the
original. If cleanup cannot be verified, remain BLOCKED. After restart-check passes,
stop only coursework with Ctrl-C. **Original operator only**, not executed here:

```bash
cd /home/saintdomix/dissertation_model
.venv/bin/python -B scripts/start_cyberquality.py
```

Original backend 8000 / ZAP 8081 configuration stays unchanged. No UI/agent/CQI
change, original process manipulation, monitor or scan was performed in this update.


**Current: OFFLINE verified; real LIVE_LAB validation BLOCKED.** No separate live
approval was given, no lease/key configuration was created, no scan/monitor/tunnel
was started. All commands below are coursework-only unless explicitly marked
original-operator-only. Do not set a receipt to READY merely to pass a gate.

## Ubuntu: start, verify, stop — PASS offline

Prerequisites: mounted coursework disk, prepared `.venv-coursework`, port 8001
free. FastAPI serves the built React app; no separate frontend server is needed.

```bash
cd /mnt/assignment/cyberquality_multiagent
/usr/bin/python3 -I -S scripts/coursework_check.py --preservation --source-proof
/usr/bin/python3 -I -S scripts/assignment4_safety.py
/usr/bin/python3 -I -S scripts/coursework_lab.py status
# Only rebuild after frontend edits:
.venv-coursework/lib/python3.10/site-packages/playwright/driver/node demo/frontend/scripts/build_coursework.mjs
.venv-coursework/bin/python -I -B scripts/coursework_serve.py
```

Open `http://127.0.0.1:8001/`. Expected: model integrity VERIFIED; lab status LOCKED
without authorization. Stop only this foreground coursework server with Ctrl-C.
Never use original lifecycle scripts or copied PID files for coursework.
Read-only checks in another Ubuntu terminal:

```bash
curl --fail --silent http://127.0.0.1:8001/api/health
curl --fail --silent http://127.0.0.1:8001/api/coursework/isolation
curl --fail --silent http://127.0.0.1:8001/api/multiagent/official
```

Overview runs Full Assessment. One selected task persists across all four pages
and refresh. The branch-page source selector explicitly chooses full snapshot,
standalone/live, or accepted research. Only eligible Full Assessment completion
publishes official CQI; standalone actions never replace it. A failed attempt
shows the previous valid CQI separately with its original ID/date.

## Read-only readiness audit — performed, BLOCKED prerequisites remain

Receipt: `runtime/coursework/unified/readiness-audit.json`.

- Original PID 415036/backend 8000 remains running; status APIs reported no owned
  monitor or latest posture job. No original process was signaled.
- One Moodle TCP port-80 connection succeeded; no Moodle HTTP request was made.
  Apache log exists/readable; its contents were not consumed.
- Ubuntu has no `/home/saintdomix/.ssh/config`; no active SSH tunnel was observed.
- Kali address in repository: `192.168.226.129`. Account, installed ZAP version,
  loopback 8082 availability/authentication and scanner/spider/passive queues are
  **NOT VERIFIED**. Do not infer idle state from an Ubuntu port check.
- No verified external mechanism excludes competing original lab operations.
  A coursework flock cannot constrain the unchanged original application.
- Worker output-path mismatch is fixed to `runtime/coursework/behavioral_v2/ui-*`.
  Native PHP subprocess collection stays denied, and Moodle config is unreadable
  by this account: those Native checks may remain explicitly unavailable/partial.

There is no basis yet to request approval for a real live run. First resolve and
verify the missing Kali configuration and external exclusion arrangement. Present
that actual configuration, scope, commands and cleanup plan to the user for
**separate explicit approval**. Do not stop/change original services to obtain it.

## Kali ZAP / Ubuntu SSH / Windows — BLOCKED, not executed

On **Kali**, prerequisite inspection commands (read-only):

```bash
command -v zaproxy
ss -ltn 'sport = :8082'
```

Use a separate private coursework directory/Java temp directory and authenticated
API, bound only to Kali `127.0.0.1:8082`. The copied repository documents daemon
flags but its old example disables the key. A complete secure installed-version
startup/key-provisioning command is **not verified here**, so that unsafe example
is not reproduced. Have the operator verify the installed CLI/key mechanism and
exact owned shutdown procedure; never alter/reset the original 8081 session.

On **Ubuntu**, only after account/port/handoff verification, the derived tunnel
*template* is below. It cannot be copy-pasted until the missing authorized account
is supplied; no SSH alias or username was invented:

```text
ssh -N -o ExitOnForwardFailure=yes -L 127.0.0.1:8082:127.0.0.1:8082 <authorized-kali-user>@192.168.226.129
```

Expected: loopback-only owned tunnel to the authenticated coursework daemon.
Stop only this tunnel with Ctrl-C in its owning terminal. A separate port is not
permission for concurrent Moodle scans. **Windows:** the coursework Ubuntu SSH
connection/forward is unknown. Original Windows port 18000 is not coursework.
No speculative Windows command is supplied.

## Ubuntu: secure configuration and exclusive lease — implemented, live UNVERIFIED

Existing provider interface: `POSTURE_ZAP_API_ORIGIN`, `POSTURE_ZAP_API_KEY`,
`X-ZAP-API-Key`. Ambient POSTURE variables are still cleared. Instead, after the
actual isolated daemon/key setup is verified, use this private coursework loader:

```bash
cd /mnt/assignment/cyberquality_multiagent
/usr/bin/python3 -I -S scripts/coursework_lab.py configure-zap
```

Hidden input only; key is saved in `runtime/coursework/lab/zap-private.json`, 0600,
not Git, logs or argv. Origin is fixed to `http://127.0.0.1:8082`. Never print/cat
this file. No flag/checkbox grants ownership.

The controller requires a reviewed private `runtime/coursework/lab/readiness.json`
with actual `verified_at`, target/origin, `status: READY`, empty `blockers`, a
nonempty `external_exclusion_basis`, and verified true fields
`original_jobs_quiescent`, `external_exclusion_verified`, `zap_key_verified`,
`zap_8082_isolated`, `zap_queues_idle`, `apache_readonly_verified`. These are not
assumed by the program. The present BLOCKED audit cannot satisfy this contract.
The operator must establish/verify external exclusion; attesting idle ports alone
is insufficient. Receipt permissions must be 0600 and owned by the current user.

Only **after separate user approval of the exact operations/profile**:

```bash
/usr/bin/python3 -I -S scripts/coursework_lab.py authorize --seconds 1800
# In its own foreground Ubuntu terminal; keep it running:
/usr/bin/python3 -I -S scripts/coursework_lab.py hold --seconds 1800
```

`authorize` validates the reviewed receipt, records explicit typed approval and
profile, and hashes the receipt. `hold` takes an exclusive kernel lock, checks
original status read-only, and renews a finite lease heartbeat. It starts no lab
work. Maximum lease is three hours; stale heartbeat, expiry, wrong scope, competing
original work or missing private records fail closed. Keep the external exclusion
in force. Restart only coursework after acquisition so its existing services
load the approved LIVE_LAB configuration. No original restart is needed. STANDARD fits the default 1800-second grant;
FULL_AUTHORIZED needs a separately approved longer grant (for example
`--seconds 9000` on both authorize/hold). Existing scanner budgets are unchanged;
start is refused if remaining lease time cannot cover the profile and cleanup.

## Ubuntu: standalone monitoring / Native / ZAP — currently HTTP 423

Prerequisites: the approved lease above, application running in LIVE_LAB, permitted
read-only Apache input, verified owned authenticated ZAP for scanning. These use
existing independent controls, not new worker/scanner implementations:

```bash
curl --fail --silent http://127.0.0.1:8001/api/runtime/control
curl --fail --silent http://127.0.0.1:8001/api/runtime/status
# FUTURE authorized monitoring start / owned stop:
curl -i -X POST http://127.0.0.1:8001/api/runtime/start -H 'X-Product-Control: 1' -H 'Content-Type: application/json' -d '{}'
curl -i -X POST http://127.0.0.1:8001/api/runtime/stop -H 'X-Product-Control: 1' -H 'Content-Type: application/json' -d '{}'
# FUTURE independent Native (existing restricted, ZAP-disabled operation):
curl -i -X POST http://127.0.0.1:8001/api/posture/assessments -H 'X-Product-Control: 1' -H 'Content-Type: application/json' -d '{"target_id":"moodle-local","mode":"PASSIVE_BASELINE","zap_enabled":false}'
# FUTURE independently authorized STANDARD:
curl -i -X POST http://127.0.0.1:8001/api/posture/assessments -H 'X-Product-Control: 1' -H 'Content-Type: application/json' -d '{"target_id":"moodle-local","target_url":"http://192.168.226.132/moodle/","mode":"STANDARD","zap_enabled":true,"authorized":true}'
```

Success must show real process ownership and fresh session/windows for monitoring;
202/returned posture ID alone is not a successful scan. GET
`/api/posture/assessments/{assessment_id}` with the returned ID and inspect actual
provider coverage/execution. Cancel only that owned running ID using POST
`/api/posture/assessments/{assessment_id}/cancel`, with `X-Product-Control: 1`.
Do not truncate Apache or run a second monitor. None of these live operations was
tested; real local fixtures and gate behavior were tested instead.

## Ubuntu: full LIVE_LAB — currently BLOCKED with zero tool attempts

Prerequisites: approved lease/configuration; optionally an already active owned
monitor. **Monitoring does not start automatically.** Fresh Native/ZAP uses one
existing combined posture job; Behavioral consumes the current owned stream.
Without eligible windows, Behavioral is explicitly unavailable and existing CQI
policy decides partial scoring; no replay substitution occurs.

```bash
curl -i -X POST http://127.0.0.1:8001/api/multiagent/tasks -H 'X-Product-Control: 1' -H 'Content-Type: application/json' -d '{"scenario":"attack_replay","mode":"LIVE_LAB","zap_profile":"STANDARD","fresh_posture":true}'
```

`scenario` is required by the shared schema but live mode ignores replay selection.
Inspect returned task via `/api/multiagent/tasks/{task_id}`, `/assessment`, `/events`
and `/export`. Saved posture is optional only with `fresh_posture:false` and an
explicit eligible coursework `posture_assessment_id`; no failed fresh scan falls
back. Live uses bounded existing monitoring predictions/TreeSHAP, not new inference
in another process. Verify exact session/sequence/time/byte refs and CQI D1–D6.
The assessment never stops the monitor. Use the four pages for that same ID.

## Shutdown, release, original switch — pending authorized live verification

Finish or explicitly cancel owned scans **while the lease is valid**. Verify all
owned ZAP scan/spider/passive queues are quiescent; export/preserve evidence. Stop
only the coursework monitor through its API. Keep the idle coursework backend
running while pressing Ctrl-C in the lease-controller terminal, so it can verify
owned status, then type `RELEASE VERIFIED` only after real remote cleanup checks.
Finally stop the coursework backend and close only its tunnel/8082 daemon through
its verified owner controls. Never delete raw evidence or kill arbitrary PIDs.

On expiry/error the controller stops renewing permission and retains its lock
until quiescence is verified. If remote cleanup cannot complete, keep the lab
excluded and report BLOCKED; do not hand it back or forge RELEASED. An orphaned,
unreleased lease needs separately reviewed recovery, not an automatic takeover.
No acquire/release/live cleanup was claimed verified by fixture tests.

After verified release, the **original operator only** may use these unchanged
Ubuntu commands from `docs/productization/OPERATIONAL_CUTOVER.md`:

```bash
cd /home/saintdomix/dissertation_model
./scripts/demo_status.sh
# Only if not already running and the handoff is complete:
.venv/bin/python -B scripts/start_cyberquality.py
# Later, only when appropriate for the original operator:
./scripts/stop_demo.sh
```

Not executed here. Original backend 8000 and ZAP/tunnel 8081 remain unchanged.
Original Kali restoration credentials/session commands are unknown here; the
original startup does not create them. Do not use these commands for coursework.
