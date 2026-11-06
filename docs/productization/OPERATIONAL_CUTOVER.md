# CyberQuality operational cutover

Completed 5 November 2026, approximately 00:38 UTC+5
(`2026-11-04T19:38:00Z`). No model, scanner policy or CQI policy change.

## Active application

- Normal owned FastAPI application on `127.0.0.1:8000`, PID 413331 at acceptance.
- Windows access through the existing SSH forward: `http://127.0.0.1:18000/`.
- `LIVE_LAB`, `preview_read_only=false`; real implementations, no fixture/proxy.
- Serves `demo/frontend/preview-final-stabilization-20261104` directly. The
  original `demo/frontend/dist` and all original Git checkpoints are unchanged.
- Original backend and its owned monitor stopped gracefully. The read-only
  18010 candidate stopped through its dedicated controller. ZAP/tunnel preserved.
- Retained journal: `runtime/behavioral_v2/ui-9ee55834f3504d568af5a3b2e413f4a4`.
  Acceptance read 18 observations and four episodes; no new monitor was started.
  A retained journal is not evidence of active monitoring. D6 remains unavailable
  when relevant telemetry is stale. No assessment or attack was executed.

Start after reboot from the repository:

```bash
cd /home/saintdomix/dissertation_model
.venv/bin/python -B scripts/start_cyberquality.py
```

The wrapper decrypts existing protected startup settings in memory and invokes
the original owned demo lifecycle with an explicit retained session. It verifies
final frontend hashes, refuses duplicate owned startup, and never starts a
monitor automatically. Private configuration is
`runtime/demo_control/cyberquality_startup.json`; no key is committed or printed.

Status and stop use the existing scripts:

```bash
./scripts/demo_status.sh
./scripts/stop_demo.sh
```

Stopping closes only this backend's owned monitor, if an operator later started
one. Do not stop while an assessment is running. Inspect/finish or explicitly
cancel the owned job first. No automatic system-service registration was added.
The existing Kali runtime and tunnel must be restored separately after reboot
before scanning; startup does not create or alter them.

## Verification

Receipts and screenshots: `/tmp/final_operational_cutover/`.

- Focused launcher/lifecycle/profile/fake-monitor tests: 28 passed.
- Port-probe/launcher regression after the diagnosed correction: eight passed
  (seven overlap with the first run; one new port-probe test).
- Two explicit cancellation tests use isolated fake jobs.
- Actual GET-only API acceptance: 10 groups; real posture/history, explanations,
  SHAP, CQI v1/v2, all six dimensions, benchmarks, normalization and reports.
- Actual browser: eight groups, seven destinations, desktop and 768px; no fixture
  responses, mutating/foreign requests or JavaScript errors.
- Profile options and authorization-gated enablement verified without submitting
  an assessment. Monitoring start enabled; stop disabled with no owned monitor.
- Frozen Behavioral root:
  `59a8c7c5d3d51632d0afe45f8cd2fe50570b7af2943d26bb313888327ea9f436`.

Initially the lifecycle port probe rejected normal TCP TIME_WAIT sockets following
shutdown. The original recovery helper's conservative bind guard also rejected
them; neither attempt started a backend. `demo/preflight.py` now uses SO_REUSEADDR
as Uvicorn does. A separate real-listener test verified an existing listener still
cannot be replaced. The subsequent single launch passed core/API/browser checks.
The original recovery helper remains unchanged and needs the cooldown below.

Real new scans, scan cancellation, attacks and monitoring start were **not**
executed. Control dispatch/cancellation/duplicate prevention were tested with
fakes. The first sandboxed ASGI test run stalled after 24 passing tests; the
unrestricted focused run passed all 28. No application process was signaled by
that test-runner interruption.

## Original version recovery

The already verified package was relocated, without duplicating it, from temporary
storage to the persistent directory:

`/home/saintdomix/dissertation_checkpoints/pre_cutover_recovery_20261104T185418Z`

Its encrypted archive/key checksums remain unchanged and match the Windows copy
confirmed by the operator. The tagged source, original assets and SQLite-safe
backup passed the previous cold restoration check (487 hashes; 16 GETs).
This is not a VM backup; the installed environment and canonical evidence remain
prerequisites. No research database is restored as part of a source rollback.

When no posture job is running, execute:

```bash
cd /home/saintdomix/dissertation_model
./scripts/stop_demo.sh
# The unchanged original recovery guard requires TIME_WAIT sockets to expire.
sleep 65
recovery_root=/home/saintdomix/dissertation_checkpoints/pre_cutover_recovery_20261104T185418Z
.venv/bin/python -B "$recovery_root/payload/original_root/restore_original.py" \
  --operational --data-root "$PWD" \
  --retained-session runtime/behavioral_v2/ui-9ee55834f3504d568af5a3b2e413f4a4 \
  --key-file "$recovery_root/RECOVERY.key"
```

This launches the actual original exported source/assets in the foreground on
loopback 8000, using existing canonical evidence and journals. It refuses occupied
8000/18010 ports, verifies original source hashes, and does not adopt/start a
monitor. Stop it using Ctrl-C. It is not the new managed launcher's process; do
not use stale PID records as authority over it. Keep ZAP/tunnel running.

Verify `/api/health`, `/api/model`, `/api/posture/assessments`,
`/api/application/snapshot?mode=LIVE_LAB`, `/api/cqi`, `/api/cqi/v2` and the original
asset hashes in `payload/LIVE_PROCESS_INVENTORY.json`.

The full operational original restoration was not completed during this cutover;
its read-only cold path passed previously. The initial attempted rollback stopped
at the port guard before application initialization. Never overwrite newer
journals with the older recovery snapshot, and never force Git changes to restore
the UI. Source/build recovery and data recovery are separate operations.
