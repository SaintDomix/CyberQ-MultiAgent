# Parallel defense candidate — actual backend, read-only operations boundary

4 November 2026. No production cutover, new scan, attack, training or monitor
operation was performed. Existing source archives and recovery references remain.

## Running service

URL: **http://127.0.0.1:18010/**. Final running PID: **409991**, start ticks
37099479 (verify current ownership with the status command; do not trust an old
PID by itself). Initial PID409659 was deliberately stopped for the fallback test.

```bash
cd /home/saintdomix/dissertation_model
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -B scripts/defense_candidate.py status
```

Startup, only when this candidate is stopped:

```bash
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -B scripts/defense_candidate.py start --retained-session runtime/behavioral_v2/ui-9ee55834f3504d568af5a3b2e413f4a4
```

Stop **only this candidate**:

```bash
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -B scripts/defense_candidate.py stop
```

The startup command rejects duplicate ownership or an occupied port. It uses
one worker, no reload, loopback-only bind and the already verified assets at
`demo/frontend/preview-final-stabilization-20261104`. No frontend was rebuilt.
No new virtual environment, dataset/model copy or writable runtime link was made.

## What is real, and what is deliberately blocked

This is **not** the EvidenceStore/JournalReader UX fixture adapter. It constructs
the normal `Application`, `PostureAssessmentOrchestrator`, real Native/ZAP
provider classes and `LiveControl`, then mounts the normal `create_app` routes
and verified frontend. It does not proxy port8000. Source findings, numerical
explanations, SHAP evidence, incidents, comparisons and CQI calculations come
from the real application services and actual retained evidence.

It is **not a fully operational assessment backend**. Operational authorization
is absent. The existing read-only API/UI capability disables every mutating
request. Scanner readiness GETs are explicitly NOT_PROBED rather than calling
ZAP or falsely claiming availability. Saved scanner results still use the real
hash-verified history. `/api/candidate/status` identifies exact implementations,
boundaries, ownership, source paths and policy, without secrets.

| Feature | Candidate availability / verification |
|---|---|
| Seven pages and source selection | Functional, read-only; actual browser verification |
| Native/ZAP findings, provenance, dedup and history | Functional, read-only; actual saved assessments |
| STANDARD/FULL_AUTHORIZED/PASSIVE_BASELINE | Implementations preserved; all three displayed; execution BLOCKED |
| Job progress and cancellation | Saved stage/progress accessible; no candidate-owned job; cancellation BLOCKED; prior fake-route tests preserved |
| External Behavioral journal | Functional, read-only; no monitor adoption |
| Accepted BENIGN/attack replay | Functional, explicitly labelled saved evidence |
| Numeric explanations and SHAP | Functional from actual saved inference evidence |
| CQI v1/v2, D1–D6, coverage, comparison | Functional real computation; partial/unavailable remains visible |
| Benchmark/XGBoost evaluation | Functional hash-bound accepted measurements |
| Normalization | Schema and accepted generic capability example functional; new-input POST diagnostics BLOCKED |
| Reports | Real final v2 Markdown/JSON and historical v1 report accessible |
| Scanner reachability/readiness | UNVERIFIED in this candidate; deliberately not probed |
| Monitor start/stop, ZAP session creation/scans | BLOCKED; no real operational acceptance claimed |

## Isolation audit

- `Config` is explicitly LIVE_LAB with an existing journal, not the normal demo
  launcher path that can automatically start a monitor. Never use the shared
  `runtime/demo_control` launcher to manage this parallel candidate.
- Native/ZAP/validation constructors only initialize in-memory objects/catalogs.
  No worker starts until an operation is requested; all such requests are denied.
- `LiveControl.process=None`, empty owned-job registry and no scanner ownership.
  Shutdown only closes this unowned controller; it cannot adopt the external PID.
- SQLite uses the existing reader's `mode=ro`, `query_only=ON`, bounded connection
  timeout and short consistent read transaction. No migration, DB creation,
  journal rewrite or observation/incident emission occurs.
- Reports, model artifacts, accepted matrices and snapshots are read; CQI and
  explanation caches are in memory. No report generation or fitting is invoked.
- All writable process/control state is private `/tmp/cyberquality-defense-18010/`
  (PID identity, lock, log and disposable temporary files), not repository runtime.
- A process-local Python audit boundary rejects repository file writes, writable
  SQLite connections, child processes, outbound sockets, external signals and
  links. Only this exact loopback port may bind. It is defense in depth for
  reviewed code, **not an OS sandbox for malicious native extensions**.
- urllib3's optional IPv6 import probe on ::1:0 is blocked and caught by urllib3;
  its recorded bind denial is expected. The restriction was not relaxed.
- Child environment removes ZAP ownership/key/origin and active-validator context;
  it sets PRODUCT_FACTORY_ONLY=1, PYTHONDONTWRITEBYTECODE=1 and single-thread
  numerical limits. The writable TMPDIR is private. No key value is persisted.
- No writes to existing data/, outputs/, evidence/, runtime/ or models are
  authorized by this candidate. Incoming GETs are served normally; outgoing
  connections (including to port8000/ZAP/Moodle) are blocked.

## Evidence actually inspected

Current saved STANDARD assessment:
`posture-20261104T174900Z-1832a468e4f8`, 117 canonical finding/control rows with
NATIVE_POSTURE, ZAP_PASSIVE and ZAP_ACTIVE provenance.

Real external monitor journal:
`runtime/behavioral_v2/ui-9ee55834f3504d568af5a3b2e413f4a4`;
session ID `0ba38716abf24d639061da99cc2d4e76`, 10 observations and 3 saved episodes
at validation time. External monitor PID408997 is owned by the existing service,
not the candidate. Journal process state remains EXTERNALLY_MANAGED_UNKNOWN in
the candidate: it does not infer ownership or active threat status from a DB.
The existing monitor may continue updating its own checkpoint independently.

The inspected UNKNOWN_ANOMALY observation
`de4e4bfffee640cfd25090c39f87090e7e2a28da02ab7ddf749e947fb22837eb`
has actual classifier observation ENUMERATION_RECONNAISSANCE and AVAILABLE SHAP.
Reconciliation remains UNKNOWN; no known attack is invented.

Current CQI: conditional45.00, coverage42.8785%, conservative0. D5/D6 are
insufficiently evidenced at the scoring time; 3 historical episodes do not
establish current activity. Accepted benign replay: 33 windows/6 runs/0 episodes,
conditional49.7302, coverage51.7495%. Accepted attack replay: 68 windows/14 runs/
16 episodes, conditional21.5625. Runs and episodes are different units.
No accepted metric, timestamp, feature or prediction was rewritten.

## Acceptance and verified immediate fallback

- 72 focused isolation/integration/regression tests passed: 27 new boundary/
  real-backend cases, 17 C2 cases and 28 final API cases.
- 34 actual GET requests passed 10 integration check groups.
- Actual Chromium: 8 check groups, all seven destinations, no fixtures, no
  foreign requests, no mutations and no JavaScript errors.
- Browser inspected real findings, profiles (disabled), live explanation/SHAP,
  episodes, accepted benchmark, XGBoost matrix, CQI v1/v2, normalization and reports.
- Stop test: only PID409659 was stopped. Original backend389143, tunnel392381
  and monitor408997 retained identical start ticks. Port8000 remained healthy.
  The same candidate was then restarted as409991. No source rollback occurred.
- Frozen Behavioral root remains
  `59a8c7c5d3d51632d0afe45f8cd2fe50570b7af2943d26bb313888327ea9f436`.
- Existing 451 protected hashes and stable/Phase B/C2/final asset manifests are
  rechecked; current external journal is read-only, not copied or rewound.

Receipts/screenshots are under `/tmp/cyberquality-defense-validation/`, outside
scientific artifact directories. They are disposable and may be lost on reboot.
New source files: `demo/backend/defense.py`, `scripts/defense_candidate.py`,
`scripts/validate_defense_browser.py`, `tests/test_defense_candidate.py` and this
document. Existing reviewed stabilization sources are unchanged. No commit,
tag, branch, original asset replacement or large build was made in this task.

Initial test corrections concerned existing field names and runs vs episodes;
no evidence was altered. A validator used classifier denominator name total;
it was corrected to the actual support field. Startup guards were tested before
launch, including a separate process with actual backend imports and journal read.

## Defense flow (no operational actions)

1. Open18010; explain conditional quality, coverage, conservative assumption and
   D5/D6 gaps. Identify saved assessment and collection time.
2. Security posture: important weaknesses, verification, Native/ZAP sources,
   canonical grouping, details and source remediation. Profiles remain visible
   but disabled. Do not click controls on the original service during the demo.
3. Behavioral monitoring: inspect the actual journal's UNKNOWN example and its
   numeric benign reference/SHAP; distinguish window, classifier and episode.
4. Change evidence to accepted replay: benign false-alert improvement, then saved
   attack-pattern evidence/episodes. Explicitly say these are accepted replay,
   not newly generated live traffic or successful exploitation.
5. Model & research: KEEP_OCSVM comparison65/68,41/68,3/68; separate XGBoost
   matrix99/101; sample support and limitations.
6. Quality: D1–D6, contributors/missing evidence, historical comparison and legacy
   v1 sensitivity. Do not mix policy versions or call CQI an attack probability.
7. System: generic normalization/capability limits, model integrity and reports.

If anything fails, close the candidate tab and open **http://127.0.0.1:8000/**.
Optionally run only the candidate stop command above. This immediate fallback
was tested; no source rollback is needed.

For a future deployment/source rollback, retain all checkpoints, final source
patch/archive, separately backed-up original dist and consistent external runtime/
VM backups. Follow `DEPLOYMENT_AND_ROLLBACK.md` only after separate approval;
Git alone does not restore running processes, databases or untracked evidence.
Never switch source while these services are using it casually: late imports and
static files still depend on disk. This task authorizes no cutover or rollback.

## Before any real operation

Separate operator authorization, target/scope review, dedicated scanner/session
ownership and isolated writable assessment/monitor state are required. Do not
simply remove the read-only guard or copy the original daemon's API credentials.
Real scan/cancel/monitor behavior was not tested here, and remains unverified for
this parallel process. Operational readiness and wider LMS accuracy are not claimed.
