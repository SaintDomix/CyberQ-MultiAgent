# M2D passive near-real-time Branch 2 inference

M2C is frozen at 5db35a6 / milestone-2c-final-offline. M2D is deployment-style
inference on NEW observations, not training, threshold selection, a new accuracy
experiment, Fusion or CQI. No live host log or traffic was used during coding.
Frozen Dataset v2/model files are not modified. The offline M2C limitation remains:
all three B04 authenticated benign navigation runs were TRAIN, so held-out benign
metrics did not independently validate that scenario. Controlled attempt classes
and live model labels do not establish exploitation or confirmed compromise.

## Architecture and fixed semantics

`live_reader.py -> adapters/apache.py -> windowing.py -> features.py -> saved
inference.ModelPackage -> reconciliation/explanations -> live_storage.py`.
`live.py` coordinates those reusable components; `run_branch2_live.py` is only the
CLI. ModelPackage was moved unchanged to inference.py; models.py re-exports it
for offline callers. The artifact loader imports inference.py so live imports do
not load the project training modules. No live path calls fit/train/select/evaluate.
Only frozen outputs/branch2/m2c_final_01 is selectable through the CLI. Its loader
checks every package file hash, exact feature order and schema compatibility.
The live runtime additionally pins 65 features, 10 seconds, eight saved classes,
confidence 0.80 and schema hash
7f938a6f076339108cbf26e4a37c6f4aff0fe85836f44187b3dcf18b93692417.
Loaded estimators/reference/thresholds stay in memory; no hot swapping occurs.
Model-file stat identity is monitored during polling; changes fail closed.

Apache combined parsing is reused, including its UTF-8 replacement policy and
canonical missing-data semantics. POST bodies, Moodle sessions and roles are not
invented. Only the Dataset v2 loopback OPTIONS * Apache internal-dummy signature
is excluded; foreign/server traffic is NOT filtered. In deployment other genuine
traffic is observed too: controlled attribution requires a quiet lab.
Raw queries/referrers/UAs are transient only. Outputs contain numerical features,
existing client/UA digests, byte ranges and record hashes. The adapter's sortable
provenance ordinal is byte_start+1, explicitly not an asserted absolute Apache
line number; counting pre-start history is unnecessary. Per-window source_sha256
is a digest of ordered byte-range/record-hash observations, not a whole-file hash.

## Reader, cold start and windows

First start requires a NEW session directory and seeks current EOF. If EOF splits
an old record, its appended remainder through newline is explicitly discarded/
audited; it is not invented as a new complete request. The first eligible aligned
window starts at ceil(session-start UTC / 10 seconds). The partial startup interval
is excluded and counted. At an exact UTC boundary that interval is eligible.
No minimum count beyond NONEMPTY is imposed; quiet windows produce no predictions.

Reader polls binary records, retaining the cursor at an unfinished trailing line.
The loop defaults to 0.5 seconds, finalization grace 2 seconds. A window closes
only after its fixed end plus grace, and only after the current complete-byte
backlog is drained. An unfinished trailing line pauses finalization because its
unknown timestamp could belong to a pending window. Inference never force-closes
an open window on shutdown. Window grouping uses the existing UTC epoch alignment,
client ID and UA digest. The saved feature map is transformed into a vector in the
saved schema's exact order; there is no live feature subset or new predictor.

Poll interval bounds: 0.05–10s. Grace: 0–30s. Optional duration: 0.1–86400s. Reads
are capped at 4MiB/poll, each line at 256KiB, pending observations at 100000 events
and 16MiB of source records. Excess bounds fail closed, not evict unprocessed data.
Future timestamps beyond 60s and backward wall-clock movement fail closed. Host
clock synchronization and reasonable completion/logging delays are prerequisites.

## Checkpoint and output durability

A single-writer flock protects each session. Immutable session_manifest.json holds
initial EOF/start/source/model/schema/configuration identities. checkpoint.json
is written via a same-directory temporary, flush+fsync, atomic replace and directory
fsync. It records engine version/session ID, source device/inode/path, source safe
replay offset, observed byte high-water/size, bounded SHA-256 continuity anchors,
model/schema IDs, 10s window size, finalized watermark, counters and sequence.

The safe offset is at/before the earliest pending observation OR any unacknowledged
reader batch. Thus interruption after reading but before parsing is replayable.
Pending canonical/raw state is not written: it is reconstructed from the source.
Counters have a separate consumed-offset high-water to avoid double-counting replay.
Repeated resumes before processing retain the original read high-water. A source
prefix is not continuously re-read; 4KiB anchors at initial/safe/read positions
check continuity alongside device/inode/observed size. This is append-only source
continuity checking, not a cryptographic guarantee against a malicious host that
rewrites unanchored history or truncates/regrows identical bytes between polls.

The durable SQLite journal (standard library, synchronous FULL transactions) stores
one envelope containing finalized features AND prediction per deterministic record
ID. ID includes persisted session ID, source identity, window start, client/UA and
model identity; it does not change on process restart. JSONL projections are written
and fsynced before checkpoint advance:

- windows.jsonl: finalized compatible feature rows and hashed byte provenance;
- predictions.jsonl: saved IF/XGB/reconciliation/explanation, sequence/provenance,
  actual processing time and emission delay;
- audit.jsonl: safe start/resume/shutdown, exclusions, failures and integrity events;
- latest.json: atomic convenience view, never authoritative history;
- journal.sqlite3: authoritative transactional envelopes/idempotence index;
- checkpoint.json: atomic durable replay state;
- integrity_fault.json: durable automatic-resume prohibition after a runtime fault;
- latency_summary.json and session_summary.json: atomic session summaries.

A crash after journal/output persistence but before checkpointing replays bytes.
Existing matching records are not inferred/appended again. A crash between journal
commit and complete JSONL suffix writes is recovered by appending ONLY missing
projections. Previously completed observations interleaved behind pending ones
are skipped only when their exact byte-range/hash membership is proven by the
journal. Changed replay content or a new event in an irreversibly closed window
fails closed. Empty intervals also advance the closed watermark; late records in
those intervals are integrity faults. No historical prediction is mutated.

Torn/corrupt JSONL output, journal mismatch or irrecoverable filesystem failure
blocks automatic resume. No torn history is truncated/deleted to hide a fault.
A crash before initial manifest/checkpoint completion also requires inspection.
SQLite and projections must remain together with the source/manifest/checkpoint.
Do not copy just predictions.jsonl and claim resumability. Ensure sufficient disk
space; disk-full/fsync failure cannot promise availability, but does not silently
advance a checkpoint. Small metadata/stat checks are not tamper-proof signatures.

Source rotation/device/inode replacement or detected truncation/anchor mismatch
fails closed. There is NO reset-to-EOF/zero and NO automatic logrotate handover.
Pause/stop before planned rotation and review continuity before a separately named
new session. A session checkpoint marked FAULT or a persisted integrity_fault.json cannot be resumed automatically, even if source failure prevented a new checkpoint. Restoring old source bytes does not silently clear the known fault.
Do not delete old evidence or silently clear a fault to make acceptance pass.

## Bad records, explanations and latency

Malformed complete lines are audited by byte range/hash and a fixed safe reason;
raw text/exception contents are never copied. No event is invented. The default
bounded policy permits ten cumulative malformed lines per session, then stops.
Within that bound offsets remain provable and failures remain counted. This
matches Dataset v2's parser failure accounting with an additional runtime bound.
No broad foreign/dummy filtering is added. Large/unclosed records also fail at
explicit bounds. Report nonzero failures when reviewing deployment completeness.

Explanations are enabled by default: stored TRAIN-BENIGN robust reference and exact
TreeSHAP via the unchanged final prediction path. Python SHAP's XGB loader remains
incompatible; native exact XGBoost TreeSHAP checks raw-margin additivity and records
backend/status/causal=false. Missing/incompatible explanations are explicit, audited
and counted; valid predictions may remain. --no-explain is a diagnostic flag and
must also be repeated on resume for that session; robust deviations still exist.
Scores are UNCALIBRATED confidence, never calibrated attack probability or causality.

processing_duration_ms uses perf_counter around feature construction and model/
reconciliation/explanations; it excludes artifact-write time and one-time model
loading. window_close_to_emission_ms uses actual UTC emission minus logical end:
it includes intentional grace/poll/backlog/processing delay. Apache timestamps
are second-resolution REQUEST timestamps; delayed log completion can cause a
late-event integrity fault. Startup explanation imports can be slow and are
included in the first processing measurement. No instant detection is claimed.
Summary count/min/median/p95/max/mean uses recorded values, with SQL-backed exact
quantiles and no retained historical event list. Fixture artificial wall-clock
advancement is NOT measured lab window delay or new test-set accuracy.

## Commands and later manual acceptance — NOT executed during coding

Ubuntu preflight (source of truth):

```bash
cd /home/saintdomix/dissertation_model
git rev-parse HEAD
git tag --points-at HEAD
git diff --check
# Starting code milestone was 5db35a6 / milestone-2c-final-offline;
# review M2D working changes separately; no automatic commit is required.
test -r /var/log/apache2/access.log
.venv/bin/python -B -c "import sys; sys.path.insert(0,'src'); from branch2.artifacts import load; p=load('outputs/branch2/m2c_final_01'); print(p.feature_schema['sha256'],len(p.classes),p.reconciliation['confidence_threshold'])"
.venv/bin/python -B -m unittest discover -s tests -p 'test*.py' -v
```

Keep unrelated browsers/scanners quiet for controlled attribution; prevent rotation
through the bounded acceptance interval. Use a NEW output directory and confirm
source EOF in the created manifest; do not mistake old Apache history for live.

```bash
# First start (foreground, indefinite; stop with Ctrl+C).
.venv/bin/python -B scripts/run_branch2_live.py run --source /var/log/apache2/access.log --model outputs/branch2/m2c_final_01 --out outputs/branch2/live/m2d_live_01

# Alternative bounded first start; select this OR the command above, not both.
.venv/bin/python -B scripts/run_branch2_live.py run --source /var/log/apache2/access.log --model outputs/branch2/m2c_final_01 --out outputs/branch2/live/m2d_live_01 --duration 180
```

In a second Ubuntu terminal, inspect the first-complete-window boundary and wait
until it before ordinary browsing (this prints no request secrets):

```bash
.venv/bin/python -B -c "import json,time; p=json.load(open('outputs/branch2/live/m2d_live_01/session_manifest.json')); print(p['start_offset'],p['first_complete_window_start_epoch']); time.sleep(max(0,p['first_complete_window_start_epoch']-time.time()))"
```

BENIGN activity: manually open Moodle home and course listing in the authorized
lab browser (http://192.168.226.132/moodle/ and /moodle/course/index.php). Optionally
navigate normally under authorized login; do not use the security report because
it launches nested probes. Wait until its 10s interval closes plus 2s grace and
poll/processing time. Check predictions.jsonl/terminal; a BENIGN protocol does NOT
guarantee the model's prediction is BENIGN. Inspect actual decisions honestly.

Then ONE safe suspicious M2B pattern on Kali: query-visible inert SQLI_ATTEMPT.
It uses fictitious marker text in ignored b2_lab_* GET parameters, no extraction,
no authentication bypass, no database write or destructive query. Existing M2B
bounds/scope enforce serialized low-volume requests; this is not an exploit.
Existing capture coordination remains separate from live inference. All new
capture roots/IDs must be unused (choose a different reviewed ID if already used).

```bash
# Kali worker only; synchronize Ubuntu source without --delete.
cd ~/dissertation_model
rsync -a saintdomix@192.168.226.132:/home/saintdomix/dissertation_model/src/branch2/capture/ src/branch2/capture/
rsync -a saintdomix@192.168.226.132:/home/saintdomix/dissertation_model/scripts/run_branch2_capture.py scripts/
rsync -a saintdomix@192.168.226.132:/home/saintdomix/dissertation_model/experiments/branch2_lab_context.template.json experiments/
.venv/bin/python -B scripts/run_branch2_capture.py run --seed 42 --run-offset 60 --only-run-id SQ01-run61 --dry-run
.venv/bin/python -B scripts/run_branch2_capture.py run --seed 42 --run-offset 60 --only-run-id SQ01-run61 --authorized --ssh-host saintdomix@192.168.226.132 --capture-root evidence/branch2_captures/m2d_sqli_acceptance01
```

Start the controlled capture only after earlier BENIGN requests have flushed and
while the live engine is running. No credentials are needed for this GET-only
pattern. No full 68-run capture or model training is proposed. On Ubuntu wait
for the final interval plus grace, then inspect actual outputs and captured QA:

```bash
.venv/bin/python -B scripts/run_branch2_capture.py verify --root evidence/branch2_captures/m2d_sqli_acceptance01
.venv/bin/python -B -c "import json; p=json.load(open('outputs/branch2/live/m2d_live_01/latest.json')); print(p['record_id'],p['reconciliation'],p['shap_explanation']['status'],p['shap_explanation'].get('backend'),p['processing_duration_ms'])"
```

Stop the foreground engine with **Ctrl+C** (or let bounded duration finish).
Checkpoint must retain any still-open observations. Resume the SAME source/model/
configuration explicitly, without changing grace or explanation settings:

```bash
.venv/bin/python -B scripts/run_branch2_live.py run --source /var/log/apache2/access.log --model outputs/branch2/m2c_final_01 --out outputs/branch2/live/m2d_live_01 --resume --duration 30
.venv/bin/python -B -c "import json; from pathlib import Path; r=Path('outputs/branch2/live/m2d_live_01'); a=[json.loads(s) for s in (r/'predictions.jsonl').read_text().splitlines()]; assert len(a)==len({p['record_id'] for p in a}); print(json.load(open(r/'session_summary.json'))); print(json.load(open(r/'latency_summary.json')))"
```

The manual acceptance establishes append ingestion, exact feature/schema reuse,
saved prediction/reconciliation/explanation, restart continuity and measured
near-real-time latency. It is not a new held-out accuracy measurement, population
validation, generalization proof, live training or evidence of successful attack.
Integrity faults, nonzero bad-line counts, unavailable explanations, source
rotation or unresolved capture-agent state must be reviewed before acceptance.


## Implementation verification (temporary fixtures only)

Starting HEAD: 5db35a66ea95a9fce692c7877df81f9694518f28,
tag milestone-2c-final-offline. Baseline 251 tests; completed suite 295 tests,
all passing. The real final package fixture used temporary append-only logs,
first-start EOF, three complete windows and explicit resume. Three unique
prediction records remained byte-identical after resume; fit/network calls were
guarded at zero. All three explanation backends were
XGBOOST_NATIVE_EXACT_TREE_SHAP, status AVAILABLE, with robust deviations.

Measured fixture processing (perf_counter, milliseconds, n=3): min 71.038,
median 72.085, p95 1406.304, max 1554.551, mean 565.891. The first observation
includes cold explanation initialization. These are one temporary-fixture run,
not real Moodle latency, a performance benchmark, or new accuracy metrics.
Wall-clock progression was artificial; its window-close delay must NOT be
presented as measured lab delay. Manual acceptance remains unexecuted.

All 623 protected files across final M2C package, final Dataset v2, capture roots
and historical/imported data/raw were verified byte-identical after tests.
ModelPackage's moved implementation is byte-identical to the original class.
No real Apache log was opened, no traffic generated, no models retrained and no
Git commit made. Source continuity limits and operational prerequisites above
must be reviewed before the later authorized lab acceptance.
