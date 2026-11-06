# M5 finalization: scoped acceptance and passive saved-model runtime

The frozen candidate is copied into `outputs/branch2/accepted_behavioral_v2/`.
Neither the candidate nor accepted Model v1 is replaced. The explicit decision
and fresh evidence are in `outputs/branch2/m5_final_day/fresh_attack_holdout_01/`.

The existing protocol specifies a qualitative research promotion decision, not
an automatic numeric threshold. Decision A is scoped to the current local Moodle
laboratory: both packages detect all fourteen fresh attack runs, with two out of
two in each class, while the locked six-session benign evaluation shows no
candidate episode alerts and six alerted sessions for v1. Full window mistakes,
raw classifier mistakes and novelty-only results remain in the JSON metrics.
No model setting was changed after the blind test or attack holdout.

Six benign student-role protocols and two controlled runs per attack class do
not establish statistical significance, population accuracy or generalization
to other LMS platforms. Controlled repeats are not independent real users.
Human replication and genuinely unseen attack-class validation remain future
work. SQLI/XSS/PATH classes indicate URL-visible attempts, not exploitation.
Apache combined logs do not expose POST bodies. Novelty and XGBoost scores are
uncalibrated; explanations are not causal.

## Accepted package

`accepted_manifest.json` hashes every packaged artifact, records the unchanged
candidate canonical root, configuration, schema, adapter and dependency metadata,
and binds the original inference source files. Its canonical root excludes its
own `root_sha256` and derived `package_id`. The manifest does not hash itself.
`model/` is a byte-identical copy of the saved frozen package: OCSVM cutoff,
XGBoost, reference/scalers, confidence threshold 0.8 and persistence two.
Development and fresh acceptance metrics are copied separately. This trusted
local joblib package is not an upload format for untrusted models.

Startup verifies the manifest and all files before source consumption. A corrupt
model/config/schema/code binding fails closed. Runtime also monitors file
identity/stat continuity; it does not refit, recalibrate or select thresholds.

## Passive runtime

`behavioral_runtime.live.LiveEngine` subclasses the existing M2D engine. It uses
the original incremental `AppendReader`, byte anchors, SQLite observation journal,
crash recovery, parse/late-event bounds, polling, graceful stop and run loop.
Only package/bootstrap identity, 83-feature extraction and saved prediction
serialization differ. The original fixed-65-feature initializer cannot accept
an 83-column package; it is not bypassed by pretending schemas match.
All frozen Branch 1/Branch 2/Fusion/reporting sources remain unchanged.

The path is: append-only Apache records → existing parser → frozen platform
adapter → epoch-aligned complete ten-second windows → frozen 83 features →
saved OCSVM plus XGBoost → frozen reconciliation → durable observations →
frozen episode policy → durable incidents.

`predictions.jsonl` contains observations (`observation_id`, sequence, novelty
score/state, classifier and uncalibrated score, disagreement, provenance and
accepted package identity). `windows.jsonl` retains numerical features and
source byte ranges/hashes, never raw requests, passwords, cookies, query values,
referrers, raw user agents or POST bodies. Source client and user-agent IDs use
the original hashes. The original log remains a source and is not modified.

`incidents.json` is an atomic projection of separate SQLite incident records.
Same client/user-agent/session, same reconciliation class, exactly adjacent
ten-second windows form an episode. Gaps/class changes separate episodes.
UNKNOWN observations require two contiguous windows to escalate. A lone UNKNOWN
stays visible as an observation; confident known-attempt classification can
alert immediately, exactly as in the frozen policy. BENIGN and UNCERTAIN do not
become incidents. Observation is not incident, and neither proves exploitation.

Incident IDs are stable for session/model/client/agent/class/start. Extending an
episode updates its existing membership, not a second incident. The episode
cursor and updates commit together in the original journal database. On restart,
an observation committed before episode processing is replayed once. Missing
JSON projections are restored from the authoritative journal. Rotation,
truncation, corruption, changed source/model/config or unsafe resume fails closed;
there is no automatic reset. An exclusive session lock prevents two writers.

Runtime output is confined by the CLI to a fresh directory beneath
`runtime/behavioral_v2/`. It is not accepted research evidence. First start begins
at EOF and omits the current partial ten-second interval; restart requires
`--resume`. Stop with Ctrl-C; open windows remain checkpointed, not force-closed.

```bash
cd /home/saintdomix/dissertation_model
.venv/bin/python -B scripts/run_behavioral_v2_live.py run \
  --source /var/log/apache2/access.log \
  --out runtime/behavioral_v2/demo_01
```

Resume the exact same source/config/package with:

```bash
.venv/bin/python -B scripts/run_behavioral_v2_live.py run \
  --source /var/log/apache2/access.log \
  --out runtime/behavioral_v2/demo_01 --resume
```

These are operator commands, not executed during finalization. Log read
permission must already exist; do not run the model as root merely to bypass
permissions. No traffic generator, network client or dashboard is started.

## Offline acceptance

`scripts/verify_behavioral_v2_replay.py` guards fitting and network APIs. It
feeds copies of all fourteen locked attack logs through the incremental engine
in temporary directories, matches saved candidate decisions and scores (absolute
numeric tolerance 1e-12), then stops/resumes and checks unchanged observation and
incident identities. Saved benign features and observations are replayed without
reopening the real Apache log or replacing locked benign metrics. Synthetic tests
cover isolated/persistent UNKNOWN, known attempts, continuity failures, privacy,
corrupt packages and crashes between observation/episode/checkpoint commits.

The write-once `live_engine_acceptance.json` records actual outcomes. This replay
is runtime acceptance, not another independent held-out evaluation or a new
prospective real-time deployment experiment. The source scoring, feature policy,
Fusion/CQI and UI are unchanged.
