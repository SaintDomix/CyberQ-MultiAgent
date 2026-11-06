# Milestone 2A offline behavioral pipeline

Implementation and provisional evaluation only. Branch 1 remains frozen. No new
traffic, live collection, Fusion, CQI, dashboard, LSTM or scanner integration.

## Architecture and canonical observations

`raw access logs -> adapters/apache.py -> CanonicalBehavioralEvent -> windowing.py
-> features.py -> dataset.py -> splitting.py -> models.py -> evaluation.py`

`artifacts.py` separates immutable training packages from schema-checked inference.
`reconciliation.py` combines parallel decisions, not features or training labels.
`explanation.py` provides robust deviations and optional SHAP raw-margin attribution.
The canonical event and model core have no Moodle imports. Future collectors may
supply genuine authenticated user/session/role observations through the canonical
interface. No Open edX or Moodle application-log adapter is implemented here.

Apache combined observations retain actual UTC time, SHA-256 pseudonymous client
identifier, method, path, query in memory, status, optional response bytes, optional
UA/referrer, Apache authenticated user when `%u` actually supplies it, and file/
line/record hashes. Apache `%u` is not necessarily a Moodle identity. SHA-256 is a
linkable pseudonym, not an anonymity guarantee. Missing `-` bytes stay unknown;
observed-ratio features distinguish unknown from zero. Session/role remain absent.
POST request bodies are **not observable** in combined logs. Login POST volume is
observable; passwords, submitted SQLi/XSS bodies, and authentication success cannot
be inferred. URL indicators describe lexical attempts, never exploit confirmation.
Logged byte counts depend on the Apache format (`%O` may include headers); they
are not treated as application payload size or proof of data extraction.
Error logs are preserved and hashed for inventory; no unsupported error-log event
or application-role interpretation is invented.

Dataset exports contain numeric features, pseudonymous grouping identifiers,
source hashes/line numbers and actual capture metadata. Raw queries, UA/referrer,
passwords, session material and request bodies are not exported. `safe_evidence()`
provides hashed query/UA/referrer evidence if needed; raw source logs stay read-only.

## Fixed window definition

Default is 10 seconds. Half-open windows are UTC epoch-aligned, computed with
integer microseconds; assignment is identical during training and future inference.
Windows are grouped by complete run, client pseudonym and UA digest. No empty/idle
windows are invented. Capture start/end filter observations before windowing;
end is exclusive. Windows at capture edges retain the fixed 10-second denominator
and full boundaries; partial coverage is visible from the stored capture interval.
This differs from historical run-start-aligned windows, explaining changed counts.

UA/client identifiers are grouping metadata, **not model predictors**. Behavioral
patterns can still be confounded by browser-vs-script generation and capture duration.
Future capture balancing is required; current metrics do not prove platform or
actor-independent generalization.

## Dataset v2 and feature rationale

Version `dataset-v2-features-1.0`: 65 ordered numeric features. The full feature
list is in [FEATURE_SCHEMA.md](FEATURE_SCHEMA.md) and each package's feature schema.

- Volume/rate/span/inter-request statistics capture density and regularity.
- Path breadth/repetition and explicitly configured login/admin/AJAX/API categories
  capture resource behavior; a privileged path is not proof of authorization or role.
- Method/status/redirect/error and byte-volume statistics preserve useful historical
  features without assuming that HTTP 200 means success or that large replies are attacks.
- Raw query lengths/parameter counts/encoding, bounded twice-decoded lexical quote,
  comment/SQL/XSS/traversal indicators capture **observable** request characteristics.
  Benign input may contain these tokens. No SQL execution or browser activity occurs.
- Optional identity/session/role counts have neutral zeros plus observed-ratio flags.
  Historical combined logs supply none of these application identities/roles.

Path regular expressions are saved/configurable context (login/admin/ajax/api).
Default categories preserve useful existing conventions without coupling model
training to Moodle raw formats. Lexical dictionaries, decode limit, window alignment,
feature order and path rules are schema-bound. Unsupported order/hash fails closed.
Trees receive raw finite numeric features (identity preprocessing; no test-fit scaler).

Each row stores run_id, scenario, explicit manifest label, actual window boundaries,
source SHA-256/line numbers and feature schema version/hash. Labels come from the
reviewed mapping, never feature heuristics or arbitrary filename substrings.
`experiments/branch2_v2_labels.json` documents capture-level reconstruction. S02 is
mixed reconnaissance, not independently labelled ADMIN_PROBING. S03's original
protocol says Nikto; preserved generator explicitly maps S03 to a controlled burst,
and actual root-GET/UA patterns agree. Its reconstructed burst label remains
**provisional**; the original generator invocation and service disruption are not known.

## Data quality and historical separation

Existing metadata: 14 scenario runs and one excluded TEST capture. Included data:
961 events, 72 windows; five loopback Apache `OPTIONS *` internal dummy requests
excluded explicitly; one B03-run02 request falls outside the recorded capture.
All 989 raw lines across the 15 access logs parse; 983 are in the 14 scenario logs.
Capture duration often differs from declared/planned duration; actual start/end
are used and discrepancies recorded. No old files/metrics are rewritten.

Historical v3: 35 benign training windows, 41 test windows, TN19/FP5/FN5/TP12,
F1=0.705882, FPR=0.208333, from the saved metrics_v3.json. Its benign holdout uses
complete scenarios' last runs, so no direct run-window train/test leakage is visible
in that implementation. It includes infrastructure requests and uses different
window alignment. These historical metrics are not new Dataset v2 results.

Build rejects duplicate run IDs, reused capture hashes, shared raw observations
and overlapping included capture intervals. Unknown scenario mappings and missing
captures fail rather than silently invent evidence. Inventory stores malformed-line
hashes/reasons; malformed lines are not turned into observations. All rejected/
excluded counts are explicit. Filename relocation uses the metadata basename only
under project/data/raw; the original record remains unchanged.

## Leakage-safe split and sufficiency

Seed=42, test fraction=0.3, stratified by label/scenario, whole-run shuffle/holdout.
At least one train and test run per stratum of two or more; singleton strata are
unassigned. Every window from a run follows that run. Dataset checking also rejects
overlapping captures/reused observations. Split and train/test run manifests are saved.
No feature selection, threshold selection, reference statistics or preprocessing
uses held-out data. No hyperparameter search or test-driven threshold tuning.

Minimum **provisional** XGBoost class eligibility: three independent nonempty runs,
with both training and test support. This minimum is weak, especially BRUTE_FORCE's
six total windows. Two-run classes are retained for explicitly exploratory IF
holdout but excluded from supervised metrics. Zero-run classes are never fabricated.
Final collection targets are 12 benign runs and 10 per intended attack class;
these are planning targets, not proof of adequate statistical power or final acceptance.
See [DATASET_V2_CAPTURE_PLAN.md](DATASET_V2_CAPTURE_PLAN.md).

## Parallel models

Isolation Forest: 200 trees, max_samples=auto, contamination=0.1, seed42, n_jobs1.
Fit only BENIGN **training** windows; attacks never train the IF. decision_function
is score_samples minus the fitted offset; `<0` means ANOMALOUS. Higher negative
score_samples indicates more anomaly. Offset and fit metadata are saved. A monotonic
0–100 severity index has boundary50, using benign training median absolute decision
value for scale. It is not an attack probability or empirically calibrated severity.

XGBoost: multi:softprob, eligible label indices, 200 trees, max_depth3, learning_rate
0.05, min_child_weight1, subsample/colsample1, reg_lambda1, hist, n_jobs1, seed42,
mlogloss. No huge search. Models are trained in parallel; IF is not an XGB input or
training gate. Currently only BENIGN/BRUTE_FORCE qualify, so a future local run has
two eligible classes, not a defensible final eight-class evaluation.

XGBoost/SHAP are not installed in the current venv. Standard parallel training fails
before producing an artifact directory. `--if-only` is an explicit partial package,
not a substitute classifier; xgb metrics are NOT_EVALUATED. Requirements declare
bounded supported candidates; installed versions are recorded in each actual package.
Native XGBoost JSON preserves the classifier; joblib stores the IF. Only load trusted
local packages (joblib is executable serialization). File hashes detect accidental
changes, not maliciously re-signed manifests. Reproduce with package library versions.

## Evaluation and reconciliation

Held-out IF exports TP/TN/FP/FN, precision/recall/F1/FPR/accuracy, per-run metrics and
score summaries by actual scenario label. Undefined ratios are null. XGB exports
class-ordered confusion matrix, per-class precision/recall/F1/support, macro/weighted
F1, accuracy and attack-vs-benign aggregate. Ineligible classes are explicitly excluded
from XGB metrics. Per-class zero-division uses sklearn zero_division=0 with support
reported. Correlated windows are not independent experimental samples.

Reconciliation threshold defaults to 0.8, configurable and saved:

| IF | XGB | Result |
|---|---|---|
| Anomalous | confident known attack | known attack with anomaly support |
| Anomalous | uncertain/unavailable or confident BENIGN | UNKNOWN_ANOMALY; disagreement retained for confident BENIGN |
| Normal | confident known attack | known attack; model disagreement |
| Normal | confident BENIGN | BENIGN |
| Normal | uncertain/unavailable | UNCERTAIN |

`predict_proba` is an **uncalibrated classifier score**, never a calibrated probability.
Threshold choice is explicit methodology, not selected to improve held-out metrics.

## Explanation and saved package

Robust reference is BENIGN-training-only median/MAD. Scale=1.4826*MAD; zero-MAD
features use IQR/1.349, then max(abs(median)*0.1,1). This prevents new query indicators
from disappearing when benign training values are constant. Return signed/absolute
deviations and top feature names. Scores describe reference deviation, not causality.

Optional SHAP TreeExplainer uses raw model margins, predicted-class top contributions,
handling legacy list and modern multiclass tensor shapes. Missing/incompatible SHAP
is an explicit status with empty contributions; robust explanations still operate.
There are fixture integration tests, but no real SHAP attribution has been claimed.

A complete package contains isolation_forest.joblib, xgboost.json, feature schema,
class mapping, reconciliation config, benign robust reference, training metadata/
versions/source hashes, split plus train/test run manifests, held-out metrics,
predictions, explanations and artifact hash manifest. Partial IF packages explicitly
say complete_parallel_package=false. Training and inference are separate commands;
inference never fits. Inference on a training dataset is not held-out evaluation.
The scoring API accepts unlabeled feature rows: scenario/ground-truth label may
be absent and remain null; model decisions do not depend on supplied labels.
All output directories are new, immutable subdirectories of outputs/branch2 or
 data/branch2_v2; existing artifacts and protected historical paths cannot be overwritten.

## Actual provisional result and exact reproduction

Dataset: `data/branch2_v2/provisional_existing_01/`.
IF final implementation package: `outputs/branch2/m2a_provisional_if_02/`.
Earlier IF package `_01` is retained, not overwritten. Both use the same numeric
method/split; `_02` includes explicit train/test run inventory artifacts.

Eight train runs / six held-out runs; IF fits four benign runs, 37 windows.
Held-out 28 windows: 21 benign and seven scenario-labelled suspicious.
Actual result: TP5 TN16 FP5 FN2; precision0.5, recall0.714286, F1=0.588235,
FPR=0.238095, accuracy0.75. The false-positive rate is poor; no tuning was performed
to hide it. Final experimental Dataset v2 evaluation is **not complete**.

```bash
.venv/bin/python -B scripts/run_branch2.py build \
  --out data/branch2_v2/provisional_existing_02
.venv/bin/python -B scripts/run_branch2.py train \
  --dataset data/branch2_v2/provisional_existing_02/dataset.json \
  --if-only --seed 42 --contamination 0.1 \
  --out outputs/branch2/provisional_if_next

# Dependency installation is proposed, not executed in Milestone 2A:
.venv/bin/python -m pip install -r requirements/branch2.txt
# Optional SHAP:
.venv/bin/python -m pip install -r requirements/branch2-explain.txt

.venv/bin/python -B scripts/run_branch2.py train \
  --dataset data/branch2_v2/provisional_existing_02/dataset.json \
  --seed 42 --confidence-threshold 0.8 \
  --out outputs/branch2/provisional_parallel_01
.venv/bin/python -B scripts/run_branch2.py infer \
  --dataset data/branch2_v2/provisional_existing_02/dataset.json \
  --model outputs/branch2/provisional_parallel_01 \
  --out outputs/branch2/offline_inference_01
.venv/bin/python -B -m unittest discover -s tests -v
```

Training evaluates in the same command and stores metrics/predictions; inference
uses saved schema/config/models without retraining. Choose new output paths on
reruns and retain previous evidence. No new network traffic was performed.
