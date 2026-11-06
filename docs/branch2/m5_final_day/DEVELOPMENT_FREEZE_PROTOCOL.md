# Dataset v3.1 development review and pre-TEST candidate freeze

This stage uses TRAIN/VALIDATION only. It neither promotes a model nor evaluates
TEST, the earlier external diagnostic browsing session, or fresh attack holdouts.
Accepted Model v1, Fusion/CQI, original reservations and captures stay unchanged.

## Review and source eligibility

The explicitly authorized exclusions are M5FD-20261014-001/002/003, all INVALID.
They remain historical evidence with their original errors and labels. No capture
is salvaged, moved or replaced. This gives nine browser TRAIN sessions (004–012)
and six browser VALIDATION sessions (013–018), rather than twelve usable browser
TRAIN sessions. This reduction is recorded as a limitation. Session 003 proves
an unmet resource-discovery precondition, not that all Moodle resources are absent.

`development_review.json` must PASS before construction or fitting. Review
replays all included bounded source slices, verifies deterministic ownership,
checks collection receipts against capture-manifest hashes, binds every development
capture file and the unchanged original plan, and checks frozen v1 source status.
Raw hashes retain ambient traffic; only owned observations enter features. Invalid
and diagnostic data are excluded explicitly. No TEST observation is opened.

The builder preserves M2C historical TRAIN/VALIDATION membership and rejects
shared run IDs, duplicate observations/capture hashes, and overlapping browser
capture intervals. Historical TEST IDs appear only as excluded split metadata.
Each run's class, partition, source type, window count and provenance reference
are saved in the development manifest. The feature schema remains the existing
83-column `dataset-v3.1-features-2.1`, with platform adapter identity/hash.

## Existing selection policy, unchanged

All novelty models and their shared RobustScaler fit **BENIGN TRAIN only**.
IF uses 200 estimators, contamination 0.1, seed 42, n_jobs=1; OCSVM uses RBF,
nu=0.1, gamma=scale; LOF uses novelty=True, min(20, benign_train_windows-1)
neighbors, n_jobs=1. Reference median/scale also use BENIGN TRAIN only.

All score_samples directions are larger=more normal. Thresholds use only benign
VALIDATION scores: sorted_score[floor(target*n)], with strict score<cutoff for an
anomaly and equality normal. Targets are 1%, 2%, 5%, 10%; persistence is 1/2/3.
Only target≤5% and realized benign validation window FPR≤5% qualify. Select:

1. greatest validation novelty attack-window recall;
2. lowest benign any-reconciled-alert run FPR;
3. greatest attack any-reconciled-alert run recall;
4. shortest persistence;
5. IF, OCSVM, LOF fixed simplicity order, then lowest target.

All 36 candidates are saved, including unsuccessful settings. For each alternative
model's independent descriptive comparison, choose its cutoff by greatest attack
recall, lowest realized window FPR, lowest target, as in the existing calibration
helper. The ultimately selected model uses its joint model/episode cutoff.
Do not compare rounded metrics to select a candidate.

XGBoost fits TRAIN only over all eight labels, using the pre-existing 200-tree,
depth-3, learning-rate-0.05 histogram configuration, seed 42 and n_jobs=1. Its
confidence threshold remains 0.8, with **uncalibrated** score semantics. No
hyperparameter search or new selectable confidence grid is introduced.
Reconciliation retains known-attempt/disagreement/UNKNOWN_ANOMALY semantics.

Window metrics are descriptive validation estimates after selection, not fresh
held-out performance. XGBoost run predictions use the mean uncalibrated class-score
vector followed by argmax (sorted class order resolves ties). Raw novelty run
metrics use any anomalous window, separately from any-alert reconciled episode
metrics. True attack-episode intervals are unavailable; do not invent episode
ground truth. Contiguous same-class windows are grouped within run/client/agent;
unknown episode alerts require selected persistence. Known attempt episodes are
not successful exploitation.

## Freeze and reproducibility

The immutable candidate includes the dataset/review/manifest, preprocessing,
all three novelty models, XGBoost, class mapping, selected settings, every tuning
candidate, window/run validation metrics, runtime/dependency metadata, limitations
and no-retrain replay results. Every artifact has a SHA256 entry. The version 1.1
freeze also has a canonical root SHA256, excluding its own root_sha256 field;
the SHA256 of the serialized freeze-manifest file is a separate identity.
Artifact membership, artifact hashes, package hashes, source implementation and
schema identity are checked before inference. Existing outputs are never overwritten.

The freeze states TEST_ACCESSED_BEFORE_FREEZE=false, TEST_USED_FOR_SELECTION=false
and FRESH_ATTACK_HOLDOUT_USED_FOR_SELECTION=false. Fresh evaluation requires a
valid matching freeze, and future fresh captures must postdate it. Stop here;
this protocol does not authorize TEST collection/evaluation or promotion.

```bash
.venv/bin/python -B scripts/run_m5_final_day.py review-development \
  --summary outputs/branch2/m5_final_day/development_collection_runs/collection_001/summary.json \
  --exclude-invalid M5FD-20261014-001,M5FD-20261014-002,M5FD-20261014-003
.venv/bin/python -B scripts/run_m5_final_day.py build --out data/branch2_v3/development_freeze_01
.venv/bin/python -B scripts/run_m5_final_day.py train-freeze \
  --dataset data/branch2_v3/development_freeze_01/dataset.json \
  --out outputs/branch2/m5_final_day/candidate_freeze_01
```

Review/build commands refuse existing output files/directories. Rebuilding to a
temporary directory must reproduce identical dataset bytes. Wall-clock runtime
measurements and the real freeze timestamp are not deterministic model metrics.

## Limitations

Browser BENIGN coverage is limited and currently student-only. Controlled repeated
sessions are not independent human users. Moodle is the validated reference
platform; adapters support extension without proving equal accuracy on other LMSs.
Apache combined logs omit POST bodies. SQLI/XSS/PATH labels describe URL-visible
attempt patterns, never exploit success. Novelty scores and SHAP are not causal
security explanations. XGBoost scores are uncalibrated. Small validation samples
and reuse for selection limit statistical claims. Poor candidate results remain
visible. No accepted-model replacement follows from development metrics alone.
