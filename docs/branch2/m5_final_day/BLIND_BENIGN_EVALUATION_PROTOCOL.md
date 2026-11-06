# Saved-model paired blind BENIGN evaluation

Run `python -B scripts/run_m5_blind_benign_evaluation.py` from the repository,
using its environment. The command refuses an existing evaluation directory and
writes only `outputs/branch2/m5_final_day/blind_benign_test_01/evaluation/`.
No model/core/capture/locked-evidence file is changed. Fitting methods for IF,
OCSVM, LOF, RobustScaler and XGBoost are blocked during real evaluation, as are
outbound socket connections and DNS resolution. No traffic is generated.

Before prediction, validate the expected canonical freeze and all 23 artifacts,
locked TEST file SHA256 and canonical digest, pre-test receipt, original plan,
development dataset, v1 code and artifact hashes. Independently replay each
capture's bounded raw source bytes, including ambient provenance, and recompute
both 83-column and 65-column feature rows. Every prediction links to the same
accepted record byte positions through run/time/client/agent/source hashes.
The integrity receipt is written before calling either saved model.

Candidate inference uses the saved OCSVM normality score with its strict frozen
cutoff, saved XGBoost, confidence threshold 0.8 and persistence 2. v1 uses its own
saved IF decision threshold, unscaled 65-feature transform, classifier and saved
confidence threshold. Model outputs are never replaced or repaired. Additional
v1 client/agent/byte-position fields are attached from source window metadata
only; no decision changes. Replay loads both packages again and requires exact
prediction/explanation equality, without fitting.

Window anomaly rate counts every raw novelty observation. Raw run FPR counts
runs with any anomalous window. Alert rate uses contiguous same-class episodes
within run/client/agent: candidate persistence 2; v1 persistence 1 as in the
existing M5 paired comparator. v1's extra persistence gate was never a fitted
model parameter. Both group correlated windows instead of calling each window
an incident. This comparison bundles model/features/preprocessing and alert-policy
differences; it cannot establish which change caused a difference.

Raw non-BENIGN XGBoost predictions are counted even below the frozen confidence
threshold. Final confident-known attempt decisions are reported separately.
UNKNOWN_ANOMALY window observations do not necessarily produce an alert episode.
Scores are uncalibrated, non-causal evidence; attempts do not prove exploitation.

The classification rule is read from the immutable pre-test receipt before
metrics. Exact rational comparisons implement its 5%, 50%, 10% and one-third
boundaries without rounding. "Known-attack windows" conservatively includes raw
XGBoost non-BENIGN predictions, including low-confidence mistakes. If the rule
is absent, use BENIGN_TEST_DESCRIPTIVE_ONLY; an unrecognized rule stops rather
than introducing a new cutoff. No threshold/model/persistence selection occurs.

Output includes integrity receipts, both prediction sets, exact paired windows,
per-session comparisons, metrics, Markdown report, saved-model replay checks and
SHA256/byte counts for every output except the artifact manifest itself. All
pre-existing protected research artifacts are independently checked after tests.
Six student-role controlled Moodle sessions support descriptive generalization
results, not statistical significance or population FPR guarantees. Fresh attack
holdout has not run and candidate promotion is not authorized.
