# M2C final offline controlled-laboratory protocol

Branch 1 is frozen. This protocol performs no traffic generation/collection and
never imports failed/partial capture roots. M2A outputs and metrics remain
**provisional** and are not the final experimental evaluation. Inputs are the
explicitly assembled historical + verified M2B Dataset v2; its raw evidence,
65-feature order/hash and labels are preserved. Capture-target sufficiency is
not a claim of model readiness or successful exploitation.

## Frozen partitions and integrity

`run_branch2.py train-final` uses `split_final_runs`, not the provisional two-way
split. Seed 42 is mandatory in the final CLI. The splitter requires exactly 12
BENIGN runs and 10 runs in each of the seven attack classes. It allocates BENIGN
8/2/2 and each attack 6/2/2 to TRAIN/VALIDATION/TEST: 50/16/16 complete runs.
All eight classes must appear in each partition; failure is explicit.

Algorithm m2c-run-split-1.0 groups each label by scenario, processes rarer scenarios
first, shuffles sorted run IDs with the fixed RNG, and places runs by least scenario
occupancy, then lowest filled fraction of the partition quota. Seeded ordering
breaks ties. Quotas cap every placement. This maximizes available scenario breadth
without imposing impossible three-way presence of two-run scenarios. Scenario
membership is recorded; scarce scenario coverage remains a limitation. In the
current split all three authenticated B04 runs are TRAIN, so held-out BENIGN
performance does not independently evaluate that authenticated-navigation scenario.

The splitter rejects duplicate IDs/windows, excluded or unlabelled window rows,
missing/mismatched source provenance, capture/file duplicates, shared file-line
observations and overlapping actual run intervals. All windows from a run stay
in one partition. The input's raw-source hashes are checked before fitting.
TEST-run01 has no emitted rows and is excluded; injected smoke-test rows fail.
Split artifacts record run inventories, labels, scenarios, capture bounds/source
hashes, window counts, exclusion and pairwise overlap checks. Selection never uses
TEST performance. Historical label-reconstruction caveats remain in the manifest.

## Fitting and predeclared validation selection

XGBoost is fitted once on TRAIN only using the existing 200-estimator, depth-3,
learning-rate 0.05 multiclass configuration, all eight classes, random_state=42,
n_jobs=1. It does not receive validation/test rows or early-stopping data.
No large hyperparameter search, calibration or fitted feature transformation is
performed. Class mapping is saved in sorted order.

Four Isolation Forest candidates fit only TRAIN BENIGN: contamination
[0.05,0.10,0.15,0.20], 200 estimators, max_samples=auto, random_state=42, n_jobs=1.
Each is scored on VALIDATION. Selection maximizes binary anomaly F1, then minimizes
BENIGN FPR, maximizes balanced accuracy, then prefers contamination closest to 0.10.
If all those criteria tie, lower contamination breaks the remaining tie.
Benign median/MAD/IQR reference statistics and IF severity scale derive solely
from TRAIN BENIGN. The selected already-fitted forest is retained, never refitted
on validation or test.

Reconciliation confidence candidates [0.60,0.70,0.80,0.90] use the selected IF and
fixed XGB validation predictions. Selection maximizes macro-F1 over the eight known
classes; UNKNOWN_ANOMALY and UNCERTAIN are incorrect for known truth. Ties choose
the higher threshold. Every candidate and metric is saved, including poor results.
Scores from predict_proba remain **uncalibrated model scores/confidence**.

Existing reconciliation remains unchanged: confident known attack retains its
class regardless of IF (with support/disagreement recorded); an anomalous IF with
no confident known attack produces UNKNOWN_ANOMALY; confident BENIGN + normal IF
produces BENIGN; normal IF + low classifier confidence produces UNCERTAIN.
Raw XGB argmax metrics are reported independently of reconciliation.

## One frozen test evaluation and independent run-level view

Only after selection is complete does the pipeline predict TEST. Window metrics
include IF binary TP/TN/FP/FN, precision/recall/F1, specificity/FPR/balanced accuracy,
support and score summaries; XGB eight-class confusion/per-class metrics,
macro precision/recall/F1, weighted F1, accuracy/balanced accuracy; and reconciled
confusion, metrics, disagreements/reasons. Extra predicted UNKNOWN_ANOMALY or
UNCERTAIN labels have zero ground-truth support and remain visible in matrices.
Macro averages cover the eight known truth classes, preserving false negatives
from unknown decisions. Undefined binary ratios are null; class zero-division is
zero with supports shown. No ROC-AUC or confidence intervals are claimed.

Run-level XGB averages all class-score vectors within a run, then takes argmax.
Exact ties select the first saved class-mapping entry. Run-level IF averages the
window decision_function, equivalent to mean(score_samples) minus fitted offset_;
it is anomalous if strictly negative, normal at zero. Its raw anomaly score is
mean(-score_samples). This preserves the trained boundary, introduces no new
threshold, and can dilute short isolated spikes; it measures average run behavior.
Run-level reconciliation applies the existing rules to that mean IF decision and
the mean XGB vector/selected threshold. It does not use ground truth or a majority
vote of window reconciliations. Runs/windows are deterministically sorted before
averaging. The 16 held-out runs, not their correlated windows, are the independent
experimental units; they are repeated controlled lab protocols, not independent
real users or deployments.

## Explanation and saved package

Python SHAP TreeExplainer is tried first with raw model margins. Installed SHAP
0.49.1 cannot parse XGBoost 3.2.0's vector-valued multiclass base_score. The fallback
uses XGBoost's native **exact TreeSHAP** (`pred_contribs=True`,
`approx_contribs=False`, `strict_shape=True`) on the actual final model, without
changing that model. The native API defines these contributions as SHAP values.
The full feature vector plus bias is checked against raw margins for every class
(rtol=1e-5, atol=1e-4) before returning top predicted-class contributions. Backend,
Python loader incompatibility, bias/margin/additivity error and causal=false are
recorded. Neither absence nor incompatibility produces invented explanations.
The QA artifact counts available/nonempty explanations, robust deviations and
failures. Robust deviations use the TRAIN BENIGN reference only; no causal wording.

New immutable output contains serialized IF/XGB, schema/order/hash, class mapping,
reference/reconciliation, training/split/provenance manifests, validation candidates
and predictions, window/run frozen-test metrics and predictions, explanations/QA,
capture sufficiency and artifact hashes. After saving, loaded models infer the
same TEST rows without fitting; the entire prediction output must match exactly.
The replay report is a consistency test, not another held-out evaluation. Final
package hashes include that report. Existing `infer` loads this package and never
trains. Existing `train` remains the explicitly provisional two-way API.

Readiness semantics: CAPTURE_TARGET_MET when independent included runs reach the
class target; otherwise PROVISIONAL_ONLY at the provisional minimum, else
INSUFFICIENT. Old saved sufficiency artifacts are retained unchanged; the final
package emits a freshly computed report with the corrected semantics.

## Exact reproduction

```bash
cd /home/saintdomix/dissertation_model
.venv/bin/python -B -m unittest discover -s tests -v
.venv/bin/python -B scripts/run_branch2.py train-final \
  --dataset data/branch2_v2/final_candidate_01/dataset.json \
  --seed 42 --out outputs/branch2/m2c_final_01

# On repeat, choose a NEW output directory; never overwrite an experiment.
# Saved-model inference on all supplied rows is not held-out evaluation:
.venv/bin/python -B scripts/run_branch2.py infer \
  --dataset data/branch2_v2/final_candidate_01/dataset.json \
  --model outputs/branch2/m2c_final_01 \
  --out outputs/branch2/m2c_saved_inference_01
```

## Actual final offline result

The completed experiment is `outputs/branch2/m2c_final_01/`. Its partition manifests
record 50/16/16 runs and 243/80/69 windows. IF/reference fit uses 54 TRAIN BENIGN
windows; XGB fits all 243 TRAIN windows over all eight classes. Validation selected
contamination 0.15 and confidence 0.80. IF validation F1 at contamination
0.05/0.10/0.15/0.20 was 0.000000/0.511628/0.745098/0.742857. Reconciled validation
macro-F1 was 0.947193 at 0.60, 0.70 and 0.80, and 0.931568 at 0.90; the declared
tie rule selects 0.80. All candidate details, including unsuccessful candidates,
are retained in validation_tuning.json.

| Model | TEST window F1 / macro-F1 | Window accuracy | TEST run F1 / macro-F1 | Run accuracy |
|---|---:|---:|---:|---:|
| IF (binary F1) | 0.715789 | 0.608696 | 0.833333 | 0.750000 |
| XGB (8-class macro-F1) | 0.980676 | 0.985507 | 0.933333 | 0.937500 |
| Reconciled (known-class macro-F1) | 0.939731 | 0.898551 | 0.916667 | 0.875000 |

IF window counts are TP34/TN8/FP3/FN24, with BENIGN FPR 0.272727; its poor
window false-positive rate is retained. IF run counts are TP10/TN2/FP0/FN4,
FPR 0.0 on only TWO BENIGN test runs. This small denominator does not establish
robust real-world specificity, and averaging can conceal localized anomalies.
All test confusion matrices, per-class metrics and actual supports are in the
window/run-level test artifacts. Reconciliation records 26 window disagreements
and four run disagreements rather than hiding them.

All 69 TEST windows have nonempty exact native TreeSHAP contributions and robust
deviations. Python TreeExplainer remains incompatible; the backend/status counts
say so explicitly. Saved-package replay matched all 69 full prediction records
without fitting. No new traffic, source/evidence changes, failed/partial imports,
model calibration or Git commit occurred. To reproduce without overwriting the
completed package, choose a new directory, for example:

```bash
.venv/bin/python -B scripts/run_branch2.py train-final \
  --dataset data/branch2_v2/final_candidate_01/dataset.json \
  --seed 42 --out outputs/branch2/m2c_final_02
```

This repeats the frozen protocol; it is not a new independent experiment and must
not be used to tune parameters after inspecting TEST.
