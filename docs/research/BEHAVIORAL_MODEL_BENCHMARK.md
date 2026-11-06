# Task 2B: controlled three-pipeline behavioral benchmark

## Research question and controlled variables

Does replacing accepted OCSVM reduce benign false positives without losing
attack detection under identical data, classifier and production policy?
Exactly three pipelines are evaluated: A OCSVM + XGBoost, B LOF + XGBoost,
C Isolation Forest + XGBoost. The accepted Behavioral v2 package is not changed.
The fixed classifier artifact SHA256 is
`9d3acb8e87d44d13f2b62ede413e073fb51c3f264db48a6d4d229964f0e6150d`.

All pipelines share the accepted 83-feature order, raw feature extraction,
frozen RobustScaler (novelty only), raw-feature XGBoost classifier, eight class
labels, confidence threshold 0.8 and UNKNOWN persistence=2. The existing
reconciliation and episode functions are called without modification. Task 2A
explanations continue to describe only the accepted OCSVM application pipeline.

## Prospective protocol for this comparison

`outputs/behavioral/task2b_benchmark_01/benchmark_config.json` is written before
benchmark execution and is SHA256-bound. All three configurations and cutoffs
already exist in the accepted package's `model/novelty.joblib` and `model/config.json`.
They were fixed during original pre-test M5 development, not this benchmark.
No new calibration, threshold grid, persistence selection or hyperparameter search
is performed. The package contains all three fitted detectors although OCSVM is
the selected production detector.

A uses saved OCSVM directly: RBF kernel, nu=0.1, gamma=scale, frozen cutoff
1.2667822314625847. No OCSVM fit occurs. Historical OCSVM fit time was not
recorded and will not be invented or measured by refitting.

B fits one historical LOF configuration on accepted benign TRAIN: novelty=True,
n_neighbors=20, Minkowski p=2 (Euclidean), algorithm=auto, leaf_size=30,
contamination=auto, n_jobs=1. Frozen cutoff: -1.5240791194091785. Only unseen
VALIDATION/evaluation observations are passed to score_samples. Its default
offset is not used as the operational cutoff.

C fits one historical IF configuration on the same benign TRAIN representation:
200 estimators, max_samples=auto (101 samples in this dataset), max_features=1.0,
contamination=0.1, bootstrap=False, random_state=42, n_jobs=1. Frozen cutoff:
-0.5404998921984803. The contamination setting does not replace the frozen
validation-selected score_samples cutoff. Larger score_samples values mean more
normal behavior for each detector, but numeric scores are not comparable across
detectors and are not probabilities.

Both alternative fits use clones, never mutate accepted estimators, and must
reproduce saved historical validation scores to absolute tolerance 1e-12.
Their artifacts/cutoffs are frozen before holdout feature loading. Shared scaling
is transform-only; no scaler or classifier fit is allowed. A benchmark execution
marker prevents repeatedly rerunning a valid experiment to seek a preferred result.

## Splits and leakage controls

The accepted frozen development dataset contains TRAIN: 59 runs/290 windows,
including 17 benign runs/101 windows, and VALIDATION: 22 runs/114 windows,
including 51 benign windows and 63 attack windows. Fitting is restricted to
the 101 benign TRAIN windows. All original run identities are preserved.

Evaluation reuses the locked six-session blind benign evidence and the fourteen
fresh-attack holdout runs. These are **previously opened accepted evaluation
sets**, not a new blind trial. No new traffic is generated and no holdout is
used for fitting, recalibration or parameter selection. The benchmark's
replacement recommendation is comparative evidence on this existing holdout;
any future accepted migration still needs a controlled acceptance process.

The split receipt records every run and input-derived window ID, class counts,
source SHA256 and numeric input hash. It rejects cross-partition run identities,
duplicate source windows and overlapping raw source-record identities.
Numerically identical feature vectors from independent low-activity windows are
reported separately; numerical equality alone does not prove evidence reuse.
The exact same input IDs and matrix are used by A/B/C.

## Three distinct outcome layers

1. Novelty-only: benign window FPR/specificity and any-anomaly session rate;
   attack-window/run anomaly recall and per-class support.
2. Classifier-only: one invocation of the accepted XGBoost on the shared raw
   evaluation matrix. Accuracy, macro-F1, per-class precision/recall/F1 and
   confusion matrix are identical for A/B/C. Combined macro-F1 uses eight
   supported labels; attack-only macro-F1 uses seven true attack labels.
3. Strict end-to-end benchmark: anomaly AND raw XGBoost label equals the true
   known class. No extra confidence condition is added to the user's AND metric.
   A run is strict-detected if any window satisfies that condition.

Strict AND is deliberately different from **production reconciliation**, which
preserves confident known attempts even when novelty is normal. Both results are
reported. Production incidents use the existing contiguous-window function:
UNKNOWN requires two adjacent windows; confident known attempts can alert after
one. Observation is not incident. Production incidents are not redefined to force
the strict AND metric, nor is the accepted runtime changed for this benchmark.
Classifier run prediction is majority window class, ties by canonical class name.

Key proportions include raw k/n and 95% Wilson intervals without continuity
correction. Window intervals assume independent trials and are descriptive,
because windows within a run are correlated. Six benign runs and two attack
runs per class do not support a population-level significance claim.

## Replacement gate (fixed before calculation)

An alternative is eligible only if every condition holds against A:

- strictly fewer benign false-positive windows;
- no more false benign incident sessions under frozen production episodes;
- no fewer strict-correct attack runs AND no fewer production-alerted attack runs;
- no fewer novelty-detected attack windows;
- no fewer strict-correct attack windows, with identical fixed classifier results.

No loss of even one strict-correct window/run is excused as a post-hoc
"meaningful" tolerance. The <=5% benign-window FPR is a preferred operating
objective, not a substitute for the full replacement gate. Eligible ties use
fewer false-incident sessions, fewer benign FP windows, more strict attack
runs/windows, more novelty attack windows, then a fixed IF-before-LOF tie.
If no alternative passes, KEEP_OCSVM. No package is replaced in this task.

## Operational cost and reproducibility

Only LOF/IF fit times are measured; A fit time is unavailable. Each detector gets
one warm-up and three fixed passes of single-window score_samples timing on the
same pre-scaled evaluation rows. Mean/median/p95/max, estimator serialization
size and benchmark artifact size are reported. Shared scaling and classifier
time are excluded. This is not 10-second-window end-to-end detection latency.

```bash
PYTHONPATH=src:. .venv/bin/python -B scripts/run_behavioral_benchmark.py prepare
# Run focused tests before the single experiment.
PYTHONPATH=src:. .venv/bin/python -B scripts/run_behavioral_benchmark.py run
```

Raw evidence and accepted packages are referenced by hash, never copied.
`window_results.csv`, `run_results.csv`, `class_metrics.csv`,
`confusion_matrix.json`, `pipeline_results.json`, `selection_decision.json`
and the generated `report.md` retain all results, including unfavorable ones.

Methods: [scikit-learn LOF unseen-data semantics](https://scikit-learn.org/stable/modules/generated/sklearn.neighbors.LocalOutlierFactor.html);
[SciPy Wilson intervals](https://docs.scipy.org/doc/scipy-1.16.1/reference/generated/scipy.stats._result_classes.BinomTestResult.proportion_ci.html).

## Results

The single valid execution returned **KEEP_OCSVM**. LOF/IF validation-score reproduction error was exactly zero; accepted OCSVM scores/verdicts and fixed XGBoost outputs reproduced the locked predictions. No execution retry was required.

| Metric | A OCSVM | B LOF | C IF |
|---|---:|---:|---:|
| Benign novelty FPR | 1/33 (3.03%) | 1/33 (3.03%) | 1/33 (3.03%) |
| Benign any-anomaly sessions | 1/6 (16.67%) | 1/6 (16.67%) | 1/6 (16.67%) |
| False incident sessions | 0/6 (0.00%) | 0/6 (0.00%) | 0/6 (0.00%) |
| Attack novelty windows | 65/68 (95.59%) | 41/68 (60.29%) | 3/68 (4.41%) |
| Attack novelty runs | 14/14 (100.00%) | 13/14 (92.86%) | 2/14 (14.29%) |
| Strict AND correct attack windows | 63/68 (92.65%) | 40/68 (58.82%) | 3/68 (4.41%) |
| Strict AND detected attack runs | 14/14 (100.00%) | 12/14 (85.71%) | 2/14 (14.29%) |
| Production attack runs alerted | 14/14 (100.00%) | 14/14 (100.00%) | 14/14 (100.00%) |

Specificity is 32/33 (96.97%) for each detector. All three have zero benign incident episodes and 16 production attack episodes. The production result is not the strict AND result: confident known classes preserve run-level detection despite novelty misses.

Neither alternative reduces benign FPR. Both lose novelty attack recall and strict AND correct-class recall; both therefore fail the complete replacement gate. Equal benign FPR is itself insufficient for replacement even before considering those losses.

### Per-class attack novelty / strict AND counts

Each class has two runs; window support is shown explicitly.

| Class | Windows | A novelty / strict | B novelty / strict | C novelty / strict |
|---|---:|---|---|---|
| ADMIN_PROBING | 10 | 10/10 / 10/10 | 9/10 / 9/10 | 0/10 / 0/10 |
| BRUTE_FORCE | 10 | 10/10 / 10/10 | 10/10 / 10/10 | 3/10 / 3/10 |
| ENUMERATION_RECONNAISSANCE | 10 | 10/10 / 9/10 | 2/10 / 1/10 | 0/10 / 0/10 |
| PATH_TRAVERSAL_ATTEMPT | 10 | 10/10 / 10/10 | 9/10 / 9/10 | 0/10 / 0/10 |
| REQUEST_BURST_DOS_LIKE | 8 | 5/8 / 4/8 | 1/8 / 1/8 | 0/8 / 0/8 |
| SQLI_ATTEMPT | 10 | 10/10 / 10/10 | 8/10 / 8/10 | 0/10 / 0/10 |
| XSS_ATTEMPT | 10 | 10/10 / 10/10 | 2/10 / 2/10 | 0/10 / 0/10 |

### Fixed classifier

Combined evaluation: 99/101 correct (98.02%), eight-class macro-F1 0.977270. Attack-only: 66/68 correct (97.06%), seven-supported-attack-class macro-F1 0.976155. Majority-class attack-run correctness is 14/14 for all pipelines.

| Class | Support | Precision | Recall | F1 |
|---|---:|---:|---:|---:|
| ADMIN_PROBING | 10 | 0.909091 | 1.000000 | 0.952381 |
| BENIGN | 33 | 0.970588 | 1.000000 | 0.985075 |
| BRUTE_FORCE | 10 | 1.000000 | 1.000000 | 1.000000 |
| ENUMERATION_RECONNAISSANCE | 10 | 1.000000 | 0.900000 | 0.947368 |
| PATH_TRAVERSAL_ATTEMPT | 10 | 1.000000 | 1.000000 | 1.000000 |
| REQUEST_BURST_DOS_LIKE | 8 | 1.000000 | 0.875000 | 0.933333 |
| SQLI_ATTEMPT | 10 | 1.000000 | 1.000000 | 1.000000 |
| XSS_ATTEMPT | 10 | 1.000000 | 1.000000 | 1.000000 |

Both classifier errors, full matrices and their supported-label macro definitions are preserved in `confusion_matrix.json`. Standalone classifier results are literally shared, not separately fitted for each detector.

### Exact split composition

Class order below is canonical stored label order; every exact run/window ID is in split_receipt.json.

| Partition | Runs | Windows | Class distribution |
|---|---:|---:|---|
| ATTACK_HOLDOUT | 14 | 68 | ADMIN_PROBING: 10; BRUTE_FORCE: 10; ENUMERATION_RECONNAISSANCE: 10; PATH_TRAVERSAL_ATTEMPT: 10; REQUEST_BURST_DOS_LIKE: 8; SQLI_ATTEMPT: 10; XSS_ATTEMPT: 10 |
| BENIGN_TEST | 6 | 33 | BENIGN: 33 |
| TRAIN | 59 | 290 | ADMIN_PROBING: 29; BENIGN: 101; BRUTE_FORCE: 22; ENUMERATION_RECONNAISSANCE: 26; PATH_TRAVERSAL_ATTEMPT: 30; REQUEST_BURST_DOS_LIKE: 22; SQLI_ATTEMPT: 30; XSS_ATTEMPT: 30 |
| VALIDATION | 22 | 114 | ADMIN_PROBING: 9; BENIGN: 51; BRUTE_FORCE: 10; ENUMERATION_RECONNAISSANCE: 9; PATH_TRAVERSAL_ATTEMPT: 10; REQUEST_BURST_DOS_LIKE: 6; SQLI_ATTEMPT: 10; XSS_ATTEMPT: 9 |

There are zero run/source-record overlaps across partitions. Fourteen numeric-vector patterns recur across partitions; those have distinct accepted run/source-record identities. Independent controlled repetitions are not independent users, and this numerical repetition limits diversity.

### Uncertainty and paired evidence

For every detector, benign FPR is 1/33 with 95% Wilson interval 0.54–15.32%; false incident sessions are 0/6 with interval 0–39.03%. OCSVM strict recall is 63/68 with interval 83.91–96.82%, LOF 40/68 with interval 46.96–69.74%, IF 3/68 with interval 1.51–12.19%. These are descriptive intervals; window clustering prevents treating them as population-level significance evidence.

Three attack windows are novelty-detected by all three. OCSVM-only relative to LOF: 24 windows; relative to IF: 62 windows. Neither alternative detects an attack window missed by OCSVM on this evidence. Detailed paired IDs, including false-positive overlap and strict AND disagreements, are in the benchmark package.

### Scientific interpretation

Three novelty-detection pipelines were evaluated under identical feature, classifier, split and persistence conditions. The alternatives did not improve the observed benign false-positive rate, while their novelty and strict known-class detection recall were lower. The accepted OCSVM-based pipeline therefore retains the strongest observed balance on this controlled laboratory dataset. This does not establish universal detector superiority or accuracy on other platforms.

Timing, model sizes, all gate outcomes, per-run results, provenance and integrity are retained in `outputs/behavioral/task2b_benchmark_01/`. The current accepted model was not replaced.
