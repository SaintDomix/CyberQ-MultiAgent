# M5 — v1 versus Behavioral v2 Results

**Disposition: B. V2 TRADE-OFF / INCONCLUSIVE. Keep accepted v1; do not promote or replace its package.**

## Provenance and scope

M4B source was preserved in WIP commit `a3f9100` on `m4-demo-ui`; M5 branches from `milestone-3-end-to-end` (`30aa494`). New code is isolated under `src/behavioral_v2/`. No accepted Branch1, Branch2, Fusion, CQI or reporting code changed. No traffic was generated.

Dataset v3 reconstructs exactly the same 82 included runs / 392 windows from authoritative captures, with every original 65-feature vector reproduced exactly. TEST-run01 stays excluded. Source hashes, line provenance, windows, labels and run membership are preserved. Historical + verified session03 composition is intentional; failed/partial captures are not imported.

| Partition | Runs | Windows | Class run counts |
| --- | --- | --- | --- |
| test | 16 | 69 | ADMIN_PROBING:2, BENIGN:2, BRUTE_FORCE:2, ENUMERATION_RECONNAISSANCE:2, PATH_TRAVERSAL_ATTEMPT:2, REQUEST_BURST_DOS_LIKE:2, SQLI_ATTEMPT:2, XSS_ATTEMPT:2 |
| train | 50 | 243 | ADMIN_PROBING:6, BENIGN:8, BRUTE_FORCE:6, ENUMERATION_RECONNAISSANCE:6, PATH_TRAVERSAL_ATTEMPT:6, REQUEST_BURST_DOS_LIKE:6, SQLI_ATTEMPT:6, XSS_ATTEMPT:6 |
| validation | 16 | 80 | ADMIN_PROBING:2, BENIGN:2, BRUTE_FORCE:2, ENUMERATION_RECONNAISSANCE:2, PATH_TRAVERSAL_ATTEMPT:2, REQUEST_BURST_DOS_LIKE:2, SQLI_ATTEMPT:2, XSS_ATTEMPT:2 |

The same accepted TRAIN/VALIDATION/TEST runs permit a paired comparison. The reused TEST has previously been examined: this is **paired reanalysis**, not a fresh blind test. The external session did not enter fitting, threshold or persistence selection, but informed feature hypotheses and is not a completely blind external validation. Six fresh replication sessions are proposed for that purpose.

## Features and fitting

Schema `dataset-v3-features-2.0` has 83 ordered features: all 65 original features plus 18 additions: `semantic_request_count`, `semantic_request_rate`, `asset_request_count`, `asset_request_rate`, `asset_ratio`, `navigation_count`, `semantic_navigation_ratio`, `auth_request_count`, `logout_request_count`, `dashboard_request_count`, `course_view_request_count`, `quiz_request_count`, `profile_request_count`, `theme_request_count`, `unknown_semantic_ratio`, `semantic_unique_path_count`, `semantic_unique_path_ratio`, `successful_response_ratio`. `request_count` already means total requests; `ajax_request_count/ratio`, redirect and error ratios already exist and are not duplicated. No identity, role, POST-body or unavailable context is invented.

TRAIN-only analysis found 16 constant features and 16 pairs with |Pearson r| >=0.98. These are documented, not deleted post hoc. Baseline features are retained for comparability; related count/rate/ratio features are transparent redundancy. XGB gain importance is descriptive TRAIN-model importance, not causal evidence.

Novelty models share the same schema, split and RobustScaler fitted only on TRAIN BENIGN. IF uses 200 trees, n_jobs=1, seed42; OCSVM uses RBF, nu=.1, gamma=scale; LOF uses novelty=True and min(20,n-1) neighbors. XGB retains v1 settings: 200 trees, depth3, learning_rate=.05, deterministic full row/column sampling, hist, n_jobs=1, seed42, eight classes. XGB uses original numerical values; robust reference is TRAIN BENIGN only.

## Validation-only selection

Larger raw score_samples is more normal for all novelty models. A score strictly below sorted benign-validation score[floor(target*n)] is anomalous; equality is normal. Candidates are 1%, 2%, 5%, 10%. Selection admits targets <=5% and realized validation benign FPR <=5%, maximizes validation attack recall, then lower FPR/lower target. Model ties prefer IF, then OCSVM, then LOF. TEST/external never selects parameters.

| Model | FPR target | Threshold | Observed VAL benign FPR | VAL attack recall |
| --- | --- | --- | --- | --- |
| IF | 0.01 | -0.56161251 | 0.0 | 0.031746031746031744 |
| IF | 0.02 | -0.56161251 | 0.0 | 0.031746031746031744 |
| IF | 0.05 | -0.56161251 | 0.0 | 0.031746031746031744 |
| IF | 0.1 | -0.50675484 | 0.058823529411764705 | 0.2857142857142857 |
| LOF | 0.01 | -1.87496120 | 0.0 | 0.49206349206349204 |
| LOF | 0.02 | -1.87496120 | 0.0 | 0.49206349206349204 |
| LOF | 0.05 | -1.87496120 | 0.0 | 0.49206349206349204 |
| LOF | 0.1 | -1.75947648 | 0.058823529411764705 | 0.49206349206349204 |
| OCSVM | 0.01 | 0.63042112 | 0.0 | 0.5238095238095238 |
| OCSVM | 0.02 | 0.63042112 | 0.0 | 0.5238095238095238 |
| OCSVM | 0.05 | 0.63042112 | 0.0 | 0.5238095238095238 |
| OCSVM | 0.1 | 0.90199791 | 0.058823529411764705 | 0.6825396825396826 |

Only 17 benign VALIDATION windows exist; empirical resolution is 5.8824%. Thus 1%, 2% and 5% targets can coincide. Zero observed FPR is not a population guarantee. Selected model: **OCSVM**. All candidate metrics, including poor IF sensitivity, remain in `validation_selection.json` and `unsupervised_comparison.json`.

## Frozen paired TEST results

| Model | BENIGN FPR (11 windows) | Attack recall (58 windows) | Precision | F1 | Serialized bytes | Warm novelty ms/window |
| --- | --- | --- | --- | --- | --- | --- |
| IF | 0.09090909090909091 | 0.05172413793103448 | 0.75 | 0.0967741935483871 | 1042590 | 0.0900 |
| LOF | 0.0 | 0.5862068965517241 | 1.0 | 0.7391304347826086 | 48014 | 0.0202 |
| OCSVM | 0.09090909090909091 | 0.6724137931034483 | 0.975 | 0.7959183673469388 | 14846 | 0.0170 |

Latency is 20 warm local batches including matrix/scaler/schema validation (and its mapper-source hash read), excluding SHAP/XGB/data-artifact I/O. It is measured runtime evidence, not a deterministic artifact or near-real-time SLA. IF seed42/43/44 results are preserved in `seed_stability.json`; OCSVM/LOF have no stochastic seed component. No model uniformly dominates: LOF has lower observed TEST FPR, while validation-selected OCSVM has higher recall. We do not switch models using that TEST observation.

| Classifier | Window macro F1 | Window accuracy | Run macro F1 | Run accuracy |
| --- | --- | --- | --- | --- |
| v1 frozen XGB | 0.9806763285024154 | 0.9855072463768116 | 0.9333333333333333 | 0.9375 |
| v2 XGB | 0.9806763285024154 | 0.9855072463768116 | 0.9333333333333333 | 0.9375 |

All eight classes are present. Full window/run confusion matrices, per-class support/precision/recall/F1 and reconciliation metrics are in the corresponding machine artifacts. XGB scores remain UNCALIBRATED. Run XGB aggregation uses mean class vectors; ties use saved class order. Novelty run aggregation compares mean raw score to the window-calibrated cutoff; its run FPR is measured, not separately calibrated.

## Episode policy and ablation

Raw model disagreements always remain visible. Contiguous same-class windows with identical run/client/agent form an episode; a temporal gap or changed class breaks it. Known confident pattern classifications produce KNOWN_THREAT_ATTEMPT_EPISODE. Unknown anomalies shorter than selected persistence are NOVEL_OBSERVATION, not hidden; UNCERTAIN is also observation-only. These are research candidate semantics, not changes to frozen Fusion/CQI.

| Persistence | VAL benign any-alert run FPR | VAL attack run recall |
| --- | --- | --- |
| 1 | 0.0 | 1.0 |
| 2 | 0.0 | 1.0 |
| 3 | 0.0 | 0.9285714285714286 |

Validation selected persistence=1; 1 and 2 tie and shortest delay wins. On TEST, persistence2 would reduce the one benign alert run but miss another attack run; this is reporting only, **not permission to reselect**. True episode-level ground-truth intervals do not exist, so we report independently labelled run any-alert metrics and emitted episode counts, not fabricated episode precision/recall.

| Ablation | TEST benign FPR | TEST attack recall |
| --- | --- | --- |
| V1_FROZEN_PACKAGE | 0.2727272727272727 | 0.5862068965517241 |
| V2_FEATURES_CALIBRATED_IF | 0.09090909090909091 | 0.05172413793103448 |
| V2_FEATURES_TRAIN_QUANTILE_OLD_STYLE | 0.18181818181818182 | 0.5 |
| V2_SELECTED_WITH_EPISODE_POLICY | 0.09090909090909091 | 0.6724137931034483 |

Old-style IF means TRAIN score quantile at accepted contamination=.15, not .10. The paired ablation is descriptive: adding semantic features, scaling, calibration and model selection are not a randomized causal experiment. Calibrated IF alone loses substantial attack sensitivity.

## External diagnostic session

| System | BENIGN | UNCERTAIN | UNKNOWN_ANOMALY | Known attempts | Alert episodes | Disagreements |
| --- | --- | --- | --- | --- | --- | --- |
| v1 | 4 | 3 | 4 | 0 | 3 | 4 |
| v2 | 6 | 3 | 2 | 0 | 1 | 2 |

The accepted v1 saved package exactly reproduces the original live decisions and IF scores. v2 reduces anomaly windows 4→2 and alert episodes 3→1 in this diagnostic session. The two large browser resource windows remain UNKNOWN_ANOMALY; the low-volume long-AJAX and later logout-associated windows become BENIGN. This is a promising **descriptive nuisance reduction**, not established externally labelled FPR or universal generalization. Alternative-model scores/decisions and external ablations are retained without selection in `external_02`.

Native exact TreeSHAP explains 69/69 TEST windows, with raw-margin additivity checks and causal=false. TRAIN BENIGN robust deviations remain available. Saved-model replay is byte-value identical and makes no fit calls.

## Research limitations and next capture

Local Moodle testbed, small independent run count (only two BENIGN TEST runs), correlated windows, historical/protocol heterogeneity, coarse capture labels, no confirmed successful exploits, no Apache POST bodies, no calibrated probabilities, reused TEST, and diagnostic-informed feature design limit inference. No independently labelled unseen-attack-class set exists; preservation of arbitrary unknown-threat detection is not established. No confidence interval, population FPR, causal effect, or cross-platform universality is claimed.

A new offline plan proposes 24 genuine browser sessions (six protocols × four independent fresh sessions; 12/6/6 pre-reserved TRAIN/VAL/TEST) and six fresh external replication sessions. This is a coverage quota, not a power calculation. Actual available courses/quizzes/roles must be confirmed; absent actions remain absent. Existing traffic generators cannot substitute for a browser loading embedded assets. No additional traffic was collected. See `M5_BENIGN_CAPTURE_PROTOCOL.md`.

`study_01` is retained as an incomplete output attempt: JSON metadata export rejected XGB’s NaN missing-value sentinel after evaluation. `study_02` fixes only metadata serialization and uses identical selected policy and test predictions; no result-based retuning occurred. `diagnostic_01` and `external_01` remain as earlier descriptive versions.

## Reproduction

See `M5_RESEARCH_PROTOCOL.md` for commands using fresh output names and versioned paths. Accepted v1, M4 checkpoint and pre-existing research files remain intact. Candidate models are not integrated into live inference, Fusion, CQI or UI.
