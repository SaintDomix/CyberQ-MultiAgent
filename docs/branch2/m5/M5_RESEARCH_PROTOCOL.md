# M5 offline behavioral research protocol

This is an additive research candidate, not a replacement of accepted Model v1.
M4B is preserved on `m4-demo-ui` in WIP `a3f9100`; research branch
`m5-behavioral-v2` starts at accepted `milestone-3-end-to-end` (`30aa494`).
No M5 commit/tag, live traffic, model promotion, UI change or CQI change is made.

## Architecture

Existing Apache adapter → existing canonical events → exact existing 10-second
windows → 65 replay-verified features + deterministic Moodle semantic adapter →
83-feature schema → parallel novelty models / XGB → raw reconciliation →
candidate episode policy → offline paired evaluation / saved-model inference.

All implementation is in `src/behavioral_v2/`. Existing v1 modules are imported
for verified adapters, original features, split validation, coefficients-free
metrics and unchanged reconciliation. No accepted source file is rewritten.
The Moodle adapter is separate from numerical model fitting. Another platform
needs an explicit adapter and new schema hash; this is not proof of universality.

## Dataset and leakage

Dataset v3 replays authoritative line-numbered observations from the original
Dataset v2 run inventory. It verifies capture SHA256, original feature equality,
window membership and dummy exclusions. It keeps all 82 included runs, 392
windows and eight classes; TEST-run01 remains excluded. Failed capture roots
are never imported. Reuse of the frozen M2C split yields 50 TRAIN (243 windows),
16 VALIDATION (80), 16 TEST (69). BENIGN quotas are 8/2/2 runs; attacks 6/2/2.
The original split implementation checks source files/hashes/observations and
capture intervals; external IDs/capture hashes are additionally rejected.

This TEST is already known from v1, so M5 results are paired reanalysis, not a
new blind test. The October9 session remains unlabelled external diagnostic
data. It informed feature hypotheses; excluding it from fit/calibration does
not make the feature-design process blind. New independent replication is
needed before a stronger generalization claim.

## Feature policy

Schema `dataset-v3-features-2.0` has 83 features. Original 65 stay in identical
order with identical meanings. Every added feature is deterministic from paths
and observed HTTP status; no attack label is used by the adapter. Explicit
mounted `/moodle/` rules identify login/logout/dashboard/course/quiz/profile/
admin/AJAX/assets/theme/API/navigation/unknown. More-specific paths take priority.
Unknowns are retained and counted. `semantic_request_count` excludes assets,
includes AJAX/API and unknowns; it does **not** discard any original evidence.

| Added features | Rationale |
| --- | --- |
| semantic_request_count/rate | Application activity separated from asset fan-out |
| asset_request_count/rate, asset_ratio | Keep resource evidence while quantifying browser support traffic |
| navigation_count, semantic_navigation_ratio | Navigation versus support/API mix |
| auth_request_count, logout_request_count | Observable authentication navigation, not successful authentication |
| dashboard_request_count, course_view_request_count | Supported Moodle navigation context |
| quiz_request_count, profile_request_count | Differentiate ordinary activity paths without asserting completed actions |
| theme_request_count | Dynamic theme resources often lack static filename extensions |
| unknown_semantic_ratio | Expose unmapped paths rather than silently discard them |
| semantic_unique_path_count/ratio | Breadth after separating assets |
| successful_response_ratio | Observed 2xx share; “successful response” does not imply authorization or exploit success |

No feature is removed. `request_count/rate` already represent total traffic;
existing AJAX counts/ratios, redirects and HTTP error ratios are reused. No
invented “burst” cutoff is added. TRAIN-only low variance, Pearson redundancy
and fitted XGB importance are reported; redundant numerical variants remain
transparent for comparability. Quotes/SQL lexical tokens remain observations,
not proof of malicious intent. POST bodies are unavailable.

## Predeclared selection

`experiment.PROTOCOL` is persisted before fitting. All novelty models use
RobustScaler fitted solely on TRAIN BENIGN; raw feature distributions remain
available for explanation. IF: 200 trees, seed42, n_jobs1, default fit
contamination .1 **only sets an unused estimator offset**; decisions use a
separately validation-calibrated raw score threshold. OCSVM: RBF, nu .1,
gamma scale. LOF: novelty=True, min(20,n−1) neighbors, n_jobs1. All fit benign
TRAIN only. OCSVM/LOF are deterministic; IF seeds42/43/44 are reported without
choosing a seed on TEST.

For raw normality scores s (higher=more normal), sort benign VALIDATION scores.
For target α in {.01,.02,.05,.10}, cutoff = s[floor(αn)], and anomalous iff
score < cutoff. Ties are normal. This bounds empirical calibration FPR by α,
not unseen population FPR. With only17 benign validation windows, 1/2/5% coincide.

Admit target<=5% and observed validation benign FPR<=5%; maximize validation
attack recall, then lower realized FPR, then lower target. Among models use
validation recall, lower FPR, then IF/OCSVM/LOF simplicity order. This is a
declared operational FPR ceiling, not an empirically established optimum.
Models/thresholds are selected without TEST or external results. All threshold
candidates receive subsequent TEST **reporting only**, with no reselection.
No large hyperparameter search is performed.

XGB preserves v1's 200 depth3 trees, learning rate .05, full deterministic
sampling, hist, n_jobs1, seed42 and eight-class soft scores. Fit is TRAIN only;
scores are uncalibrated. Reconciliation confidence threshold remains .8.
Robust median/MAD (IQR/constant fallback) reference is TRAIN BENIGN only.

## Two-level semantics

Model observation records raw normal/anomalous scores, classifier class,
uncalibrated confidence and disagreement. Existing reconciliation is reused
as a numerical/semantic baseline; its compatibility field `if_anomalous`
means the selected novelty model's binary input in v2, and `anomaly_model`
always identifies IF/OCSVM/LOF. Do not describe OCSVM output as an IF score.

Episode grouping requires exact contiguous window endpoints and same
run/client/user-agent digest and reconciliation decision. No tolerance, fuzzy
matching or ground-truth labels are used. BENIGN produces no alert; UNCERTAIN
is observation-only. Unknown anomaly episodes require persistence1/2/3;
shorter ones remain NOVEL_OBSERVATION with visible disagreement. Confident
known patterns remain KNOWN_THREAT_ATTEMPT_EPISODE regardless of persistence.

Select persistence on VALIDATION: minimize benign run any-alert FPR, maximize
attack-run recall, shortest delay. Persistence1 and2 tie in this study, so1
wins. TEST showing benefits of2 does not authorize retuning. Capture labels
do not give exact true episode intervals: report emitted alert counts and
run any-alert confusion metrics, not fictitious episode-ground-truth accuracy.
These candidate semantics are not integrated into frozen Fusion/CQI.

Run XGB prediction averages class vectors, argmax ties use class order.
Novelty averages raw normality scores and compares to the selected window
cutoff. Run FPR is measured, not calibrated from that window threshold.

## Saved candidate / explainability

`v2_candidate_01/` stores all novelty estimators/scalers, XGB, schema+code hash,
class order, TRAIN BENIGN reference, selected thresholds/model/persistence,
train/validation/test IDs and manifest SHA256. Load verifies every expected
file/hash/schema before trusted local joblib deserialization. Selection/package
hashes are sealed before TEST and external inference. Reloaded predictions
exactly match. `inference.py` contains no fit call.

Exact native TreeSHAP uses final XGB raw margins, validates full-vector
additivity and reports unavailable on failure. Robust deviations are
descriptive, causal=false. No causal security impact or exploit success follows.

## Reproduce in NEW directories

```bash
cd /home/saintdomix/dissertation_model
.venv/bin/python -B scripts/run_branch2_m5.py diagnose --out outputs/branch2/m5/diagnostic_replay_01
.venv/bin/python -B scripts/run_branch2_m5.py build --out data/branch2_v3/replay_01
.venv/bin/python -B scripts/run_branch2_m5.py train --dataset data/branch2_v3/replay_01/dataset.json --out outputs/branch2/m5/study_replay_01
.venv/bin/python -B scripts/run_branch2_m5.py external --dataset data/branch2_v3/replay_01/dataset.json --study outputs/branch2/m5/study_replay_01 --session runtime/demo/31aff64be5fd482ebfbd2679f157ab73/live_001 --out outputs/branch2/m5/external_replay_01
.venv/bin/python -B scripts/run_branch2_m5.py infer --model outputs/branch2/m5/study_02/v2_candidate_01 --rows outputs/branch2/m5/diagnostic_02/external_rows.json --out outputs/branch2/m5/inference_replay_01
.venv/bin/python -B scripts/run_branch2_m5.py plan-benign --seed 42 --out outputs/branch2/m5/capture_plan_replay_01
.venv/bin/python -B -m unittest discover -s tests -v
```

Diagnosis/external reconstruction reads **only recorded bounded source bytes**
and verifies inode/device/hash. If Apache rotates or bytes disappear, it fails
closed; inference from already-derived feature rows remains available.
Never export raw queries or read the complete live log to guess missing data.
All outputs refuse overwrite and are restricted to new M5/v3 locations.
Deterministic predictions/splits are distinct from measured latency, which
varies with system load. Library versions and source hashes belong in the
study integrity manifest; latency is not used for result selection.
Timing includes schema validation (and its small mapper-source hash read),
but excludes raw-data/artifact I/O and SHAP. Earlier machine timing descriptions
in study_02/external_02 abbreviate that distinction as “excludes I/O”.

## Interpretation

Controlled labels are attempts/patterns, not successful exploitation.
No probability calibration, confidence interval or cross-LMS generalization
is claimed. M5 disposition remains B: retain v1 until representative new
browser protocols and a genuinely blind replication support promotion.
Novelty detectors were trained without attack samples, but evaluated attacks
belong to the eight existing protocol classes. There is no independently
labelled unseen-attack-class set; preservation of detection for arbitrary
unknown threats has not been established.
