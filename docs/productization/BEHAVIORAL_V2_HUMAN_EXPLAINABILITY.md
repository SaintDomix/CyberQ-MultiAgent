# Behavioral v2 human-readable interpretation

This is an offline derived presentation layer. It neither invokes a model nor
changes predictions, reconciliation, persistence, episode membership or CQI.
Human-readable explanations are model/evidence interpretation aids. They do not
establish causality, intent, successful exploitation or cross-platform accuracy.

## Data path

The existing application verifies the accepted package and saved predictions.
`demo/backend/explainability.py` projects a raw feature vector, frozen benign
reference, optional saved TreeSHAP and actual model outputs into structured
explanations. `Application.snapshot` caches the projection by source generation.
No new worker, network call, training or attribution computation is introduced.

Live vectors come from the existing SHA256-verified SQLite result payload's
`window.row.features` in a read-only transaction. Nothing is written to the
journal. The legacy `read_journal` default is unchanged. Replay benign vectors
come from hash-locked verified TEST feature sidecars. Attack replay reuses the
frozen parser and extractor on the exact source-hashed, line-selected accepted
events, joining run/window/client/agent identity. The eight saved deviations
cross-check each joined vector. No foreign capture records are introduced.
Replay resolution is confined to server-controlled accepted evidence roots.
If full source material is absent or invalid, use saved numeric deviations and
report PARTIAL feature coverage. No missing value is invented as zero.

The accepted model remains `behavioral-v2-59a8c7c5d3d51632d0af`, canonical root
`59a8c7c5d3d51632d0afe45f8cd2fe50570b7af2943d26bb313888327ea9f436`.
Feature count is unchanged at 83. Schema `dataset-v3.1-features-2.1`, SHA256
`b85df9aac8b1d8d9553db6e3e8bee4e7496ad9ea9b9d6db96bec3715d5d54caa`.

## Catalog and semantics

`demo/backend/feature_catalog.py` explicitly describes all 83 features. Every
entry includes a reviewed definition, extractor/function source, semantic group,
unit, direction/comparison policy, formatter and relevant classes where supported.
Unknown keys are technical-only and excluded from primary explanation. There
are 83 verified human-readable entries and zero unverified entries in this schema.
Optional identity/session/role or response-size quantities are not interpreted
when their coverage indicator is zero. Verified semantics do not imply that
every field is observable in ordinary Apache logs.

Sources are `branch2.features.extract`, `behavioral_v2.features31.extract`, and
the frozen `MoodleBehaviorAdapter.map_request`. In particular:

- Authentication-path counts include login/logout routes, not credential failures
  or authenticated identities inferred from URLs.
- Administrative categories include the adapter's admin/report routes.
- Non-asset requests include UNKNOWN semantics; navigation excludes UNKNOWN,
  assets, AJAX and application API categories.
- Percent-encoding ratio measures encoded character triplets, not request share.
- SQL/XSS indicators are lexical counts in URL queries. Traversal indicators use
  path plus query. Apache combined logs contain no POST body telemetry.
- 2xx response share does not establish authentication or operation success.
- Timing gaps use logged request timestamps; a lone request has no interpretable
  inter-request interval. No fabricated precision or user intent is inferred.

## Benign reference

`demo/backend/explanation_reference.json` is a separate derived sidecar, not a
model artifact. It reuses the frozen `model/benign_reference.json`: median,
MAD and effective robust scale from **101 benign TRAIN windows, 17 runs**.
The run IDs and hashes of the source reference and preprocessing are recorded.
No validation, TEST, attack holdout or external live session is used to estimate
this reference. No data or models are copied or refitted.

The original reference method is median and MAD; effective scale is 1.4826*MAD
when positive, otherwise IQR/1.349 when positive, otherwise
max(abs(median)*0.1,1). These are raw extractor-space values; they are distinct
from OCSVM's frozen RobustScaler parameters. The sidecar's canonical SHA256 is
`37ed6aba4c569788e1a7df9075684a86e9e9c34e34155c05bd78c52e06b1604e`;
file SHA256 `09f81e70e035d1098b4a088220832cd17ab7b0a527e5386ee7cb754ed63a74a3`.

Reproduce without fitting:

```bash
PYTHONPATH=src:. .venv/bin/python -B scripts/build_explanation_reference.py
```

The exporter refuses to replace a different sidecar. It verifies the accepted
package first. Its reference method is implemented in
`behavioral_v2.inference.robust_reference`, originally called by
`behavioral_v2.study31.train_freeze`. The exporter does not call that trainer.

## The two questions and ranking

**Anomaly question:** OCSVM's verdict and raw `score_samples` remain exactly the
saved outputs. Factors show observed raw-value deviations `(value-median)/scale`,
not OCSVM feature attribution. Flagged/uncertain windows show absolute deviations
of at least one robust unit, ranked by magnitude capped at 100. The display gate
is descriptive; it is not a new detector threshold or empirical percentile.
BENIGN windows instead show comparisons within one robust unit, prioritizing
traffic, status and paths over less informative all-zero optional counters.
No assertion that all features were normal follows from an inlier verdict.

**Classifier question:** the class is the actual stored XGBoost label. Positive
saved selected-class raw-margin SHAP contributions support classifier factors.
Ranking uses contribution magnitude multiplied by
`1 + min(abs(robust_deviation),10)/100 + 0.1*class_relevant`.
Contribution magnitude is defensively capped at 1e100 for ranking arithmetic
only, preventing overflow from malformed/extreme finite inputs; raw finite
contributions remain visible.
Negative contributions remain in technical details; they are never rendered as
positive support. With missing SHAP, only observed nonzero, class-relevant
deviations are presented, explicitly labelled associated evidence rather than
model attribution. BENIGN never receives forced attack reasoning.

Each question has at most four primary factors, one per semantic group. Ties
use technical feature name. Model outputs/score are always separate from these
descriptive rankings. Scores are not causal evidence. In the real burst example,
response size drove the saved classifier attribution; the explanation does not
invent a high request-rate claim simply because the selected class is DOS-like.

Fractions show percentages with percentage-point differences. Counts/rates/sizes
may show ratios only with a positive median >=1e-6, a larger observation and a
finite ratio <=1e6. Zero/tiny/negative medians use absolute values and differences.
Missing/nonfinite values and unknown feature keys are omitted with explicit
coverage. No NaN/Infinity or zero-denominator ratio is exported.

## SHAP and score meaning

Saved exact native TreeSHAP stays available under technical details, including
signed top-feature contributions, raw-margin output space and additivity error
when present. No SHAP is generated or imputed here. Saved top-eight contributions
are not the full contribution vector and do not causally explain security impact.

XGBoost's score is **the maximum `predict_proba` class score, uncalibrated**.
It is not calibrated confidence or attack probability. OCSVM uses `score_samples`
against the frozen cutoff; its score is not a probability or a SQLi classifier.
Known class values, including SQLI/XSS/PATH `_ATTEMPT`, remain unchanged.
UNCERTAIN and model disagreement are retained without forcing a known incident.

## API, UI and episodes

Existing `/api/behavior/observations`, `/api/evidence/{id}` and
`/api/explainability/{observation_id}` keep their original fields. The explanation
adds `version`, `summary`, `anomaly`, `classification`, `evidence_quality`,
`technical` and `provenance`. Factors contain stable IDs, feature/group/label/unit,
actual/reference values, direction, numeric ratio if valid, comparison, importance,
basis and rendered text. Provenance identifies package/schema/reference/catalog.

The observation drawer now presents these two human questions first. SHAP, signed
deviations, raw vectors, baseline statistics and provenance remain in a technical
expander. BENIGN and UNCERTAIN get appropriate headings. A suppressed isolated
anomaly remains an observation, with its original suppression reason.

Incidents gain an additive `explanation` field: linked/anomalous window counts,
dominant actual classifier class, unchanged timestamps/duration, existing frozen
persistence semantics, and recurring representative factors. Numeric factors
identify a representative observation; they are not an aggregate rate for the
whole episode. No episode boundaries, memberships or escalation are recalculated.
Observation ≠ incident. One episode can contain many windows.

Only allowlisted numeric feature fields and attribution fields enter the derived
explanation. Unknown raw payload fields, queries, cookies, credentials, bodies,
session IDs and URLs are not echoed. Existing presentation sanitization remains
in place. Numeric optional metadata describes coverage, not personal identities.

## Acceptance and reproducibility

Final acceptance artifacts: `outputs/explainability/task2a_acceptance_01/`.
`examples.json` contains real examples for all eight classes, actual run/observation
IDs, ground truth, novelty/class outputs, structured factors and SHAP availability.
`report.md` renders each example; `feature_catalog.json` and `hashes.json` provide
the reviewed catalog and artifact integrity. This is interpretation acceptance,
not a new model evaluation or a re-estimation of locked research metrics.

```bash
PYTHONPATH=src:. .venv/bin/python -B scripts/evaluate_human_explanations.py \
  --out outputs/explainability/task2a_acceptance_01
PYTHONPATH=src:. .venv/bin/python -B scripts/export_product_test_payload.py
cd demo/frontend
PATH=/tmp/node-v22.14.0-linux-x64/bin:$PATH npm test
PATH=/tmp/node-v22.14.0-linux-x64/bin:$PATH npm run build
```

Use a new output directory for repeat acceptance; existing acceptance artifacts
are never overwritten. The test fixture path `/tmp/product_api_test_payload.json`
contains real accepted application projections for render testing. An explicit
empty-state render fixture is separate from retained workstation posture state.

Limitations: laboratory/student-role reference support; no population or other-LMS
accuracy claim; no POST-body visibility; lexical indicators can be benign; no
causal OCSVM explanation; limited saved SHAP features; partial vectors may yield
fewer factors. A reference/presentation failure leaves predictions and CQI intact
and displays explanation unavailable. No LLM, network, random wording or
time-dependent factor selection is involved.
