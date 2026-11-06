# Explainability presentation

No model attribution is invented or recomputed by an API read request. Task 2A
adds deterministic, cached human-readable projections from existing numeric
evidence. See [Behavioral v2 human explainability](BEHAVIORAL_V2_HUMAN_EXPLAINABILITY.md)
for the catalog, TRAIN reference, API contract, ranking and acceptance examples.

XGBoost explanations use the saved upstream `shap_explanation`: status, backend,
raw model-margin output space and signed feature contributions. Positive/negative
bars retain their sign, with width based only on absolute magnitude. Contributions
explain classifier margin, not causal security impact. Scores remain explicitly
UNCALIBRATED. Unavailable SHAP displays "Explainability unavailable for this record".

OCSVM/UNKNOWN details show the saved robust deviations against the frozen benign
TRAIN reference. The label is "Associated deviations — not causal attribution."
These are not OCSVM SHAP values, causal explanations or recalibrated test-derived
statistics. Model disagreement and the frozen reconciliation reason stay visible.

Fusion explanations identify actual episode evidence, reviewed relationship rule
and relevant posture IDs. Context is non-causal and has no extra score effect.
CQI is directly explained by deduplicated contributions, six dimension products,
equal weights, policy coefficient tables and twelve weight-sensitivity variants.
It does not require fabricated SHAP attribution.

The application distinguishes source evidence, policy-derived presentation labels,
live journal observations, replay projection identifiers and locked evaluation
metrics. An observation can remain suppressed without hiding its raw model
decision or its contribution under the separate frozen CQI policy.
