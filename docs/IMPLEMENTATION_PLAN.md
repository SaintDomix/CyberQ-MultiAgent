# Five-Day Full Model Implementation Plan

## DAY 1 — Unified Branch 1

Goals:

- audit all existing Branch 1 code;
- define one normalized finding schema;
- integrate external scanner;
- integrate internal Moodle assessment;
- integrate vulnerability/advisory intelligence;
- integrate role/access validation;
- build Active Validation framework;
- implement safety/context gates.

Target active validators:

- SQL injection
- XSS / unsafe reflection
- open redirect
- sensitive path/file exposure
- authentication/account enumeration
- access control
- session/authentication checks
- selected SSRF context

Acceptance:

Branch 1 can be run as one pipeline and produces one normalized finding set
with evidence and confirmation status.


## DAY 2 — Complete Active Validation + Final Behavioral Dataset

Branch 1:

- finish selected active validators;
- add tool adapters only where useful:
  ZAP / Nikto / Semgrep / Gitleaks;
- normalize tool findings.

Branch 2:

- freeze feature schema;
- preserve existing behavioral features;
- add SQLi/XSS/path-traversal request features;
- extend controlled benign and suspicious dataset where required;
- establish final scenario protocol;
- enforce run-level train/test split.

Acceptance:

The complete dataset can be rebuilt reproducibly and active validators produce
structured evidence.


## DAY 3 — Final Behavioral AI

Isolation Forest:

- benign-only training;
- window-size sensitivity;
- contamination sensitivity;
- held-out-run evaluation;
- anomaly-severity scoring;
- unknown-anomaly support.

XGBoost:

- multiclass known-threat classification;
- run-level train/test separation;
- class-level metrics;
- probability/confidence calibration where justified.

Explainability:

- robust feature deviations;
- SHAP;
- semantic explanations.

Required evaluation:

- confusion matrices
- precision
- recall
- F1
- false-positive rate
- specificity
- macro-F1 for multiclass classification
- per-class metrics
- scenario-level results

Acceptance:

Known attacks can be classified;
unknown anomalies remain detectable;
predictions have evidence-backed explanations.


## DAY 4 — Evidence Fusion and Cybersecurity Quality Assessment

Implement unified evidence schema.

Implement:

- normalization
- root-cause deduplication
- severity mapping
- confidence mapping
- contextual adjustment
- cross-branch correlation
- security-dimension assessment
- documented scoring formula
- Cybersecurity Quality Index
- recommendations

Build:

`run_full_assessment.py`

Acceptance:

One command can combine both branches and create one integrated assessment.


## DAY 5 — Freeze, Validate and Prepare Defense Outputs

No major new architecture.

Run the complete pipeline from clean inputs.

Verify:

- reproducibility
- no train/test leakage
- correct ground truth
- false-positive behavior
- active-validation evidence
- finding semantics
- scoring formulas
- deduplication
- cross-branch correlations

Generate:

- final JSON
- final CSV
- final report
- model metrics
- confusion matrices
- SHAP plots
- anomaly plots
- security-dimension summary
- CQI
- methodology tables
- architecture information
- README
- exact reproduction commands

Tag the reproducible final release in Git.


# Critical Path

The required final architecture is:

Branch 1
+
Isolation Forest
+
XGBoost
+
SHAP
+
Evidence Fusion
+
Security Dimensions
+
Cybersecurity Quality Index
+
Integrated Runner

Do not divert effort to optional large components before this works.


# Quality Criteria

"Good model results" means:

- correct methodology;
- real evidence;
- reproducibility;
- no train/test leakage;
- acceptable false-positive behavior;
- stable results across runs;
- meaningful explanations;
- explicit limitations.

It does NOT mean forcing artificially high accuracy or F1.
