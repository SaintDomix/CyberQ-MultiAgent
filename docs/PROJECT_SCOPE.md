# Final Dissertation Model Scope

## Objective

Build one integrated hybrid cybersecurity-assessment model for Moodle /
adaptive educational platforms.

The model consists of:

1. Branch 1 — Vulnerability and Security Posture Assessment
2. Branch 2 — Behavioral Threat and Anomaly Analysis
3. Evidence Fusion
4. Security-Dimension Assessment
5. Cybersecurity Quality Index
6. Explainable findings and recommendations


# BRANCH 1
## Vulnerability and Security Posture Assessment

Branch 1 answers:

"What weaknesses or exploitable security conditions exist in the platform?"


## 1. External Security Assessment

Required scope:

- HTTPS/TLS posture
- HTTP-to-HTTPS behavior
- security headers
- cookies and session transport properties
- HTTP methods
- information disclosure
- exposed development/resources files
- public attack surface
- Moodle-specific externally visible endpoints


## 2. Internal Moodle and Server Assessment

Required scope:

- exact Moodle core version
- plugin/component inventory
- Moodle security configuration
- authentication configuration
- guest/self-registration configuration
- web-services configuration
- session configuration
- PHP/runtime context
- filesystem ownership and permissions
- Moodle application-root security
- Moodle data-root context


## 3. Vulnerability Intelligence

Required scope:

- Moodle/vendor security-advisory matching
- affected-version range evaluation
- plugin/core vulnerability intelligence
- context-aware exposure analysis

A version match must remain VERSION_BASED until stronger evidence exists.


## 4. Authentication and Access-Control Assessment

Support role-aware validation for available roles such as:

- anonymous
- student
- teacher
- manager
- administrator

Assessment must compare actual accessible content/functions and not rely only
on HTTP status codes.

Target issues include:

- unintended authenticated access
- role/capability inconsistencies
- information disclosure
- authentication weaknesses
- selected broken-access-control conditions


## 5. Safe Active Validation

A dedicated Active Validation Layer must determine whether a candidate weakness
is relevant and whether a safe runtime test should be performed.

Required core validation scope:

- selected SQL injection validation
- XSS / unsafe-reflection validation
- open redirect validation
- sensitive file/path exposure
- authentication/account enumeration
- access-control validation
- session/authentication controls
- selected SSRF-relevant contextual validation

Pipeline:

candidate evidence
→ context/safety gate
→ controlled active request(s)
→ baseline/test comparison
→ confirmation status
→ structured evidence

Active validators must be safe and non-destructive by default.

A finding does not require active validation to remain a valid finding.

Passive, internal, configuration, role, source-code, or version evidence may
already be sufficient to produce a structured finding.

Active validation is an optional evidence-strengthening stage for findings
where:
- an applicable validator exists;
- runtime confirmation is meaningful;
- the test is safe and authorized.

Absence of an active validator must not suppress an otherwise supported finding.


## 6. Supporting Security Tools

Supporting evidence may be collected from:

- OWASP ZAP
- Nikto
- Semgrep
- Gitleaks

These tools are evidence sources.

Their output must be normalized, contextualized and deduplicated by our model.
The final model must not simply copy scanner results.


# BRANCH 2
## Behavioral Threat and Anomaly Analysis

Branch 2 answers:

"What suspicious or attack-like behavior is occurring against the platform?"


## Input

- Apache access/error logs
- Moodle security-relevant logs
- sanitized request-derived security features where necessary
- authenticated user/session context where available
- Moodle role/capability context where available
- resource/action context from Moodle application logs


## Pipeline

logs
→ parsing
→ temporal aggregation
feature extraction
        ↓
 ┌──────┴────────┐
 ↓               ↓
Isolation      XGBoost
Forest
 ↓               ↓
unknown /      known-threat
anomaly        classification
 └──────┬────────┘
        ↓
decision reconciliation
        ↓
explainability
        ↓
behavioral security event


## Isolation Forest

Purpose:

unsupervised detection of deviations from legitimate Moodle behavior.

Training:
benign behavioral runs only.

Outputs:

- NORMAL / ANOMALOUS
- raw anomaly score
- interpretable anomaly-severity score
- UNKNOWN_ANOMALY capability


## XGBoost

Purpose:

supervised classification of known behavioral threat patterns.

Core target classes:

- BENIGN
- BRUTE_FORCE
- ENUMERATION_RECONNAISSANCE
- ADMIN_PROBING
- REQUEST_BURST_DOS_LIKE
- SQLI_ATTEMPT
- XSS_ATTEMPT
- PATH_TRAVERSAL_ATTEMPT

Additional classes may be implemented only if supported by sufficient data:

- ACCOUNT_ENUMERATION
- SCRAPING_LIKE
- SESSION_ABUSE_LIKE
- UNUSUAL_PRIVILEGED_ACTIVITY


## Behavioral Features

Preserve and verify the existing behavioral/window features.

Add justified request/query-derived features for application-attack behavior,
including where appropriate:

- query length
- parameter count
- URL-encoding ratio
- special-character statistics
- quote statistics
- comment-token statistics
- SQL-related lexical indicators
- XSS/script-related lexical indicators
- traversal-related lexical indicators
- request-method/context indicators
- response/status changes

Avoid storing sensitive request content unnecessarily.

Additional target behavioral classes:

- ACCOUNT_ENUMERATION
- SCRAPING_LIKE
- SESSION_ABUSE_LIKE
- UNUSUAL_PRIVILEGED_ACTIVITY
- ABNORMAL_BULK_ACCESS

The architecture must allow adding behavioral classes,
feature extractors and active validators without modifying
the evidence/fusion core.

Additional contextual feature groups may include:

Identity/session features:
- user/session activity counts
- session switching/reuse indicators
- authentication success/failure patterns
- user-agent/IP consistency where ethically and technically appropriate
- post-login behavioral transitions

Role/context features:
- role-aware endpoint/action distributions
- privileged-action ratios
- deviation from normal role behavior

Resource/data-access features:
- resource-access breadth
- download/access frequency
- cumulative response volume
- repeated resource traversal
- abnormal bulk-access indicators


## Explainability

Required layers:

1. Robust/statistical feature-deviation analysis
2. SHAP attribution for supervised model predictions
3. Security-semantic explanation

SHAP identifies which features contributed to a prediction.

The semantic layer converts evidence into cautious security terminology such as:

"brute-force-like activity"

rather than:

"confirmed brute-force attack"

unless supporting evidence genuinely justifies confirmation.

If Isolation Forest detects an anomaly while the known-threat classifier has
insufficient confidence:

UNKNOWN_ANOMALY / MULTIVARIATE_OUTLIER


# EVIDENCE FUSION

Both branches must output normalized structured evidence.

Required fields should include, where applicable:

- source
- branch
- category
- finding/event type
- affected asset
- severity
- confidence
- confirmation status
- root cause
- temporal context
- evidence
- explanation
- recommendation

Fusion must perform:

- normalization
- root-cause deduplication
- confidence weighting
- context adjustment
- cross-branch correlation


## Cross-Branch Correlation Example

Branch 1:

SQL-injection-relevant weakness/exposure

+

Branch 2:

SQLI_ATTEMPT observed

=

higher-confidence correlated security risk.


# SECURITY DIMENSIONS

Target dimensions:

- Transport Security
- Configuration Security
- Patch and Vulnerability Management
- Authentication and Session Security
- Access Control
- Exposure and Information Disclosure
- Behavioral Threat Security


# FINAL ASSESSMENT

The final system must produce:

- normalized findings
- behavioral events
- evidence
- severity
- confidence
- explanations
- recommendations
- security-dimension scores
- overall Cybersecurity Quality Index
- machine-readable JSON/CSV outputs
- human-readable report
- dissertation-ready tables and plots


## Scoring Requirements

Every score must have:

- a documented formula;
- a documented interpretation;
- reproducible input evidence.

Do not double-count multiple findings caused by the same root cause.

The Cybersecurity Quality Index is NOT an attack probability.


# FINAL INTEGRATED RUNNER

Target user-facing entry point:

`python run_full_assessment.py ...`

It should orchestrate:

Branch 1
→ Branch 2
→ Evidence Fusion
→ Security-Dimension Assessment
→ Final Cybersecurity Quality Assessment
→ Reporting


# Out of Critical Path

Do not add these until the required architecture works correctly end-to-end:

- LSTM / LSTM Autoencoder
- Kafka/SIEM infrastructure
- real-time distributed pipelines
- GUI dashboards
- large custom exploit frameworks
- unrelated deep-learning models

Additional models are optional extensions, not prerequisites.


## Extensibility Requirement

The architecture must allow new:

- Branch 1 finding rules;
- active validators;
- behavioral feature extractors;
- behavioral threat classes;
- evidence sources;

to be added without redesigning the canonical evidence contracts,
Evidence Fusion core, or final assessment pipeline.