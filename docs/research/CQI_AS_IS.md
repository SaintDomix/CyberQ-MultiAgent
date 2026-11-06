# CQI before Task 3A

Policy `fusion-cqi-1.1` is implemented in `src/fusion/schema.py`,
`adapters.py`, `dedup.py`, `cqi.py` and `pipeline.py`. It is unchanged by this task.

Dimensions are D1 TRANSPORT_HTTP_PROTECTION, D2 IDENTITY_SESSION_ACCESS,
D3 EXPOSURE_DISCLOSURE, D4 PATCH_VULNERABILITY_MANAGEMENT,
D5 SERVER_HARDENING_INTEGRITY and D6 BEHAVIORAL_THREAT_ACTIVITY.

Posture contribution is severity × result × confirmation. Severity coefficients
are 1/.75/.5/.25/0 for CRITICAL/HIGH/MEDIUM/LOW/INFO; result coefficients are
1/.5/0/0/0 for FAIL/PARTIAL/PASS/DISMISSED/NOT_APPLICABLE; confirmation
coefficients are 1/.7/.35/0/0 for CONFIRMED/VERSION_BASED/NOT_CONFIRMED/
FALSE_POSITIVE/NOT_APPLICABLE. NOT_TESTED is excluded. Other unknown coefficients
exclude a row unless an eligible zero disposition takes precedence.

Reviewed shared roots use a maximum contribution. Rules merge plaintext-related
controls, filesystem-write observations, and Moodle patch/advisory observations.
Operational Native/ZAP canonicalization precedes Fusion, with explicit weakness
keys and maximum eligible source contribution; titles are never fuzzy matched.

For scored root contributions c_j, Q_d=100 product_j(1-c_j). No eligible root
means Q_d is unavailable. An eligible zero can yield Q_d=100 even if other
controls in that dimension were not observed. Overall CQI is the arithmetic
mean of available dimensions, with baseline weights 1/6 renormalized to their
available sum. Bounds are 0–100; higher means better policy-defined quality.
Backend states are SCORED/PARTIAL_EVIDENCE/INSUFFICIENT_EVIDENCE; operational
presentation adds PARTIAL_EVIDENCE when it detects missing checks. There is no
validated universal numeric band defining secure/compromised operation.

D6 consumes saved reconciliation observations, not incident lifecycle state.
Behavior coefficients are BENIGN=0, UNCERTAIN=.15, UNKNOWN=.4,
enumeration/admin=.5, other known attempts=.75. Model disagreement support=.8,
other qualifying support=1. XGBoost scores are not probability multipliers.
Adjacent same-class observations with retained stream identity merge using max
contribution, but suppressed isolated anomalies can still depress CQI. Recent
evidence uses an inclusive 300-second emission-time horizon; default as-of is
latest evidence time. Old episodes can leave that horizon without resolution.

Historical assessments are immutable files under runtime/posture. The application
reads them and journals, calls assemble(), and projects CQI into typed API schemas.
It computes, rather than overwrites, research CQI on read. Research JSON/metrics
and old snapshots remain available independently of new policy versions.

Verified mathematical limitations:

- No fixed applicability/coverage denominator enters the old score.
- Excluding failed/unavailable dimensions renormalizes weights and can raise the
  scalar despite reduced observability. Presentation cautions cannot bound this.
- A single confirmed critical contribution makes a dimension exactly zero.
  Multiplication can rapidly saturate near zero for multiple independent findings.
- Arithmetic aggregation permits strong dimensions to compensate for a weak one.
- D6 observation penalties are disconnected from accepted incident persistence.
- No explicit closed/resolved scoring state exists; temporal exclusion alone
  can appear to be recovery.

These are code-verifiable behaviors. Whether exponential severity scaling,
geometric aggregation or a specific guard is preferable is a normative design
choice requiring property and sensitivity analysis, not an empirically proven bug.

Pre-change local reproduction: accepted benign replay 52.75878906249999;
attack replay 36.092274983723954; retained posture
posture-20261028T181407Z-06aa5f745e5b posture-only score
40.23080444335938. These are old-policy, evidence-time results, not live
measurements of improved or worsened platform security.
