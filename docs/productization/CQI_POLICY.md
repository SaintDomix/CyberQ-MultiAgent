# CQI policy presentation

The authoritative policy is unchanged in `src/fusion/schema.py`, `cqi.py`,
`dedup.py` and `pipeline.py`; its research protocol remains authoritative.
The application calls `assemble()` directly and never invents a UI score.

Dimensions: D1 Transport/HTTP, D2 Identity/session/access, D3 Exposure/disclosure,
D4 Patch/vulnerability management, D5 Server hardening/integrity,
D6 Behavioral threat activity. Baseline weights are exactly 1/6 each.
Missing evidence remains insufficient and available weights are normalized by
the existing implementation. No perfect security is inferred from missing data.

Posture contribution = severity × result × confirmation coefficient.
Severity CRITICAL/HIGH/MEDIUM/LOW/INFO = 1/.75/.5/.25/0.
Result FAIL/PARTIAL/PASS/DISMISSED/NOT_APPLICABLE = 1/.5/0/0/0.
Confirmation CONFIRMED/VERSION_BASED/NOT_CONFIRMED/FALSE_POSITIVE/
NOT_APPLICABLE = 1/.7/.35/0/0; NOT_TESTED is coverage-only.
No source confidence multiplier is invented. A dismissed false positive stays
zero even when severity is absent; the UI never fabricates a source severity.

Behavior BENIGN/UNCERTAIN/UNKNOWN = 0/.15/.4; enumeration/admin = .5;
brute-force/burst/SQLI/XSS/traversal attempts = .75. Reconciliation support
coefficients remain the frozen policy: classifier-only known support .8;
anomaly-supported known and UNKNOWN support 1; benign support 0.
Classifier confidence is not used as a calibrated probability multiplier.

Reviewed shared roots use maximum member contribution. Same-class contiguous
behavioral windows are one CQI episode with max contribution. Separated streams
remain distinct. Dimension risk = 1 − product(1 − cluster contribution);
quality = 100 × product(1 − contribution). CQI is the weighted average of
available quality dimensions. All coefficients are transparent ordinal policy,
not empirical probabilities. Internal precision is retained; UI displays two
decimals. Standalone contributor deductions are **not additive**.

Incident persistence and CQI are distinct: a suppressed isolated UNKNOWN is not
an incident, but still contributes to the unchanged raw-evidence CQI policy.
The API exposes this explicitly and separately counts current-horizon incidents.
Do not filter observations out merely to make D6 look better.

The twelve ±20% dimension-weight variants come from the existing sensitivity
function. Weights were not tuned from the displayed result. CQI is a quality
index, never a compromise/attack/security probability or a CVSS replacement.
