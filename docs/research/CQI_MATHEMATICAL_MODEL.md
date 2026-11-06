# A coverage-aware evidence model for the Cybersecurity Quality Index

Task 3A; implementation `src/cqi_v2`; policy `cqi-evidence-2.0`;
response schema `scientific-cqi-response-2.0`. This document specifies the
implemented algorithm. The original `fusion-cqi-1.1` remains unchanged.

## 1. Research problem and measured construct

The system combines security-posture observations with reconciled Behavioral v2
episodes. The construct is **ordinal cybersecurity quality supported by the
available, scoped evidence at a declared time**, not probability of compromise,
security, exploitation or attack. A scalar without scope and coverage is an
incomplete measurement. The result therefore includes a conditional estimate,
a conservative missing-control envelope, observability, evidence reliability,
dimension decompositions and provenance.

This is a normative research-prototype index. No breach-cost, expert-elicitation
or population calibration dataset was available. Coefficients and the
non-compensation rule are explicit policy assumptions, not statistically fitted
security-risk estimates. Percent-like 0–100 units are index points, not event
frequencies. Internally exact floating-point values are retained; four significant
figures in a report do not imply corresponding measurement accuracy.

## 2. AS-IS baseline and verified limitations

See `CQI_AS_IS.md` and the retained `baseline_legacy_outputs.json`. Old posture
hazard was severity × finding-result × confirmation, with maximum contribution
per reviewed shared root. Dimension quality was the complementary product
\(Q_d=100\prod_j(1-c_j)\). The overall index was the weighted arithmetic mean
of **available** dimensions, baseline weights 1/6, renormalized after exclusions.

Verified code behavior: a critical confirmed contribution of one makes a
dimension zero; multiple products can saturate near zero; missing controls do
not enter a fixed denominator; unavailable dimensions are dropped; arithmetic
averaging permits compensation; D6 includes raw anomaly observations even when
they are not episodes. A 300-second emission-time window can exclude an old
observation without any resolution assertion. These facts do not establish that
every new design parameter below is empirically optimal.

Reproduced old scores: benign replay 52.75878906249999; attack replay
36.092274983723954; retained partial posture
`posture-20261028T181407Z-06aa5f745e5b` 40.23080444335938. They remain historical
v1 results. Changes under v2 are policy reanalysis, never target-state changes.

## 3. Actual dimensions and evidence boundary

| ID | Exact repository dimension | Mapped source categories |
|---|---|---|
| D1 | TRANSPORT_HTTP_PROTECTION | Transport Security; Security Headers; HTTP Configuration |
| D2 | IDENTITY_SESSION_ACCESS | Authentication & Session; Access Control; Authentication & Access |
| D3 | EXPOSURE_DISCLOSURE | Information Disclosure; Exposure; Privacy & Exposure |
| D4 | PATCH_VULNERABILITY_MANAGEMENT | Patch & Vulnerability Intelligence |
| D5 | SERVER_HARDENING_INTEGRITY | Server-side Configuration; Runtime Hardening; Network Egress / SSRF Defense |
| D6 | BEHAVIORAL_THREAT_ACTIVITY | Accepted reconciled episodes and current telemetry availability |

Category mapping is reused from `fusion.schema.CATEGORIES`. No new CQI mapping
is invented for UNMAPPED ZAP alerts. Such alerts remain visible in warnings and
the existing findings interface, without a fabricated penalty.

Inputs are one verified current posture snapshot and accepted behavioral
observations/episodes, each scoped to the assessed deployment. Multiple posture
assessment IDs in a call are rejected. API inputs are resolved through existing
hash-verified snapshots/journals; the mathematical function assumes this trusted
input boundary. A synthetic caller can construct test values but cannot thereby
establish a real vulnerability or successful exploitation.

## 4. Notation and domains

| Symbol | Meaning and domain |
|---|---|
| \(t\) | Explicit UTC assessment as-of time |
| \(d\in\mathcal D\) | Applicable dimensions among D1–D6 |
| \(i\in C_d\) | Fixed applicable control identity in dimension d |
| \(j\in J_d\) | Reviewed weakness/root unit, with control members \(C_j\) |
| \(s_i\in[0,1]\) | Ordinal severity coefficient |
| \(r_i\in[0,1]\) | Evidence-reliability discount, not probability |
| \(b_i\in\{0,\beta,1\}\) | Supported weakness/result multiplier |
| \(k_i\in\{0,\kappa,1\}\) | Fresh observability of a control |
| \(h_i=s_i r_i b_i\) | Supported weakness hazard in index units |
| \(h_j=\max_{i\in C_j}h_i\) | Root hazard; source duplicates are not summed |
| \(u_j\ge h_j\) | Root hazard with policy allowance for unobserved control portions |
| \(\lambda>0\) | Hazard-to-quality scale; default ln(2) |
| \(w_d>0\) | Dimension weight, default 1/6 |
| \(g\in[0,100]\) | Maximum overall compensation over weakest dimension; default 20 points |
| \(\widehat Q_d,L_d,U_d\) | Conditional quality, lower-envelope and upper-envelope values, 0–100 |

All persisted computations use deterministic ordering and finite arithmetic.
Different evidence metadata can change result hashes while leaving analytical
values invariant. The default policy is fingerprinted by a canonical SHA256;
variants share the version name but have distinct parameter hashes.

## 5. Finding-level evidence and current status

Severity is INFO=0, LOW=.25, MEDIUM=.5, HIGH=.75, CRITICAL=1. These ordinal
coefficients preserve the existing severity order; they are not CVSS replacement
values or empirical loss ratios. Reliability is CONFIRMED=1, VERSION_BASED=.7,
LIKELY=.5, CONTEXTUAL=.25, NOT_CONFIRMED=.35. A version match remains evidence of
a vulnerable-version condition, not confirmed exploitation. No raw XGBoost
score or numeric ZAP confidence is interpreted as attack probability.

For fresh, applicable evidence:

\[
h_i=s_i r_i b_i,\qquad
b_i=\begin{cases}1&\text{FAIL}\\\beta=0.5&\text{PARTIAL}\\0&\text{valid PASS or verified inactive disposition.}\end{cases}
\]

Observability is 1 for supported fresh PASS/FAIL, \(\kappa=.5\) for PARTIAL,
and 0 for NOT_AVAILABLE, NOT_ASSESSED, NOT_TESTED, NOT_REEVALUATED, failed,
invalid or stale collection. PARTIAL thus has **two distinct roles**: an
intermediate observed weakness and incomplete observability; these are separately
reported, not an assertion that half a vulnerability exists.

Unknown severity/reliability/status excludes a definitive contribution and marks
the control unobserved. INFO carries zero hazard by policy even when recorded
as FAIL; it remains a visible observation. A low-reliability FAIL has nonzero
hazard, is not PASS and reduces effective reliability coverage. A low-reliability
PASS can have zero supported hazard but is explicitly partial evidence, not a
fully assured perfect assessment.

DISMISSED is not FAIL. An explicit FALSE_POSITIVE disposition is inactive with
observability one; unsupported dismissal is unobserved, not automatically healthy.
The underlying finding is never rewritten. A separate lifecycle record can
establish REMEDIATED/RESOLVED/OBSOLETE only when verified=true, an evidence
reference exists, the source confirmation is CONFIRMED, and its verification
timestamp lies between the source observation and t. Unverified closure does
not erase the weakness. The mathematical function checks consistency; it does
not independently prove the truth of a human verification assertion.

Posture evidence older than 86,400 seconds or in the future is unavailable under
the default current-state policy. This one-day limit is an operational assumption
requiring deployment review. Historic reanalysis explicitly supplies the original
completion time. It does not relabel an old observation as freshly collected.

## 6. Canonicalization, deduplication and comparison scope

The fixed versioned registry enumerates **83 mapped control IDs, 69 reviewed
root units**. It is generated once from existing implementation identities and
stored as the source artifact `control_registry.json`; its canonical hash is checked at load time.
It does not derive a denominator from how many alerts or PASS rows happened to
arrive. Coverage-only validator declarations, unknown mappings and dynamic
scanner rule counts are not additional successful controls.

Existing reviewed shared roots are preserved: plaintext transport, web-server
write permissions, and Moodle patch/advisory level. Members and provenance
remain visible; root contribution uses maximum, never a sum. Operational
canonical members are traversed to preserve every source. Different independent
mapped weaknesses remain separate. Active validation is retained as supporting
metadata, without an additional penalty or automatic promotion of confirmation.
Adding stronger actual source evidence may increase a maximum reliability-weighted
hazard; merely adding another identical source cannot multiply it.

A genuinely new mapped weakness can add independent hazard but cannot buy
coverage credit by generating trivial PASS rows. For longitudinal operational
comparison, previously declared mapped control **identities** from same-target,
same-profile snapshots are retained in `known_controls`. Their old status,
severity and verdict are never copied. If no current result exists for such a
control, it becomes missing, not implicitly resolved. Comparisons across changed
policy, platform/applicability scope or coverage return NOT_COMPARABLE and no
security-improvement delta. The conservative-bound delta remains available as
an explicitly different quantity. Registry/scope expansion is not a target fix.

## 7. Applicability and coverage

Moodle-only controls are removed from a generic platform's applicable registry,
without penalty or coverage credit. Internal-server controls may remain applicable
but unavailable on a generic target if their real collector prerequisite is absent.
Explicit NOT_APPLICABLE source evidence removes that control from its root's
required members. A root is inapplicable only if all its applicable members are
excluded. A fully inapplicable dimension is excluded from aggregation; suppressing
a dimension with a known current positive hazard is rejected. An arbitrary
unknown platform identity cannot silently opt into Moodle context.

For each root, conservative observability and effective reliability coverage are:

\[
K_j=\min_{i\in C_j} k_i,\quad
E_j=\min_{i\in C_j}(k_i r_i),\quad
C_d={1\over |J_d|}\sum_jK_j,\quad
C_d^{eff}={1\over |J_d|}\sum_jE_j.
\]

The minimum avoids a PASS on one related control asserting that an unobserved
member was checked. Per-control duplicates use the maximum available support,
then the minimum is taken across distinct root members. Root units have equal
coverage weight within each dimension. Overall observability is
\(C=\sum_{d\in\mathcal D}w_d C_d/\sum_{d\in\mathcal D}w_d\), with analogous
effective reliability coverage. The denominator and IDs are returned explicitly.
It is dimension-balanced coverage of a fixed registry, not percentage of every
possible vulnerability in existence. Generic Task 2C capability coverage is a
different construct and is never substituted into this score.

## 8. Per-dimension quality and missing-control envelope

For default missing-control allowance \(m=1\), define

\[
u_j=\max_{i\in C_j}\{h_i+(1-k_i)m\},\quad
H_d=\sum_{j\in J_d}h_j,\quad H_d^+=\sum_{j\in J_d}u_j.
\]

Supplementary mapped weaknesses add their root hazard. If they are carried in
the fixed longitudinal scope, absence gets the same missingness allowance.
All evidence conflicts remain visible; a valid high contribution is not cancelled
by another source's PASS.

\[
\widehat Q_d=100 e^{-\lambda H_d},\quad
L_d=100e^{-\lambda H_d^+},\quad U_d=100e^{-\lambda H_d}.
\]

The conditional estimate is unavailable when there is no observed evidence for
the dimension. The mathematical envelope still participates in overall bounds;
missing dimensions are not silently renormalized away. D6 with no telemetry has
the broader interval [0,100], because a missing activity stream cannot bound the
number of unobserved episodes. No overall scalar is returned if **all** dimensions
are unobserved. If some are observed, the displayed `overall` is the conservative
lower envelope; dimensions with no observation retain `score=null` for presentation.

These are **policy sensitivity envelopes**, not confidence or prediction
intervals. They cover specified missing controls under maximum hazard m, not all
unknown real vulnerabilities, unreliable reports or unseen threat classes.
Reliability uncertainty is disclosed by effective coverage and parameter
sensitivity, not disguised as a calibrated statistical interval.

Default ln(2) means one unit of hazard halves dimension quality: a single
confirmed critical weakness yields 50, a comparable high weakness about 59.46,
and a low weakness about 84.09. Independent hazards add in exponent space.
No critical finding absorbs the dimension at zero; no large PASS inventory
dilutes failures. Multiple real independent weaknesses can still drive quality
low—this is disclosed, not tuned away for presentation.

## 9. Behavioral D6, time and recovery

Only the **accepted existing episode output** enters D6 hazard. CQI does not
recompute persistence or regroup windows. Current observations establish telemetry
availability and validate episode membership/reconciliation. UNKNOWN episodes
already satisfy accepted persistence=2; confident known patterns follow existing
accepted behavior and may qualify from one window. An isolated UNKNOWN or an
UNCERTAIN observation is not fabricated into an incident. It remains visible in
the stream/explanation without a new incident-based CQI penalty.

Incident severity coefficients retain .4 for UNKNOWN, .5 for enumeration/admin,
and .75 for the other known attempt classes. Support is 1 for anomaly-supported
known patterns/UNKNOWN and .8 for known model disagreement. These are ordinal
scoring assumptions; raw uncalibrated class scores are never multiplied into risk.
For distinct active stable episode IDs:

\[
H_6=\sum_{e\in A(t)} b_{class(e)}a_e,
\qquad Q_6=100e^{-\lambda H_6}.
\]

An episode is active for this **activity index** only when its last-seen and at
least one member observation are within the inclusive 300-second horizon at t.
Duplicate stable episode IDs contribute once; conflicting duplicates fail closed.
Replayed observation IDs contribute once. Stable accepted stream identities
prevent independent sessions being merged to hide incidents. Complete removal
of an incident row by an untrusted caller is outside the trusted input contract;
the API uses the existing hash-verified journal projection.

Verified CLOSED/RESOLVED records with an evidence reference and verification
time after last-seen permit explicit closure. These input assertions must come
from a legitimate reviewed lifecycle process. This task does not add a closure
button, invent human review or mutate accepted incident state. Closure mathematics
is tested; deploying a human incident-review workflow is future product work.

Time expiry is recorded **OUTSIDE_ACTIVITY_HORIZON; NOT_VERIFIED_RESOLVED**.
With fresh later normal telemetry, the activity dimension can recover because
the activity window is quiet. That is temporal activity recovery, not verified
remediation or proof the attack ceased. Without recent telemetry, D6 is unavailable
with [0,100], not healthy. Old incidents remain in provenance/history. Fresh
incidents after a closure are independently active; a closure before last-seen
cannot suppress newer evidence. In LIVE mode the API defaults to actual UTC time;
replay explicitly uses its evidence clock. A stopped old journal is not current
normal activity simply because its final observation was BENIGN.

## 10. Overall aggregation and selection

Applicable dimensions retain equal positive baseline weights 1/6 because no
empirical basis for a different importance ordering exists. Weights normalize
only over **genuinely inapplicable** exclusions, not unavailable evidence.
For any applicable vector \(q\), compare:

\[
A(q)=\frac{\sum_d w_dq_d}{\sum_dw_d},\qquad
G(q)=100\prod_d(q_d/100)^{w_d/\sum_dw_d},
\]
\[
F(q)=\min\{G(q),\min_d q_d+g\},\qquad g=20.
\]

If a geometric input is zero, G=0; computation otherwise uses weighted logs.
The implemented overall is **F(L)** when any dimension has observations, with
envelope [F(L),F(U)]. The additional `conditional_overall` applies F to available
conditional dimensions and is prominently non-comparable when coverage differs.
It is never substituted silently for the conservative scalar.

Selection is a prospective design decision: arithmetic fully compensates;
geometric reduces compensation but still permits a small-weight weak dimension
to be overshadowed. F enforces the explicit requirement that overall quality
cannot exceed the weakest applicable dimension by more than 20 points. There is
no claim that 20 is experimentally optimal. Alternatives are all retained in
scenario results; guard 10/30 is in sensitivity analysis. More elaborate
aggregators were not needed to satisfy this transparent constraint.

Example q=(20,100,100,100,100,100): A≈86.67, G≈76.47, F=40. A severe dimension
cannot disappear behind five good ones. Conversely, the guard creates plateaus:
if the minimum-dimension cap binds, deterioration elsewhere can lower that
dimension without changing the overall scalar. This is weak monotonicity,
not strict sensitivity for every possible change. The API always exposes all six
dimensions; a scalar alone must not be used as a complete ordering of platforms.

## 11. Mathematical properties and assumptions

P1 boundedness follows from nonnegative finite hazards, 0≤exp(-x)≤1 and min/means
of bounded values. P2 follows from fixed identities, ordering, inputs, policy,
scope and as-of. A wall-clock API request at a different time is a different input.

P3 remediation cannot decrease quality when control scope, applicability,
observability and other factors are fixed: it weakly reduces one root maximum,
the exponential increases and F is coordinatewise nondecreasing. P4 independent
deterioration weakly increases one hazard, reversing that inequality. These are
not proofs for comparisons that also change evidence coverage or scope.

P5 severity ordering follows because s enters hazard linearly and is ordered.
It requires comparable r,b,k and root independence; stronger evidence on a low
finding need not rank below weaker evidence on a high finding. P6 follows from
max idempotence and stable episode-ID deduplication. Stronger actual reliability
can legitimately change the maximum, but duplicate count cannot multiply it.

P7 dropping a known observed failure cannot improve the lower envelope when its
declared control remains in scope: its prior hazard is ≤m, while an absent
control gets allowance m. Taking a maximum before summation is essential for a
partially observed shared root; simply adding a fixed root gap could otherwise
produce inflation. Known supplementary identities must remain in comparison
scope. Missing evidence never contributes an observed PASS. Contradictory or
changed applicability is flagged, not used as a like-for-like improvement.

P8 follows by excluding proved inapplicable controls before coverage/hazard
aggregation; no Moodle-only penalty is assigned to a generic platform. P9 follows
from adding positive accepted incident hazard. P10 follows from removing only a
verified closed or explicitly temporally inactive episode; missing telemetry
never establishes normal recovery. P11 is provided by separate APIs, policy hashes
and immutable historical sources. P12 follows from returned root/member IDs,
source provenance, hazard/coverage coefficients, dimension decompositions and
policy/registry/result hashes. Floating arithmetic is checked with small numerical
tolerances in property tests, without inventing empirical uncertainty estimates.

## 12. Worked numerical counterfactual

The constructed `confirmed_critical` fixture has one explicitly declared control
in each posture dimension and verified normal D6 telemetry. All pass except a
confirmed critical D1 weakness. Its source is `fixture-D1`, root `CONTROL-D1`;
this is a synthetic unit test, not a newly observed vulnerability.

Here s=r=b=k=1, h=1, \(\lambda=\ln2\), so D1=50. Other dimensions=100.
G=100×0.5^(1/6)≈89.09, but F=min(89.09,50+20)=**70**. Coverage=1.
An additional independent high D3 weakness gives D3≈59.46 but F remains 70
because the D1 guard binds. That is an explicitly reported plateau, not a test
failure hidden through tuning. The old policy gave 83.33 then 70.83.

Verified remediation of D1 gives h=0 and F=100, with the original source row
retained plus its verified lifecycle assertion. Old v1 ignores that new lifecycle
field and still reports 83.33 on the same underlying FAIL row. No historical
source field is changed. An observed new PASS in a fresh assessment would also
provide valid remediation evidence through the existing current-state pipeline.

## 13. Counterfactual and retained-evidence results

The immutable design receipt precedes score computation. Twenty scenarios cover
serious and low-confidence weaknesses, remediation, independent deterioration,
Native/ZAP duplicates, missing internal/role evidence, partial collection,
generic applicability, normal activity, known/UNKNOWN episodes, isolated anomaly,
duplicate episode, closure, missing telemetry and temporal recovery. Every fixture
is labeled CONSTRUCTED_COUNTERFACTUAL; no synthetic state is written into a real
assessment or accepted model dataset.

Selected results: normal complete=100; confirmed critical=70; remediated=100;
low-confidence critical≈96.04 (partial evidence); one known incident≈79.46;
two independent known incidents≈55.36; UNKNOWN episode≈95.48; isolated UNKNOWN
observation=100 under incident-based scoring. Missing internal/role dimension
gives conservative 70 with conditional 100 and observability 5/6. No recent D6
gives conservative zero with conditional 100 and coverage 5/6; **zero here is
uncertainty, not a measured total security failure**. Read the structured bounds.

Retained observed-source reanalysis (not new traffic):

| Source | Old v1 | v2 conservative | v2 conditional | Observability |
|---|---:|---:|---:|---:|
| Accepted benign replay | 52.7588 | 0.1854 | 49.7302 | 51.75% |
| Accepted attack replay | 36.0923 | 0.0927 | 21.5625 | 51.75% |
| Retained partial posture | 40.2308 | 0 | 45 | 45.80% |

The 69-unit registry exposes substantial unobserved controls not represented by
the historical 40-finding accepted posture. Many simultaneous unobserved-control
allowances make the lower bound extremely small. This pessimism is a material
limitation: it improves coverage honesty but makes the scalar poor for ranking
severely incomplete assessments. Do not hide it or interpret 0.185 as measured
platform failure. Conditional estimates, coverage and missing-control lists are
required companions. The retained posture has no D6 input, making its overall
lower envelope zero; its source score is still exactly 40.23080444335938 under v1.

All accepted observation/explanation and episode hashes matched before/after.
No threshold, feature, model, grouping, scanner mapping or finding changed.

## 14. Bounded sensitivity and robustness

The predetermined set has 23 variants including baseline: 12 focal dimension-
weight changes ×.8/1.2, severity ×.8/1.2, reliability ×.8/1.2, behavior influence
×.8/1.2 (values clipped at one), partial observability .25/.75 and guard 10/30.
There is no grid search or outcome-selected optimum. Twenty scenarios give 460
compact evaluations. All important monotonic, duplicate and incident-count
orderings held. There were **12 strict pairwise rank reversals**, retained in full.

For example, a low-confidence critical posture indication versus an UNKNOWN
episode reverses with a 20% D1 weight change, reliability change or behavior
influence change. The ordering of a partial assessment versus a confirmed
weakness also depends on the partial-observability assumption. Such trade-off
rankings are not robust enough to claim a universal total order. A severity-
hazard interpretation and missing-evidence interpretation are both normative.

Coverage C versus effective reliability coverage Ceff is reported directly rather
than selecting one after seeing results. The study does not estimate statistical
parameter distributions or confidence intervals. Report confidence would require
independent elicitation, replication and calibration research.

## 15. API versioning, storage and product migration

`Application.scientific_quality` reads the same verified source snapshots,
journal, accepted episodes and existing orchestration. It writes no raw evidence,
does not reset state and performs no fitting. LIVE uses actual UTC as-of by
default; replay explicitly declares its evidence-time semantics. Generic targets
cannot inherit the lab's unrelated Behavioral stream. Posture-only reanalysis
keeps D6 unavailable.

`GET /api/cqi/v2` returns typed v2 data: overall score kind, conservative/conditional
values, bounds, coverage, missing controls/dimensions, six dimensions, contributors,
Behavioral active/history distinctions, coefficients and hashes. Query parameters
mode/replay/run_id match existing conventions; as_of is optional explicit UTC.
`GET /api/cqi/v2/policy` exposes registry/policy for audit. Input values are not
echoed in invalid-request diagnostics; output uses existing product sanitization.

Existing `/api/cqi`, `/api/cqi/dimensions`, application snapshots, old reports and
the current dashboard remain v1 for backward compatibility. This is an explicit
versioned migration, not a silent rewrite of accepted research or a Task 3B UI
redesign. New clients must select v2 and display coverage/score-kind, never merely
swap its lower bound into the old decorative score. The running monitor/backend
is not restarted by this task; loading the new route requires its next authorized
normal deployment. In-process FastAPI acceptance verifies the actual new route.

No new runtime closure database or automatic remediation claim is introduced.
The scoring function accepts verified lifecycle records; an operator-review API/UI
and evidentiary verification workflow remain separate product work. Historical
assessments retain their original formula and scores indefinitely. Newly generated
reanalysis artifacts are stored separately under `outputs/cqi/` with hashes.

## 16. Validation and reproducibility

```sh
PYTHONPATH=src:. .venv/bin/python -B -m pytest -q tests/test_scientific_cqi.py
PYTHONPATH=src:. .venv/bin/python -B scripts/validate_scientific_cqi.py \
  --out outputs/cqi/a_new_nonexistent_directory \
  --baseline outputs/cqi/task3a_02/baseline_legacy_outputs.json
```

The script refuses an existing output or disk below 500 MB. The baseline receipt
used for this task is preserved in the output and can be selected with `--baseline`
for exact pre-change comparison. The initial development runs captured that
receipt before changing scoring; reproduction does not require temporary files. No raw logs,
models or scanner databases are copied. The finalized evidence package is
`outputs/cqi/task3a_02/`; the initial pass remains at `task3a_01`.

Formal properties are tested directly and across the bounded parameter set;
relevant existing Fusion, posture/dedup, Task 2C, Behavioral/episode,
explainability, backend and frontend tests also run. Protected artifact hashes
are checked before/after. Exact counts and source/result hashes are in the final
quality receipt. The accepted Behavioral v2 root remains
`59a8c7c5d3d51632d0afe45f8cd2fe50570b7af2943d26bb313888327ea9f436`.

## 17. Literature grounding and remaining gaps

Verified primary reference: OECD/European Union/EC-JRC (2008), *Handbook on
Constructing Composite Indicators: Methodology and User Guide*, OECD Publishing,
DOI [10.1787/9789264043466-en](https://doi.org/10.1787/9789264043466-en).
The handbook discusses transparent theoretical design, missing data, weighting,
aggregation/compensability and sensitivity. It motivates evaluating these choices;
it does **not** validate this project's severity coefficients, exponential scale,
20-point guard or cybersecurity-specific index. No invented citation or authority
is offered for those policy parameters.

Outstanding research: expert/stakeholder weight elicitation; independent security
outcome validation; reliability calibration; causal validity; a reviewed interval
model for epistemic uncertainty; evaluation of registry completeness and root
dependence; sensitivity to temporal limits; operational validation beyond Moodle;
human incident review; a richer non-scalar comparison for sparse evidence. No
population-level significance, universal LMS accuracy or successful-exploit
detection follows from this study. More coverage can improve a lower bound without
a platform change; compare conditional estimates only under stable scope/coverage.

## 18. Dissertation/paper subsection structure

1. Measurement construct, threat/evidence boundary and distinction from risk probability.
2. Canonical evidence, source reliability and reviewed root equivalence.
3. Applicability registry, observability and conservative missing-data treatment.
4. Dimension hazard/quality and accepted Behavioral episode integration.
5. Aggregation alternatives and explicit non-compensation constraint.
6. Mathematical properties with assumptions and counterexamples to stronger claims.
7. Counterfactual protocol and retained-source reanalysis.
8. Sensitivity, unstable rankings, limitations and product-version migration.

For an IEEE-style short paper, prioritize formulas, the worked example, the
coverage/scalar distinction, duplicate invariance, the 20×23 protocol and the
honest rank-reversal/partial-assessment results. Do not present the policy as an
empirically calibrated compromise probability or claim statistical generalization.
