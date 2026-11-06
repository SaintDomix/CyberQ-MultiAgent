# M3A offline Fusion and Cybersecurity Quality Index protocol

This milestone implements a deterministic quality **index**, not a probability
of compromise or attack, not a CVSS replacement, and not a causal model.
Frozen Branch 1 posture and frozen Branch 2 inference are consumed, never run.
Starting code: `3149487eb7c52996529cad6fe500a531bdc7bec5`,
`milestone-2d-live-inference`.

## Frozen experimental inputs

Exactly four files are read by the evaluator:

- `outputs/branch1_m1d_acceptance_lab_run02/findings.json`: accepted 40-record posture snapshot.
- `outputs/branch2/live/m2d_live_01/predictions.jsonl`: saved-model live observations.
- `outputs/branch2/m2c_final_01/package_manifest.json`: frozen model identity (SHA256 of file bytes).
- `outputs/branch2/live/m2d_live_01/acceptance_summary.json`: accepted model/schema/integrity identities.

M1E benchmark/role results are acceptance evidence, not additional scoring inputs.
`branch1_unified_live_smoke` is not the posture basis. Model serialization and
Apache logs are never opened. Source log paths and byte-range hashes are retained
as provenance strings, never dereferenced. Input hashes are checked again before
writing. Model/schema IDs, package completeness/version and declared hashes,
contiguous prediction sequences, acceptance counts, saved-inference flags,
uncalibrated-score flags, fixed reconciliation threshold and byte provenance are
validated. This verifies identity links; it does not independently authenticate
raw Apache observations or revalidate the model binary. No training imports,
network clients, host log access or model fitting are needed.

## Architecture and canonical contract

`src/fusion/schema.py` defines `fusion-cqi-1.1` and a strict canonical dataclass.
`adapters.py` performs pure normalization and evidence-time selection;
`dedup.py` applies reviewed root rules; `correlation.py` adds context;
`cqi.py` computes dimensions, index and sensitivity; `pipeline.py` writes
11 reproducible artifacts. `scripts/run_fusion.py` is the offline entry point.

Canonical fields retain evidence/source-record IDs, input path, original source
provenance, category, finding type/behavior class, assets/components when present,
check result, severity, confirmation/evidence strength, available timestamps,
recommendation, eligibility/exclusions, dimension, contribution and coefficients.
Absent posture timestamps, confidence or assets remain absent/null. No confidence
multiplier is invented. Original evidence/explanation/observed/expected values and
behavior reconciliation/robust/SHAP explanations remain accessible in source
details. All canonical items declare `causal=false` and
`successful_exploitation_confirmed=false`. Parent findings are never changed.
Duplicate exact posture IDs collapse deterministically; conflicting copies fail.
Duplicate behavioral IDs or sequences fail rather than concealing live-integrity
errors. Semantic decision/reason/IF/classifier contradictions fail closed.

## Six dimensions

| Dimension | Posture category mapping |
|---|---|
| D1 TRANSPORT_HTTP_PROTECTION | Transport Security; Security Headers; HTTP Configuration |
| D2 IDENTITY_SESSION_ACCESS | Authentication & Session; Access Control; Authentication & Access |
| D3 EXPOSURE_DISCLOSURE | Information Disclosure; Exposure; Privacy & Exposure |
| D4 PATCH_VULNERABILITY_MANAGEMENT | Patch & Vulnerability Intelligence |
| D5 SERVER_HARDENING_INTEGRITY | Server-side Configuration; Runtime Hardening; Network Egress / SSRF Defense |
| D6 BEHAVIORAL_THREAT_ACTIVITY | Selected recent Branch 2 observations |

Unknown categories are retained, explicitly UNMAPPED in exclusions/coverage,
and excluded from scoring. No implicit mapping is made. A dimension without a
scoreable cluster has `INSUFFICIENT_EVIDENCE` and null quality, never an automatic
100. INFO/pass evidence can demonstrate assessed coverage with zero contribution.
A zero-risk assessed dimension may score 100; this is an index result, not a
claim of overall safety.

## Ordinal coefficients

| Posture severity | Factor |
|---|---:|
| CRITICAL | 1.00 |
| HIGH | 0.75 |
| MEDIUM | 0.50 |
| LOW | 0.25 |
| INFO | 0.00 |

| Result | Factor |
|---|---:|
| FAIL | 1.00 |
| PARTIAL | 0.50 |
| PASS / DISMISSED / NOT_APPLICABLE | 0.00 |
| NOT_TESTED | excluded; coverage only |

| Confirmation | Factor |
|---|---:|
| CONFIRMED | 1.00 |
| VERSION_BASED | 0.70 |
| NOT_CONFIRMED | 0.35 |
| FALSE_POSITIVE / NOT_APPLICABLE | 0.00 |
| NOT_TESTED | excluded; coverage only |

Individual posture contribution = severity × result × confirmation.
Unknown severity/result/confirmation factors are explicitly reported and
non-scoreable. LIKELY/CONTEXTUAL have no posture coefficient in this baseline;
they remain evidence with UNKNOWN_CONFIRMATION coverage rather than silently
acquiring invented factors. Definitive PASS/DISMISSED/NOT_APPLICABLE,
FALSE_POSITIVE and INFO have zero contribution even if a different coefficient
is unknown; that unknown is still reported as a data-quality observation, not a scoring
exclusion. `score_eligible` includes these deterministic zero-risk assessments;
`excluded_from_scoring` counts only non-scoreable items. Canonical `exclusions`
and coverage `exclusions` contain actual scoring exclusions only. Unknown source
coefficients remain separately visible under `data_quality_observations` and the
unknown-value coverage lists. No severity is invented. NOT_TESTED always excludes
scoring.

| Final behavior decision | Factor |
|---|---:|
| BENIGN | 0.00 |
| UNCERTAIN | 0.15 |
| UNKNOWN_ANOMALY | 0.40 |
| ENUMERATION_RECONNAISSANCE / ADMIN_PROBING | 0.50 |
| BRUTE_FORCE / REQUEST_BURST_DOS_LIKE / SQLI_ATTEMPT / XSS_ATTEMPT / PATH_TRAVERSAL_ATTEMPT | 0.75 |

Behavior contribution = decision factor × reconciliation support:

| Reconciliation reason | Support |
|---|---:|
| BOTH_BENIGN_NORMAL | 0 |
| ANOMALY_WITHOUT_CONFIDENT_KNOWN_ATTACK | 1.0 |
| NORMAL_IF_WITH_UNCERTAIN_OR_UNAVAILABLE_CLASSIFIER | 1.0 |
| KNOWN_ATTACK_WITH_ANOMALY_SUPPORT | 1.0 |
| KNOWN_ATTACK_MODEL_DISAGREEMENT | 0.8 |

The last state retains classifier-only known-pattern evidence with lower support
and preserves model disagreement. A high score is never treated as a calibrated
probability. Ground truth `label` is not consumed. All attempt/pattern semantics
are retained; uncertainty and unknown anomalies do not become known attacks.
These coefficients are transparent ordinal policy, not empirical probabilities.

## Reviewed root-condition rules

Within a **single-platform posture snapshot**:

- PLAINTEXT_TRANSPORT: TLS-001, TLS-003, HDR-001,
  COOKIE-MoodleSession-SECURE. Score maximum eligible contribution once in D1.
  The cookie stays categorized D2 for evidence/coverage, but is not scored twice.
  Missing per-control assets stay null; snapshot identity scopes the rule.
- MOODLE_PATCH_LEVEL: PATCH-001 and ADV-MSA-*. Maximum eligible contribution
  once in D4. Preserve patch-state evidence, each advisory, advisory count/list,
  member count and severity breadth. Many advisories do not sum mechanically.
- WEBSERVER_WRITE_PERMISSIONS: FS-001 and FS-002; maximum once in D5.
- Everything else: independent canonical evidence cluster. CSP,
  X-Content-Type-Options, Referrer-Policy and Permissions-Policy remain separate.

No source `root_cause` is required; no fuzzy clustering occurs. Every cluster
exposes ID, rule, representative/max contribution, members, count, rationale and
unique recommendations. Raw behavior windows remain distinct canonical evidence. For scoring,
non-benign windows are grouped into deterministic temporal episodes as described
below; no probabilistic independence claim is made. Exact duplicated posture evidence
or another copy within the same reviewed family cannot worsen its cluster score.
Multiple installations must be evaluated in separate snapshots; this adapter
is not a multi-tenant assessment protocol.

## M3A.1 behavioral episodes

Raw Branch 2 windows are evidence, not independent risk contributions. All
selected canonical records and raw prediction coverage counts are preserved.
`TEMPORALLY_CORRELATED_BEHAVIOR_EPISODE` groups score-eligible non-BENIGN
observations only when their final reconciliation class and retained stream
identity match and their fixed UTC windows are exactly adjacent:
`next.window_start == previous.window_end`. Each window must be an aligned
10-second interval; adjacency tolerance is **zero seconds**. No fuzzy matching,
scenario labels, SQ01 run IDs or hardcoded experiment timestamps are used.

Stream identity includes the input artifact, client ID, user-agent ID, live
session/run IDs, source file/path/device/inode, model ID and schema hash where
retained. Matching uses the complete retained identity tuple; different clients,
sessions, sources, models or user agents cannot merge. The adapter now preserves
client/user-agent/run identity from the frozen prediction JSON without accessing
source logs. If client/session/source identity or window timing is missing,
keep a singleton episode and report why no merge was inferred. Supplied malformed
or non-aligned/non-10-second timing fails closed.

Within a stream, chronological order controls episodes. A gap, different class,
or intervening BENIGN window breaks an episode. Contiguous UNKNOWN_ANOMALY and
UNCERTAIN windows follow the same rule. Reconciliation support may vary within
an episode while the final class remains identical.

```
episode contribution = max(member window contributions)
D6 risk = 1 - product(1 - episode contributions)
```

BENIGN retains zero-contribution evidence clusters and cannot multiply risk.
Episode clusters expose stable IDs, class, member evidence/record IDs and
sequences, count, start/end, retained identity, max contribution and rationale.
IDs are deterministic from identity/class/member evidence, independent of input
ordering. One qualifying window versus five contiguous same-class windows with
unchanged maximum contribution yields identical D6 quality. Separated episodes
remain distinct and can increase D6 risk. This prevents window fragmentation
from mechanically multiplying risk; it is a deterministic policy aggregation,
not a claim that separated episodes are statistically independent.

Episode construction occurs after recent-evidence selection, so a horizon may
clip an episode; its ID and extent describe the selected membership. Exact
adjacency cannot distinguish separate real actions without observable gaps,
and missing identity prevents merging rather than inventing context. Correlation
uses these same scoring episode memberships and still has no scoring effect.

## CQI mathematics and coverage

For eligible clusters assigned to dimension d:

```
risk_d = 1 - product(1 - contribution_cluster)
quality_d = 100 * (1 - risk_d)
CQI = sum(quality_d * baseline_weight_d) / sum(available baseline_weight_d)
```

Each baseline weight is exactly rational **1/6**:
`BASELINE_EQUAL_DIMENSION_WEIGHTING`,
`weights_are_empirically_calibrated=false`. Equal weights are a methodological
baseline chosen to avoid fabricated empirical or expert calibration. Exact
rational weights are recorded; JSON numeric weights are their floating-point
representations. Complementary-product aggregation is a bounded monotonic
**index**, not a joint probability. Full float precision is retained internally;
`cqi_display` rounds to 2 decimals. No interpretation bands are imposed.

If dimensions are unavailable, available weights are renormalized explicitly,
CQI is marked PARTIAL_EVIDENCE, and missing coverage is visible. This partial
index must not be interpreted as an equally complete assessment. Not-tested
items do not penalize or reward CQI. Branch 1 coverage reports total/eligible,
pass/fail/partial/dismissed/not-applicable/not-tested, unmapped categories and
unknown coefficients. Branch 2 reports total/recent/old/future counts, benign,
uncertain, unknown anomaly and known attempts. Dimensions report evidence and
eligible/scored-cluster counts; cross-dimension dedup may make these differ.

## Evidence-time horizon and replay

Default lookback is 300 seconds. Omitted `--as-of` means maximum
`emitted_at_utc` in the input, never wall-clock now. Selection is inclusive:
`[as_of - lookback, as_of]`. Older and future records are excluded/countable.
Input identities are validated over all predictions before selection.
Explicit ISO UTC `--as-of` supports benign-phase versus controlled SQLI-phase
comparison without modifying input. Timestamps must include UTC offset/Z.
No experimental phase timestamp is hardcoded. Empty selected behavior means
insufficient D6 evidence, not proof of benign activity.

## Contextual correlations and recommendations

Rules associate SQLI with SQL injection metadata (including ADV-MSA-26-0031),
XSS with XSS/cross-site-scripting metadata, burst with DoS metadata, brute force
with authentication/session context, reconnaissance with exposure/disclosure,
admin probing with access/exposure, and traversal only with explicitly matching
path/file disclosure metadata. No match produces no fabricated association.
Associations are emitted per behavioral episode and matching posture evidence
set, with every member behavior record ID retained. Associations retain
dismissed/version evidence semantics, not vulnerability
confirmation. Correlations contain CONTEXTUAL confidence, causal=false,
exploit_confirmed=false and score_effect=NONE. CQI never reads correlations.
Posture recommendations are reused/deduplicated per cluster; suspicious behavior
only recommends preserving/investigating evidence, inspecting logs and reviewing
relevant controls. No unsupported specific exploit remediation is asserted.

## Weight sensitivity

Exactly 12 variants: for each dimension increase/decrease its baseline focal
weight by 20%; renormalize the other five proportionally to sum exactly one.
This means focal weights 1/5 and 2/15 respectively. Record all weights/CQIs,
minimum, maximum, absolute range and maximum deviation from baseline. Missing
scores retain the same available-dimension renormalization. Never select weights
based on observed outcomes.

## Artifacts and reproducibility

A NEW directory only; existing output directories are refused. Deterministic
sorted JSON, stable IDs, no current-time metadata. Artifacts:
canonical_evidence, fusion_clusters, correlations, dimensions, cqi, coverage,
sensitivity, recommendations, unified_findings, provenance, summary (all JSON).
Provenance hashes the four input byte streams and records an aggregate result
hash. Input source paths are part of provenance, so byte-identical replay assumes
the same input locations; output-directory changes do not affect results.
An interrupted write can leave an incomplete new directory; no automatic deletion
or overwrite is performed. Use a fresh directory after reviewing such a failure.

## Proposed offline execution (not executed during implementation)

```bash
cd /home/saintdomix/dissertation_model
.venv/bin/python -B scripts/run_fusion.py evaluate \
  --branch1 outputs/branch1_m1d_acceptance_lab_run02/findings.json \
  --branch2 outputs/branch2/live/m2d_live_01/predictions.jsonl \
  --model-manifest outputs/branch2/m2c_final_01/package_manifest.json \
  --live-acceptance outputs/branch2/live/m2d_live_01/acceptance_summary.json \
  --out outputs/fusion/m3a_candidate_01 \
  --behavior-lookback-seconds 300
```

For historical state evaluation, add `--as-of <actual ISO UTC evidence time>`
and use a different new output directory. Choose actual phase boundaries from
accepted evidence in a later step, not an invented timestamp.

Verification uses synthetic fixtures/temporary directories only:

```bash
.venv/bin/python -B -m unittest discover -s tests -v
```

## Research limitations and interpretation

The local Moodle testbed does not establish generalization to every LMS.
Adapters are extensible; platform universality is not claimed. Attack classes
represent controlled patterns/attempts, never successful exploitation. Apache
combined logs lack POST bodies. XGBoost confidence is uncalibrated. Version
matches are not exploitation confirmation. Weights, factors and root rules are
transparent baseline policies without empirical calibration. Contextual
correlation is not causal and never upgrades source confirmation. CQI should be
read together with dimensions, evidence, coverage and sensitivity, never as a
standalone probability or universal ranking. This implementation changes neither
branch, model, evidence, feature schema, attack taxonomy nor train/test protocol.
It introduces the six-dimension M3A scoring baseline specified for this milestone;
earlier scope documents describe broader conceptual dimensions, not this formula.

## Implementation verification

The complete unittest suite passed: **357 tests**, comprising 295 existing tests
and 62 new synthetic Fusion tests. Before/after protected inventories each
contain 874 files under `data/`, `evidence/`, and `outputs/`, with identical sizes
and SHA256 values. Inventory SHA256:
`ca6e7a6d9944fa4b8a9361c076f5ab0cf292f3d58bd35fb2b4a5741274a03dfb`.
Tracked and new-file whitespace checks passed. Existing tracked files and HEAD
were unchanged. No real Fusion scoring run, host Apache access, generated
traffic, model fitting, commit or tag occurred during this implementation.


### M3A.1 patch verification

The updated full suite passed **375 tests** (357 preceding tests plus 18 episode
and coverage regression tests). The 907 pre-existing protected files under
`data/`, `evidence/`, and `outputs/`, including the existing M3B Fusion outputs,
remain byte-identical. No real Fusion output was regenerated. The earlier M3A
verification above records the pre-patch stage, not the current test count.
