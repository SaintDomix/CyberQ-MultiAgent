# M3C offline end-to-end assessment and reporting

M3C is the final Day-3 baseline research system for **AI-Based Model for Analysis
and Evaluation of Cybersecurity Quality in Adaptive Educational Platforms**.
It consumes frozen accepted research results. It does not execute either branch,
load/retrain models, read the real Apache log, generate traffic or change CQI
policy. Base code HEAD: `3149487eb7c52996529cad6fe500a531bdc7bec5`.
M3A.1 Fusion policy remains `fusion-cqi-1.1` without coefficient/formula changes.

## Architecture

`src/reporting/assessment.py` calls `src.fusion.pipeline.evaluate` directly.
Fusion is the sole implementation of normalization, evidence-time selection,
root-condition and temporal-episode clustering, dimension scoring, CQI,
correlation and weight sensitivity. M3C ranks existing cluster contributions,
aggregates presentation summaries, deduplicates recommendation text, builds a
comparison, checks acceptance and renders reports. It never shells out to Fusion.
`render_markdown.py` defines shared A-L report content; `render_html.py` renders
escaped standalone HTML with embedded CSS and no scripts, fonts, CDN or external
assets. `acceptance.py` contains explicit named checks, not scoring policy.
`scripts/run_end_to_end.py` is the single offline entry point.

## Frozen inputs and experimental basis

- Branch 1: `outputs/branch1_m1d_acceptance_lab_run02/findings.json`.
- Branch 2: `outputs/branch2/live/m2d_live_01/predictions.jsonl`.
- Model identity: `outputs/branch2/m2c_final_01/package_manifest.json`.
- Live acceptance: `outputs/branch2/live/m2d_live_01/acceptance_summary.json`.

The accepted M3B directories (`m3a_candidate_02`, `m3b_benign_02`,
`m3b_sqli_02`) are preserved comparison evidence, never overwritten or used as
additional scoring inputs. The directory named `m3b_benign_02` represents the
**PRE-SQLI BASELINE**, not benign-only evidence: it has 13 BENIGN windows and
3 UNKNOWN_ANOMALY windows. Report wording reflects this distinction.

Fusion validates JSON input suffixes, model-manifest identity, M2D acceptance,
schema identities, contiguous live sequences, saved-inference flags,
uncalibrated classifier semantics and authoritative byte-range provenance.
Log-path strings are retained as provenance, never dereferenced. Model binaries are read only for protected-artifact hashing, never deserialized
or executed; scoring provenance checks validate frozen identity links, not model
execution.
Missing platform metadata remains missing; observed assets are copied from
posture evidence without inventing a platform/version.

## One-command final acceptance workflow

**Proposed command; not executed during implementation:**

```bash
cd /home/saintdomix/dissertation_model
.venv/bin/python -B scripts/run_end_to_end.py assess \
  --branch1 outputs/branch1_m1d_acceptance_lab_run02/findings.json \
  --branch2 outputs/branch2/live/m2d_live_01/predictions.jsonl \
  --model-manifest outputs/branch2/m2c_final_01/package_manifest.json \
  --live-acceptance outputs/branch2/live/m2d_live_01/acceptance_summary.json \
  --out outputs/end_to_end/m3c_final_01 \
  --behavior-lookback-seconds 300 \
  --as-of 2026-10-07T10:52:12.180465+00:00 \
  --baseline-as-of 2026-10-07T10:22:32.380373+00:00 \
  --sqli-as-of 2026-10-07T10:52:12.180465+00:00 \
  --expected-sqli-members 5
```

Comparison timestamps are arguments, not scoring constants. Without `--as-of`,
Fusion uses maximum emitted evidence time, never wall-clock now. Lookback is
300 seconds by default; selection boundaries retain Fusion's inclusive policy.
Both comparison timestamps must be supplied together, in increasing UTC order.
A fresh output directory is required. No old directory is deleted or reused.

Exit codes: 0 = all required acceptance checks pass; 1 = a completed assessment
has failed acceptance checks, with full failure evidence retained; 2 = argument,
input/provenance validation or I/O failure. An interrupted/invalid run may leave
an incomplete new directory; inspect it and choose a fresh directory, never
silently delete or overwrite research artifacts.

## Artifacts

At the output root:

- `assessment.json`: versioned platform/scope/horizon, CQI semantics, dimensions,
  ranked drivers, behavioral episodes, correlations, coverage, deduplicated
  recommendations, limitations, upstream explanation status and identity links.
- `cqi.json`, `dimensions.json`, `fusion_clusters.json`, `correlations.json`,
  `coverage.json`, `sensitivity.json`, `provenance.json`: unchanged Fusion results.
- `recommendations.json`: deduplicated report actions with linked evidence IDs;
  original per-evidence recommendations remain in the nested Fusion output.
- `comparison.json`: actual baseline/state CQIs and deltas, per-dimension changes,
  raw behavior counts, episode and correlation counts, SQLI memberships and
  full canonical posture equality. No numeric CQI expectation is hardcoded.
- `report.md` and `report.html`: thesis/demo presentation with A-L sections,
  dimension bars, top risks, episodes, comparison and provenance.
- `acceptance.json`: PASS/FAIL, observed values, expectations, explanation and
  required flag per named check; overall PASS only if all required checks pass.
- `summary.json`: result/profile and report references.
- `integrity_verification.json`: runtime pre-existing-artifact inventory digest,
  file count and changed/missing list. No wall-clock timestamp.
- `artifact_manifest.json`: relative filenames, byte counts, SHA256 and roles for
  every other output file, including nested states. It excludes itself to avoid
  self-hash recursion.

`fusion/` retains the complete main Fusion output, including canonical evidence
and source recommendations. When comparison is requested,
`comparison_states/baseline/` and `comparison_states/sqli/` retain the full Fusion
artifacts and provenance for both states. Input hashes must match the main
assessment in both states. These are new outputs; M3B directories remain intact.

## Interpretation and comparison semantics

Ranked risk drivers use actual deduplicated contribution (descending), stable
cluster-ID ties, representative evidence, member counts, rationale and upstream
recommendations. No causal percentages are manufactured. CQI is directly
explainable through its policy coefficients and bounded formula; M3C does not
perform SHAP. It summarizes actual upstream M2D SHAP availability, or explicitly
reports NOT_SUPPLIED; SHAP attribution is raw-margin and noncausal.

Every selected raw window remains canonical evidence and a coverage observation.
Non-benign D6 episodes reuse M3A.1 exact adjacency/class/identity clustering and
maximum member contribution. Five SQLI windows are one attempt-pattern episode,
not five successful attacks. A correlation is CONTEXTUAL with score_effect NONE,
causal false and exploit_confirmed false.

The comparison expects fixed canonical posture, unchanged D1-D5, changed D6,
negative overall CQI delta, one SQLI episode with the specified expected member
count (default 5), and a contextual SQLI association. These are scenario
acceptance criteria, not mathematical policy or tuning. They are checked against
actual computed results. The accepted M3B values are reference evidence only:
42.09212239583333 versus 39.6337890625, D6 36.0 versus 21.25. M3C implementation
has not rerun or claimed these as newly measured results. Comparison JSON retains
full precision; reports display two decimals, without changing the formula.

## Acceptance and integrity semantics

Required core checks verify protected artifacts, no training, model/schema
identity, index/noncalibration semantics, six bounded assessed dimensions,
bounded overall CQI, noncausal/noneffect/no-exploit correlations, reports and
complete input provenance. Insufficient/null dimensions fail full acceptance
rather than being filled with perfect values.

With both comparison arguments, profile is `M3C_SCENARIO`: all comparison checks
are required. Without them, profile is `CORE_ASSESSMENT`: `comparison.json` says
NOT_REQUESTED, comparison checks record FAIL/not assessed with required=false,
and cannot be mistaken for a passed full scenario demonstration. No absent
comparison is reported as a successful test. No failures are concealed.

The command inventories all pre-existing files under repository `data/`,
`evidence/`, `outputs/` before creating output and verifies their hashes/sizes
before acceptance. The implementation itself is separately verified against a
before/after protected inventory. New output files are not pre-existing protected
files; old outputs and raw evidence are never edited. This is an integrity
comparison, not prevention of external concurrent modification. Use a quiescent
repository for reproducible acceptance. Manifest self-integrity can be verified
using an externally recorded hash if needed.

## Reproducibility and testing

No current-time metadata affects CQI, IDs, reports or scored artifacts. Same
inputs/paths/as-of/lookback produce byte-identical core JSON and reports in fresh
output directories. The separately named `integrity_verification.json` describes
the runtime repository inventory: if the surrounding repository has gained
additional outputs, its count/digest (and the artifact manifest covering it) can
differ. This does not change assessment scores or reports. With the same protected
inventory, all generated files are byte-identical. Input absolute paths are
provenance, so moving input files changes those provenance bytes.

```bash
.venv/bin/python -B -m unittest discover -s tests -v
```

New tests use synthetic JSON fixtures and temporary output roots only. They cover
CLI validation/exit semantics, no overwrite, structured assessment, semantics,
ranking, episode presentation, escaped standalone reports, all dimensions,
noncausal/noneffect correlations, recommendation deduplication, comparison math,
acceptance success/failure, hash manifests, full deterministic replay and
network/training/Apache guards. They do not assert real experimental metrics from
fabricated data or execute the real final acceptance command.

## Limitations and future extension points

Local controlled Moodle results do not demonstrate universal LMS performance.
Controlled classes describe attempts/patterns, not exploit success. Apache
combined logs lack POST bodies. XGBoost scores are uncalibrated; version matches
are not exploit confirmation. CQI coefficients/weights are transparent ordinal
baseline policy, not empirical risk calibration. Correlation is contextual,
never causal. Sensitivity weights are not tuned from observed results. Read CQI
together with evidence coverage, missing context, dimensions and sensitivity.

Future Branch 1 platform/scanner adapters can supply canonical posture evidence;
new Branch 2 detectors or temporal models can operate behind canonical behavioral
representations. A later versioned CQI policy may use empirically/expert-derived
coefficients without rewriting the evidence pipeline. A future dashboard can
consume `assessment.json`; no dashboard is implemented here. M3C is the baseline
research system, not a claim that development cannot continue.


## Implementation verification

The complete suite passed **401 tests** (375 existing plus 26 new M3C tests).
All 940 pre-existing protected files have identical before/after sizes and
SHA256 hashes, including the accepted M3B outputs. Inventory SHA256:
`95b366648d5bd9c5899a314cef13374f88175585a4b31a033f635642036a7c2c`.
HEAD remains `3149487eb7c52996529cad6fe500a531bdc7bec5`. Tracked and new-file
whitespace checks passed. No existing source/evidence/model/output was modified;
no real final M3C run, training, host Apache access, network traffic, commit or
tag was performed. Test outputs were temporary synthetic artifacts only.
