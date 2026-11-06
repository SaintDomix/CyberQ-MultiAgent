# Current Verified Baseline

Date: 2026-10-04

## Infrastructure

Primary repository:
`/home/saintdomix/dissertation_model`

Ubuntu Moodle host:
`192.168.226.132`

Local Moodle:
`http://192.168.226.132/moodle/`

Kali testing host:
`192.168.226.129`

A pre-integration filesystem backup exists outside the repository:
`~/dissertation_model_PRE_INTEGRATION_2026-10-04.tar.gz`

Git contains the pre-integration baseline and imported legacy implementations.


# Existing Branch 1

Working/reference implementations are preserved under:

`legacy/branch1/first_branch_v22/`

This contains the later external HTTP/Moodle scanner.

`legacy/branch1/moodle_deep_v2_role_pack/`

This contains:
- server-side Moodle evidence collection;
- Moodle/version/component analysis;
- vulnerability/advisory matching;
- internal configuration assessment.

`legacy/branch1/role_validation_v3/`

This contains:
- role probes;
- cross-role comparison;
- authenticated/anonymous access validation.

Real previous evidence is preserved under:

`evidence/baseline/branch1/`

including:
- internal Moodle evidence;
- deep assessment outputs;
- anonymous role evidence;
- student role evidence;
- administrator role evidence;
- role-access review.

The complete Kali development history is preserved separately under:

`legacy/kali_snapshot_2026-10-04/`

Important:
selected active SQLi/XSS/SSRF/etc. validation is NOT yet implemented as the
final unified Active Validation Layer.


# Existing Branch 2

Raw experimental Apache logs are under:

`data/raw/`

Existing benign scenarios include:
- B01
- B02
- B03

Existing controlled suspicious scenarios include:
- S01 repeated authentication behavior
- S02 probing/enumeration-style behavior
- S03 request-burst behavior

Experiment metadata is under:

`experiments/`

Earlier parser/feature code exists under:

`src/`

Working behavioral implementations are preserved under:

`legacy/branch2/`

The latest existing implementation before full integration is Behavioral v3.

Current latest v3 experiment:

- training windows: 35
- test windows: 41
- TN: 19
- FP: 5
- FN: 5
- TP: 12
- precision: 0.706
- recall: 0.706
- F1: 0.706
- false-positive rate: 0.208

Existing v3 behavioral hypotheses include:
- BRUTE_FORCE_LIKE
- ENUMERATION_LIKE
- ADMIN_PROBING_LIKE
- REQUEST_BURST_LIKE
- FAILED_PROBING_LIKE
- MULTIVARIATE_OUTLIER
- NO_NAMED_THREAT_PATTERN

Current Isolation Forest is operational.

Current behavioral feature extraction is operational.

Current rule-based semantic explanation is operational.

The current dataset is still small and is not considered final.


# Not Yet Implemented in the Final Model

Milestone 1A now provides canonical Branch 1 findings and future Branch 2 event
contracts in `src/evidence_contracts/`, with offline adapters for the saved
external MVP, deep v2, and role-review v3 JSON. The normalization CLI exports
historical observations into `outputs/normalized_baseline/`. See
`docs/EVIDENCE_CONTRACTS.md` for mappings, identity rules and reproduction.
Behavioral event production, full model integration, fusion and scoring remain
unimplemented; these contracts do not establish any new live findings.

Milestone 1B adds the production security-posture pipeline in `src/branch1/`
and `scripts/run_branch1.py`. Offline replay preserves all 40 Milestone 1A
records and identities (external 23, deep 16, role review 1). Fresh internal,
advisory and role analysis and bounded external HTTP assessment return canonical
findings without runtime dependencies on legacy code. Live passive collection
has fixture tests but has not been network-validated in this milestone. See
`docs/BRANCH1_PIPELINE.md` for restored checks, limitations and commands.

The following are REQUIRED by the project scope but are not yet complete:

- authorized live acceptance of the unified Branch 1 posture pipeline;
- final safe Active Validation Layer;
- SQLi active validation;
- XSS active validation;
- selected additional active validators;
- expanded SQLi/XSS/traversal behavioral request features;
- final reproducible behavioral dataset;
- XGBoost multiclass threat classifier;
- SHAP explanation layer;
- final Isolation Forest model-selection experiments;
- adoption of canonical evidence contracts by both live branch pipelines;
- cross-branch correlation;
- root-cause deduplication;
- security-dimension scoring;
- Cybersecurity Quality Index;
- final integrated runner;
- final integrated report.

Do not describe any of these as implemented until actual code and reproducible
results exist.
