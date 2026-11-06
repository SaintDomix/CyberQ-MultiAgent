# Productionization Run 2 baseline

Starting branch: `m5-behavioral-v2`. Starting HEAD:
`30aa494aa41a6f077db25750ed38d647600a63fc`.
Existing M5 changes/artifacts are untracked and preserved; no branch merge,
commit, tag or model refitting is performed.

Accepted Behavioral v2 verified before editing: package
`behavioral-v2-59a8c7c5d3d51632d0af`, canonical root
`59a8c7c5d3d51632d0afe45f8cd2fe50570b7af2943d26bb313888327ea9f436`.
Model v1 package verification passed. The accepted Branch1 source contains
40 findings: 21 FAIL, 15 PASS, 3 PARTIAL, 1 DISMISSED. Source bindings are
recorded in `demo/artifact_sources.json` (hashes, not copied research results).

Before-edit inventory contains 1,279 files under data/evidence/outputs.
The temporary before-inventory is `/tmp/productization_before_inventory.json`.
A final receipt will compare every original byte/hash; new application work
belongs only to demo/source/tests/docs and disposable runtime directories.

## Reuse

- Existing `src/fusion/` pure assembly, category mapping, root dedup,
  correlation rules, six equal-weight CQI dimensions and sensitivity.
- Accepted `src/behavioral_runtime/` passive model engine; no algorithm changes.
- M2D SQLite journal schema: `results(sequence, record_id, payload, sha256)`;
  v2 adds `episode_cursor`, `episode_groups`, `incidents`. Application access
  uses SQLite read-only transactions and verifies payload hashes.
- M4 checkpoint branch `m4-demo-ui`, commit `a3f9100`: selectively restore
  React/Vite package files, UI primitives, CSS, utilities/tests, privacy
  sanitization, dependency declarations and launcher. No whole-branch merge.

## New application components

Typed domain adapters; read-only evidence/runtime service and cache; frozen
source bindings; normalized API; explicit passive-monitor controls; seven-page
product presentation; source/incident/explanation details; focused tests/docs.
The new interface replaces v1-specific UI orchestration only, not research code.

## Intentionally untouched

`src/branch1`, `src/branch2`, `src/fusion`, `src/reporting`, frozen Behavioral v2
features/models/config/adapter, Model v1, all accepted evidence/output/raw data.
No live Apache read, traffic generation or model execution during this run.
CQI retains raw-observation semantics: suppressed isolated UNKNOWN observations
can still affect D6, while incident escalation independently requires the frozen
persistence rule. No hidden scoring-policy change is made for presentation.
