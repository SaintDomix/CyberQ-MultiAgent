# Evidence-faithful UX candidate — Phase B

Date: 4 November 2026 (operator time zone UTC+05:00). Review candidate only;
not deployed or accepted. Source branch: `work/ux-clarity-20261104`.
Baseline HEAD: `a6d31a2633766ee285b4b80c3df361b184abc2f2`.

## Scope and visual changes

The existing seven-page application, original dark palette, sidebar and circular
gauge remain. The rejected `ScientificQuality.jsx` frontend was not restored.
Only the previous product projection and evidence-selection logic was
selectively recovered, then corrected to isolate unpaired historical D6.

| Page | Before | Candidate / accessible detail |
|---|---|---|
| Overview | Legacy scalar, several simultaneous summaries and long contributor text | Original gauge labelled **Observed-evidence quality — conditional**, nearby coverage, smaller conservative result, six compact dimensions, five priority roots and at most three investigation links |
| Security posture | Execution details dominated the findings workflow | Summary, paginated/filterable canonical findings, source and verification labels, finding drawer, separate execution and immutable-history views |
| Behavioral monitoring | Scores and evidence all exposed in the stream; bounded first 200 records | Paginated observation API, compact reconciled outcomes, Summary → Important factors → Technical details, original numerical comparisons and SHAP |
| Incidents | Episode and observation drawers could stack | One detail at a time, linked observations and back navigation, actual CQI activity interpretation, expiry distinguished from verified remediation |
| Cybersecurity quality | Legacy interpretation was primary | Typed v2 dimensions, contributors/coverage, comparison, method and contextual Fusion tabs; v1 remains explicitly labelled |
| Model & research | Architecture comparison but no clear controlled novelty experiment | Separate exact novelty chart/table, fixed XGBoost eight-class matrix, retained v1/v2 comparison, full methods/provenance |
| System & evidence | Verbose diagnostics | Operational controls separated from navigation; ingestion capability summary with technical disclosure and accepted generic fixture; runtime, reports and scanner details preserved |

## Evidence and API contract

`GET /api/product/assessment` returns `product-assessment-3.0`:
`snapshot`, typed `scientific_cqi`, `selection`, `assessment`, `history`,
`comparison`, `closure_review` and `preview_read_only`.

One read of the selected evidence supplies both application objects and CQI v2.
The accepted `cqi-evidence-2.0` calculator and all its parameters are unchanged.
Only application orchestration and presentation were edited.

* Conditional quality is not a complete-platform estimate or a probability.
* Coverage is shown beside it; reliability-adjusted coverage remains in detail.
* The conservative scalar is separately labelled, with its pessimistic
  missing-evidence assumption. Zero does not establish zero protection.
* Unavailable/inapplicable dimensions are not converted into numerical zero or
  PASS. Current stale telemetry is not labelled benign proof.
* Explicit historical posture selection reads no current Behavioral journal.
  Its scoring clock is the assessment completion time; D6 is **unpaired and
  unavailable**. No fabricated historical Behavioral snapshot is created.
* Comparisons use the existing target/scope/applicability/coverage safeguards.
  Absence is not verified remediation; guard plateaus are disclosed.
* Viewing replay/history changes local query state only. It never calls the
  operational mode-transition endpoint.
* A missing product route (404) permits clearly labelled legacy v1 display.
  503, malformed contracts and selected-history errors do not silently fall back.

Other new GET endpoints:

| Endpoint | Purpose |
|---|---|
| `/api/product/observations` | Source-bound pagination/filtering over all retained observations; no silent 200-record limit |
| `/api/product/evidence/{identity}` | Selected-snapshot canonical/member evidence only; current-assessment expectation guard |
| `/api/research/benchmark` | Hash-pinned accepted Task 2B results, configuration, splits and selection gate |
| `/api/research/normalization-example` | Hash-pinned generic accepted fixture, explicitly not newly supplied telemetry |
| `/api/research/cqi-method` | Unchanged accepted mathematical document |
| `/api/research/cqi-sensitivity` | Unchanged accepted counterfactual sensitivity output, explicitly not real remediation |

No arbitrary path-serving endpoint was added. Existing APIs remain available.
Scores, findings, saved features, signed contributions and predictions are
projected from existing evidence. No scanner, inference runner or experimental
pipeline is executed by these projections. Human explanations use the existing
deterministic engine over saved inference inputs, not new model inference.

## Scientific values preserved

Novelty recall: OCSVM **65/68**, LOF **41/68**, Isolation Forest **3/68**.
Benign false positives: **1/33 each**. False-incident sessions: **0/6 each**.
Strict anomaly plus correct-class windows: **63/68**, **40/68**, **3/68**.
Production reconciled run detection: **14/14 for each**. These are explicitly
different definitions, not conflicting percentages.

Fixed XGBoost: **99/101** combined, accuracy **98.02%**, supported macro-F1
**0.97727**; attack-only **66/68**, **97.06%**, supported macro-F1 **0.97615**.
Confusion-matrix cells and per-class supports come from the accepted artifact.
The decision remains **KEEP_OCSVM**. Laboratory support and correlated-window
limitations remain visible. No calibrated attack probability, causality or
successful exploitation is claimed.

Benchmark manifest root:
`8ee2a0fe37c4e64760c4bc9a6041718de15716f18d7b82d3e3c19a75e46b7c6a`.
Shared XGBoost artifact:
`9d3acb8e87d44d13f2b62ede413e073fb51c3f264db48a6d4d229964f0e6150d`.
Behavioral package:
`59a8c7c5d3d51632d0afe45f8cd2fe50570b7af2943d26bb313888327ea9f436`.

## Feature preservation matrix

| Feature/evidence | Previous location | Candidate location | Preserved / behavior |
|---|---|---|---|
| Original gauge/theme/sidebar | Overview / shared shell | Same | Visual identity retained; scalar explicitly v2 conditional |
| All seven destinations | Sidebar | Same identifiers, posture before behavior | Preserved; keyboard labels added |
| Source and target | Global controls | Compact evidence context | Preserved; read-only query selection |
| Authorized scanner controls | Posture | New authorized assessment disclosure | Same profile/scope rules; disabled in preview; not executed in acceptance |
| Findings, unmapped and ZAP-only | Posture | Findings tab, server filters/pagination | Same immutable rows; no removal or invented CQI mapping |
| Category, status, severity, dimension and source filters | Posture / accepted baseline | Findings filters | Category and legacy OWASP_ZAP source preserved; unmapped is a separate selector, not a replacement finding status |
| Native/ZAP/active validation | Posture technical views | Finding drawer / Execution details | Existing evidence components reused |
| Retained ZAP | Posture/System | History link / scanner disclosure | Retained evidence remains history-only |
| Observation model scores | Monitoring row/drawer | Summary, factors and technical drawer | Same outputs; uncalibrated label retained |
| Numeric factors/SHAP/full features | Explanation drawer | Important factors / Technical details | Original saved data retained; no frontend attribution calculation |
| Episode identity/timeline/provenance | Incidents | Episode drawer and linked evidence | Preserved; accessible back navigation |
| Fusion rules/context | Quality | Contextual fusion tab | Same semantic associations; no new penalty |
| v1 CQI/history | Overview/Quality | Explicit legacy fallback / comparison disclosure | Preserved; never labelled v2 |
| CQI v2 math/missing controls | Typed API/docs | Dimensions drawer / contributors / method | Existing math unchanged; availability made explicit |
| Research v1/v2 comparison | Model | Accepted v1/v2 evidence tab | Same accepted numbers |
| Task 2B novelty/classifier data | Research artifacts | Separate novelty and classifier tabs | Hash-verified read-only projection |
| Ingestion/capabilities/dependencies | System | Summary and expandable technical specification | Existing sample inspection retained, disabled only in preview |
| Final v2 and historical v1 reports | System | Same report links | Existing source reports unchanged |
| Start/stop monitor | Global header | Explicit System controls | Functionality retained, no implicit mode transition; disabled in preview |
| Durable operator closure | Not implemented | Explicit unavailable capability | No decorative Resolve button or invented audit workflow |

## Preview isolation and operator instructions

The stable served path is `demo/frontend/dist`. It was not built, replaced or
modified. The candidate build is `demo/frontend/preview-ux-20261104` (372 KiB).
Two isolated builds were necessary: the initial candidate and one corrective
build after visual review found missing category/unmapped filtering, later-page
drawer persistence and an unstyled telemetry input. Both used existing local
dependencies, without installation. The stable build was not touched.

The isolated API uses `EvidenceStore` and `JournalReader`: no scanner providers,
execution orchestrator or monitoring controller are constructed. It reads
immutable posture snapshots and an optional retained journal; all HTTP writes
are rejected. Scanner availability is explicitly **NOT_PROBED**, not falsely
reported as failed. It does not contact ZAP.

From the repository root, in a separate terminal:

```bash
PYTHONDONTWRITEBYTECODE=1 OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 \
  .venv/bin/python -B scripts/run_ux_preview.py --port 18004 \
  --retained-session runtime/behavioral_v2/ui-e01c26a593174d42bec5d45faf703576
```

Open **http://127.0.0.1:18004/**. Stop only this foreground preview with Ctrl+C.
The script rejects port 8000 and the stable build path. For accepted-evidence
only preview, omit `--retained-session`. Selecting accepted evidence is a
read-only saved-prediction projection, not running a replay experiment.

Do not use `start_demo.sh`, `stop_demo.sh` or the global demo controller for this
candidate preview. Do not rebuild into `dist` or restart the current service.

## Validation and visual evidence

Executed fixture regressions: **476 backend tests passed**. After adding the
current-vs-historical evidence-link guard, **15 focused backend tests passed**.
Executed frontend regressions: **76 passed**, including **10 focused render
tests** on the final frontend source. An earlier 75-test pass preceded the
feature-preservation correction. Tests do not fit models, scan the
laboratory or manipulate the running service.

Commands (run from repository root unless noted):

```bash
PYTHONPATH=src:. PRODUCT_FACTORY_ONLY=1 PYTHONDONTWRITEBYTECODE=1 \
 OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 .venv/bin/python -B -m pytest \
 tests/test_ux_clarity.py tests/test_scientific_cqi.py tests/test_fusion.py \
 tests/test_posture_profiles.py tests/test_operational_posture.py tests/test_current_active.py \
 tests/test_fresh_posture.py tests/test_native_plan.py tests/test_posture_demo_patch.py \
 tests/test_platform_normalization.py tests/test_behavioral_runtime.py \
 tests/test_behavioral_v2.py::SemanticTests tests/test_behavioral_v2.py::SplitTests \
 tests/test_behavioral_v2.py::EpisodeTests tests/test_behavioral_v2.py::ProvenanceTests \
 tests/test_live_human_explainability.py tests/test_human_explainability.py \
 tests/test_product_application.py -q --disable-warnings --maxfail=2

# From demo/frontend; existing Node installation, no npm install:
PATH=/tmp/node-v22.14.0-linux-x64/bin:$PATH \
 LIVE_EXPLANATION_PAYLOAD=../../outputs/explainability/task2a1_live_01/live_api_payload.json \
 node --test --experimental-test-isolation=none src/utils/data.test.js \
 src/utils/product.test.js scripts/product_render.test.mjs \
 scripts/normalization_render.test.mjs scripts/live_explanation_render.test.mjs \
 scripts/ux_clarity_render.test.mjs
```

The UX SSR tests generate an API-shaped payload in memory with
`scripts/export_ux_fixture.py`, or accept `UX_CLARITY_PAYLOAD` explicitly.
The payload contains saved evidence; it does not result
from a new model or scanner run. Browser acceptance uses the real isolated API
and existing local Chromium. Its 503/404 cases are explicitly browser fixtures.
See the final receipt for browser results and screenshot paths. The first
browser attempt is preserved separately: its pagination assertion ran before
the asynchronous row response. Later screenshot passes explicitly waited for
filtered rows; all receipts are retained. The final browser pass uses the
corrective build and checks category/unmapped filter availability. A browser-only
synthetic row identity tests polling persistence; it is never represented as a
new observed event or included in scientific evidence.

## Source changes

Backend: `demo/backend/app.py`, `schemas.py`, `services.py`; new
`product_api.py`, `product_quality.py`, `research_api.py`, `preview.py`.
Frontend: `src/App.jsx`, `api/client.js`, `utils/product.js`,
`styles/index.css`, `pages/ProductPages.jsx`, `components/UI.jsx`,
`BehaviorExplanation.jsx`, `IngestionDiagnostics.jsx`, `OperationalPosture.jsx`;
new `AssessmentContext.jsx`, `CqiPresentation.jsx`, `DetailDrawer.jsx`,
`PostureWorkspace.jsx`, `ResearchEvaluation.jsx`.
Tools/tests: `scripts/run_ux_preview.py`, `scripts/browser_ux_acceptance.py`,
`scripts/export_ux_fixture.py`,
`tests/test_ux_clarity.py`, `demo/frontend/scripts/ux_clarity_render.test.mjs`.
One existing CQI fixture test is isolated from workstation posture snapshots in
`tests/test_scientific_cqi.py`; mathematical assertions were not weakened.

## Recovery — operator only, not executed

The running backend and stable assets were never deployed, so they need no
rollback. Switching a Git branch does not change an already running process.
Stop only the separate preview with Ctrl+C before any source recovery.

First preserve the candidate, including new files (not only a tracked patch):

```bash
cd /home/saintdomix/dissertation_model
checkpoint=/tmp/ux_candidate_recovery_$(date -u +%Y%m%dT%H%M%SZ)
mkdir -m 700 "$checkpoint"
git rev-parse HEAD > "$checkpoint/HEAD.txt"
git status --short > "$checkpoint/status.txt"
git diff --binary > "$checkpoint/tracked.patch"
git diff --cached --binary > "$checkpoint/staged.patch"
git ls-files --others --exclude-standard -z -- demo/backend demo/frontend/src \
 demo/frontend/scripts scripts/run_ux_preview.py scripts/browser_ux_acceptance.py \
 scripts/export_ux_fixture.py \
 tests/test_ux_clarity.py docs/productization/UX_CLARITY_CANDIDATE.md \
 > "$checkpoint/new_source.list0"
tar --null -czf "$checkpoint/new_source.tar.gz" --files-from "$checkpoint/new_source.list0"
tar -tzf "$checkpoint/new_source.tar.gz" > "$checkpoint/archive_contents.txt"
sha256sum "$checkpoint"/*.patch "$checkpoint"/*.tar.gz
```

Confirm the archive is readable and all new candidate source is included. Then,
only if the operator wants source rollback and no later changes are mixed in:

```bash
git restore --source=pre-ux-20261104 --worktree -- \
 demo/backend/app.py demo/backend/schemas.py demo/backend/services.py \
 demo/frontend/src/App.jsx demo/frontend/src/api/client.js \
 demo/frontend/src/components/BehaviorExplanation.jsx \
 demo/frontend/src/components/IngestionDiagnostics.jsx \
 demo/frontend/src/components/OperationalPosture.jsx demo/frontend/src/components/UI.jsx \
 demo/frontend/src/pages/ProductPages.jsx demo/frontend/src/styles/index.css \
 demo/frontend/src/utils/product.js tests/test_scientific_cqi.py
```

New candidate files remain preserved and unused by the restored entry points;
they can be moved individually to the recovery directory after verifying the
archive. Do not remove or move unrelated untracked research files. Preview
assets can remain in their separate directory; the stable service never uses
them. No reset, clean, broad stash, evidence deletion or production restart is
part of this procedure. A permanent checkpoint outside `/tmp` requires the
operator to choose a safe location; `/tmp` is not durable backup storage.

## Remaining boundaries

This is an operator-review candidate, not deployment approval. There is no
trusted persistent incident-closure workflow. Historical D6 remains unavailable
without paired evidence. Preview deliberately does not prove live scanner or
monitor availability. No new assessment, remediation experiment, ML run or
cross-LMS validation was performed. Backend fallback, source freshness and all
unsupported capabilities remain visible rather than replaced with optimistic
values. Full scientific evidence remains accessible under details.
