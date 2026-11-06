# Phase C2 — parity repairs and minimal Overview

4 November 2026. Review candidate only; **not deployed, not operator-approved,
not a production-readiness claim**. Branch `work/ux-clarity-20261104`.

## Recovery and scope

Preflight passed before edits: clean tracked candidate source, HEAD and operator
checkpoint `ux-phaseb-candidate-20261104` both
`fe6f4c80fcc1ea05ae76c08c594c5445237b0d8b`.
`pre-ux-20261104` and `backup/pre-ux-20261104` still point to
`a6d31a2633766ee285b4b80c3df361b184abc2f2`.
The rejected experiment and original stash remain
`f69aec973916095a3e391fe40a800a4a00615be8`.
No reference, index, commit, branch or deployment was changed by C2.

The Phase B application remains the foundation. Only verified parity gaps,
related drawer accessibility, and approved Overview Option A were changed.
All scientific code remains unchanged. The existing seven destinations remain.

## Repair matrix

| C1 finding | C2 implementation and exact source | Evidence / limits |
|---|---|---|
| P0: completed selected snapshot used as current execution | `demo/backend/product_quality.py` now projects `latest_execution` separately from selected `assessment`. `demo/backend/posture_projection.py` obtains actual latest state and existing in-memory ownership/cancellation eligibility. `demo/backend/product_api.py` exposes additive fields and read-only attempt history/detail. `demo/frontend/src/App.jsx`, `components/PostureExecution.jsx`, `components/PostureWorkspace.jsx` bind latest execution, providers, existing ZAP progress, errors, duplicate-start blocking and explicit cancellation. | Fake-executor API tests cover QUEUED/RUNNING/COMPLETE/PARTIAL/FAILED/INTERRUPTED, GET without side effects, explicit existing cancel route, duplicate start, preview/unowned ineligibility and invariant selected CQI. Browser-only fake job verifies the button and terminal states. No real start/cancel sent. |
| P1: absent LIVE completion labelled accepted baseline | `product_quality.py` gives missing LIVE evidence no research profile and an explicit unavailable state; `AssessmentContext.jsx` and `PostureWorkspace.jsx` show actual latest state without historical PASS/FAIL substitution. | Four unavailable-current API cases; frontend rendering fixture. Accepted research remains explicitly selectable. |
| P1: missing historical ZAP counts | `posture_projection.py` shares the existing verified normalized-zap.json derivation with `posture_api.py`; product selected metadata uses it. `OperationalPosture.jsx` reserves Pending for actual queued/running state. | Actual retained FULL `posture-20261027T172357Z-b6df0bf04712`: 1,182 passive and 0 active alerts recovered. Original active-stage failure remains. Missing source stays unavailable; no invented zero. Hash and no-mutation regression. |
| P1: LOW root representative conceals HIGH members | `demo/frontend/src/utils/evidence.js` selects the most severe supported actual member, with deterministic ties. Exact source identity supplies a member title. `CqiPresentation.jsx` renders its own severity and verification, labels representative semantics and exposes all members. | Actual MOODLE_PATCH_LEVEL fixture starts with LOW ADV-MSA-26-0020 but correctly selects HIGH evidence. Additional same-control/different-source fixture prevents mixed member properties. Hazard, membership, coverage and score are unchanged. |
| P1: incomplete v1 access | `pages/ProductPages.jsx` retains the original complete LegacyQuality view; `CqiPresentation.jsx` adds explicit Legacy CQI v1 tab with dimensions, original contributors, sensitivity and full record. | SSR and actual browser reach dimensions, contributors and sensitivity. V2 remains primary. Selected evidence is interpreted under each named policy separately. |
| P1: incident/contextual posture drawers overlap | `ProductPages.jsx` closes the episode drawer before opening linked evidence and preserves episode/source/return target. `App.jsx` resumes on back or failed source fetch. `DetailDrawer.jsx` supports explicit focus return and initial return target. | Actual retained incident → contextual finding → Back → Escape: one dialog, linked-source focus restored, original episode trigger restored. Observation/back navigation also passes. |
| P2: profiles undiscoverable | `PostureWorkspace.jsx` entry reads New assessment · STANDARD / FULL / Passive. Original target, authorization and backend policy routing remain. | Browser finds all three options, STANDARD default. Each action remains preview-disabled with explanation; fake running job prevents another start. Actual scanner execution NOT RETESTED. |
| P2: missing replay reset | `AssessmentContext.jsx`, `App.jsx`: Reset to all accepted runs clears run selection and chooses full accepted attack holdout, entirely in local view state. | Browser verifies selection changes without mode-transition/replay-execution POST. |
| P2: incomplete attempt history | All statuses retained by `posture_projection.py`; `/api/product/history` paginates; `PostureExecution.jsx` offers immutable completed snapshot selection separately from read-only attempt inspection. | 61-item fixture across three pages preserves six states; actual saved history shows FAILED and PARTIAL attempts. Non-completed attempts never become selected completed CQI evidence. |
| P2: crowded Overview | `AssessmentContext.jsx`, `CqiPresentation.jsx`, `App.jsx`, `styles/index.css` implement Option A only. | Actual screenshots at 1600/1280/768. One gauge, coverage, conservative interpretation, concise gaps, balanced summaries, collapsed six dimensions and drill-down. No horizontal overflow. |

## Overview and scientific interpretation

Compact identity names platform, evidence context/profile, collection time and
completeness. Change evidence/source details contains full selectors, raw ID,
clock semantics and provenance. No UI poll is represented as a new assessment.

The original gauge is labelled **Quality of assessed controls**, with
**Observed-evidence quality — conditional**, actual coverage and completeness
adjacent. The conservative policy result is visually secondary, with the
pessimistic missing-evidence assumption and interpretation accessible. Its
zero is not described as measured zero protection.

D5 internal evidence and D6 telemetry gaps are stated as observability limits,
not vulnerabilities or PASS. All D1–D6 cards, original values and coverage
remain in Dimensions and evidence completeness and on the Quality page.

The Posture summary shows three supported root members with actual titles,
severity and verification, each opening selected-source evidence. The Behavioral
summary identifies available evidence or stale telemetry, retained record and
episode counts, scoring-horizon activity, and investigation links. It does not
claim benign activity when recent telemetry is missing.

Current/historical/replay identities remain distinct. Historical posture never
borrows current D6. Comparison safeguards and score mathematics are unchanged.
Native, ZAP Passive, repository validation and ZAP Active provenance remain
inspectable. No scorer, scan policy, prediction, feature, SHAP or benchmark was
changed. Original numerical features and technical details are retained.

## Tests and reproducibility

From repository root (existing environment, no installation):

```bash
PYTHONPATH=src:.:tests PRODUCT_FACTORY_ONLY=1 PYTHONDONTWRITEBYTECODE=1 OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 .venv/bin/python -B -m pytest tests/test_ux_c2.py tests/test_ux_clarity.py tests/test_scientific_cqi.py tests/test_fusion.py tests/test_posture_profiles.py tests/test_operational_posture.py tests/test_current_active.py tests/test_fresh_posture.py tests/test_native_plan.py tests/test_posture_demo_patch.py tests/test_platform_normalization.py tests/test_behavioral_runtime.py tests/test_behavioral_v2.py::SemanticTests tests/test_behavioral_v2.py::SplitTests tests/test_behavioral_v2.py::EpisodeTests tests/test_behavioral_v2.py::ProvenanceTests tests/test_live_human_explainability.py tests/test_human_explainability.py tests/test_product_application.py -q --disable-warnings --maxfail=2 --junitxml=/tmp/ux_c2_regression.xml
```

**494 passed**, including the 17 new C2 backend cases. Focused C2 tests passed
first. A later combined attempt inside the sandbox stalled at in-process API
transport and was interrupted; the above completed run used the permitted
outside-sandbox environment. No live scanners were invoked.

Export the API-shaped read-only fixture, from repository root:

```bash
PYTHONPATH=src:.:tests PRODUCT_FACTORY_ONLY=1 PYTHONDONTWRITEBYTECODE=1 OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 .venv/bin/python -B scripts/export_ux_fixture.py > /tmp/ux_c2_payload.json
```

From `demo/frontend` (existing Node path):

```bash
PATH=/tmp/node-v22.14.0-linux-x64/bin:$PATH UX_CLARITY_PAYLOAD=/tmp/ux_c2_payload.json LIVE_EXPLANATION_PAYLOAD=../../outputs/explainability/task2a1_live_01/live_api_payload.json node --test --experimental-test-isolation=none src/utils/data.test.js src/utils/product.test.js scripts/product_render.test.mjs scripts/normalization_render.test.mjs scripts/live_explanation_render.test.mjs scripts/ux_clarity_render.test.mjs scripts/ux_c2_render.test.mjs
PATH=/tmp/node-v22.14.0-linux-x64/bin:$PATH node node_modules/vite/bin/vite.js build --outDir preview-ux-c2-20261104
```

**94 frontend tests passed** (76 existing, 18 new). Build PASS in an isolated
384 KiB directory. Small rebuilds followed fixes discovered during validation;
stable dist and Phase B preview assets were never build targets.

From repository root:

```bash
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -B scripts/browser_ux_c2_acceptance.py --output outputs/ux/c2_20261104_final
git diff --check
```

Final actual Chromium acceptance: **17 check groups PASS**, 13 screenshots,
zero forwarded mutations, zero foreign requests, zero JavaScript errors.
One cancellation POST was intercepted and fulfilled by a browser-only fake job.
That is UI wiring evidence, not real cancellation/scanning acceptance. No
provider or monitor controller is constructed by the preview.

Earlier receipts remain: `_01` failed on a disclosure test helper; `_02` on a
selector matching a hidden option. `_02` also revealed a stale cancellation
message after job termination; this was fixed. `_03` passed before final
source-identity hardening and the retained-observation summary. The final
receipt uses the exact final build. Command-location errors during editing and
test invocation did not change scientific files; final commands above passed.

## Evidence and screenshots

Final compact evidence: `outputs/ux/c2_20261104_final/`.

- `before_phaseb_overview_1600.png`: actual existing Phase B preview, GET only.
- `after_overview_1600.png`, `after_overview_1280.png`, `after_overview_768.png`.
- Other six pages: `posture_current.png`, `behavioral_explanation.png`,
  `incidents.png`, `quality_root_members.png`, `legacy_v1_sensitivity.png`,
  `research_classification.png`, `system_generic.png`.
- `historical_full_recovered_counts.png`, `fake_execution_completed.png`.
- `browser_receipt.json` records actual checks and screenshot hashes.
- `integrity_receipt.json`, test logs, source/build hashes and Git records
  accompany this document. Earlier receipts are not overwritten.

## Review preview — no deployment

```bash
cd /home/saintdomix/dissertation_model
PYTHONDONTWRITEBYTECODE=1 PRODUCT_FACTORY_ONLY=1 OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 .venv/bin/python -B scripts/run_ux_preview.py --port 18006 --assets demo/frontend/preview-ux-c2-20261104 --retained-session runtime/behavioral_v2/ui-e01c26a593174d42bec5d45faf703576
```

Open `http://127.0.0.1:18006/`. Stop this foreground preview with Ctrl+C.
The acceptance script stopped only its own child preview. Existing port8000
application and port18004 operator preview are left intact. ZAP and monitoring
were not restarted, stopped, reconfigured or operationally probed. Runtime
process state remains EXTERNALLY_MANAGED_UNKNOWN; this is not proof of a running
monitor and is not converted into benign monitoring status.

## Preservation and remaining limits

Final receipt checks all 451 protected hashes, accepted Behavioral package,
original source/recovery refs and original untracked paths. The frozen root is
`59a8c7c5d3d51632d0afe45f8cd2fe50570b7af2943d26bb313888327ea9f436`.
Task 2B remains KEEP_OCSVM (novelty 65/68, 41/68, 3/68; strict correct-class
63/68, 40/68, 3/68; production run detection 14/14 each). Fixed XGBoost remains
99/101 combined. These values are loaded from hash-pinned artifacts.
CQI and scanner/model source hashes are unchanged. No accepted raw evidence,
posture snapshot, scientific result or model was rewritten.

C2 proves fixture/API/browser presentation and wiring. It deliberately does
not prove new real STANDARD/FULL/PASSIVE execution, real cancellation, live
monitor start/stop or a live remediation. Those operational functions remain
implemented, reachable and preview-disabled, with source and fixture evidence.
No new closure workflow or scanner authorization mechanism was added.

The operator must personally inspect and approve the Overview before any
separate deployment decision. Keep both recovery checkpoints. Source rollback,
build restoration and backend deployment are separate operations; do not use a
destructive checkout over this working tree or touch scientific untracked data.
