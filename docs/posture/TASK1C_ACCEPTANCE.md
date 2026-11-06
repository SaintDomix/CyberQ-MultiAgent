# TASK 1C — gated no-op acceptance; executing scan remains blocked

Production assessment: `posture-20261027T134140Z-3e125fe236b4` (UTC identifier).

Receipt:
`runtime/posture_acceptance/task1c_posture-20261027T134140Z-3e125fe236b4/acceptance.json`

Receipt SHA256:
`2cb5aba61c4262d0927b1c3e4ef52c0d23625a2e9f75066bfdff480fc8ce9ca4`

This is **not acceptance of an executing active scanner**. The requested
zero-safe-rule outcome was used without relaxing safety. See
`BOUNDED_ZAP_ACTIVE.md` and `ZAP_ACTIVE_SCANNER_REVIEW.json`.

## Actual single production-path assessment

| Stage | Result | HTTP target requests |
|---|---|---:|
| Native | COMPLETE | 30 |
| ZAP Passive | COMPLETE, fresh unnamed session, scope PASS | 5 |
| Repository Active Validation | COMPLETE, exposure corroboration | 2 |
| ZAP Active gate | NOT_AVAILABLE / NO_REVIEWED_SAFE_SCANNERS | 0 |

ZAP 2.17.0 remained in safe mode. 53 installed rules were reviewed for policy:
42 DISABLED_UNSAFE, 4 DISABLED_NOT_RELEVANT, 7 DISABLED_UNREVIEWED. No rule was
enabled; the daemon's default rule settings were not changed. There is no scan
ID. No API active-scan dispatch, mode weakening, crawling or payload traffic was
issued. Gate control checks took 0.053274573 seconds. Actual scan duration zero.

Three current candidates (GET 2xx): `/moodle/`, `/moodle/course/`,
`/moodle/login/index.php`. Zero parameters. `/my/` and `/admin/` 303 responses
remain valid passive evidence but are excluded from active candidates. Planned
active work zero; hard ceiling zero. ZAP history stayed 11 to 11. No active
traffic existed to process in the passive queue. Active produced/mapped/unmapped,
corroborating and unique observations: all zero.

121 current source/coverage rows became 110 canonical rows, 11 duplicate rows
removed, 3 multi-source canonical findings. No ZAP Active row entered scoring.
Rebuilding from this assessment's fresh Native/Passive sources and coverage
produced byte-equivalent frozen Fusion artifacts before/after attached
repository-validation metadata. Posture-only partial CQI: 40.23080444335938 in
both projections. No new mapped weakness or active-induced CQI change.

Real examples: HDR-002 retains Native + ZAP Passive, four source members, one
canonical CSP control, active validation N/A. EXPOSURE-001 retains Native and
repository sensitive_path CONFIRMED, two GETs, parent weakness unchanged.
There is **no real four-source example**, because ZAP Active did not execute.
A synthetic four-source dedup test proves the existing maximum-contribution
policy retains one penalty rather than four.

## Verification

- Focused gate + current-validation tests: 68 PASS.
- Relevant posture/API/validator/product regression tests: 315 PASS total,
  including those 68; no unrelated ML pipelines run.
- Frontend tests: 43 PASS. Production Vite build PASS.
- Snapshot version 1.2: all six member-file hashes verified, plus manifest.
- All 1,413 pre-existing protected files remained byte-identical.
- All 97 inventoried frozen source files unchanged; baseline Git core diff empty.
- Behavioral v2 canonical root verified unchanged:
  `59a8c7c5d3d51632d0afe45f8cd2fe50570b7af2943d26bb313888327ea9f436`.
- Synthetic rerun test executes the gate on both new assessment identities,
  preserves the first snapshot and refuses injected/stale active rows.
- Fourth-stage failure leaves Native, Passive and repository validation intact.

One normal demo start failed before assessment submission. Normal preflight
passed; one normal retry succeeded. Exactly one assessment POST was submitted.
No broad process termination or operational permission change was performed.

## Remaining prerequisites

No executing scanner/cancellation/deadline/active-generated queue-drain tests
are claimed. Installed add-on/core identity and enforceable pre-send
scope/method/request/response limits must be established before enabling a rule.
Protected context and isolated active runtime restoration remain unimplemented.
This work stops at the honest gated outcome, not a claimed full active-scanning
capability. No CQI redesign, platform normalization, ML training, commit or tag.

## Final Git inspection

The tracked diff includes prior uncommitted work; untracked posture source is not
counted by Git diff --stat. No paths were staged.

```text
 demo/backend/adapters.py                      | 18 +++++++-
 demo/backend/app.py                           | 19 ++++++--
 demo/backend/schemas.py                       | 33 ++++++++++++++
 demo/backend/services.py                      | 62 +++++++++++++++++++++++++--
 demo/frontend/scripts/product_render.test.mjs | 57 ++++++++++++++++++++++++
 demo/frontend/src/pages/ProductPages.jsx      | 14 +++---
 docs/release/FINAL_ARCHITECTURE.md            | 21 ++++++++-
 7 files changed, 210 insertions(+), 14 deletions(-)
```

```text
 M demo/backend/adapters.py
 M demo/backend/app.py
 M demo/backend/schemas.py
 M demo/backend/services.py
 M demo/frontend/scripts/product_render.test.mjs
 M demo/frontend/src/pages/ProductPages.jsx
 M docs/release/FINAL_ARCHITECTURE.md
?? data/branch2_v2/final_candidate_01/
?? data/branch2_v3/
?? data/raw/AP01_suspicious_run51_access.log
?? data/raw/AP01_suspicious_run52_access.log
?? data/raw/AP01_suspicious_run53_access.log
?? data/raw/AP01_suspicious_run54_access.log
?? data/raw/AP01_suspicious_run55_access.log
?? data/raw/AP01_suspicious_run56_access.log
?? data/raw/AP01_suspicious_run57_access.log
?? data/raw/AP01_suspicious_run58_access.log
?? data/raw/AP01_suspicious_run59_access.log
?? data/raw/AP01_suspicious_run60_access.log
?? data/raw/B04_benign_run51_access.log
?? data/raw/B04_benign_run52_access.log
?? data/raw/B04_benign_run53_access.log
?? data/raw/BN02_benign_run51_access.log
?? data/raw/BN02_benign_run52_access.log
?? data/raw/PT01_suspicious_run51_access.log
?? data/raw/PT01_suspicious_run52_access.log
?? data/raw/PT01_suspicious_run53_access.log
?? data/raw/PT01_suspicious_run54_access.log
?? data/raw/PT01_suspicious_run55_access.log
?? data/raw/PT01_suspicious_run56_access.log
?? data/raw/PT01_suspicious_run57_access.log
?? data/raw/PT01_suspicious_run58_access.log
?? data/raw/PT01_suspicious_run59_access.log
?? data/raw/PT01_suspicious_run60_access.log
?? data/raw/RB01_suspicious_run51_access.log
?? data/raw/RB01_suspicious_run52_access.log
?? data/raw/RB01_suspicious_run53_access.log
?? data/raw/RB01_suspicious_run54_access.log
?? data/raw/RB01_suspicious_run55_access.log
?? data/raw/RB01_suspicious_run56_access.log
?? data/raw/RB01_suspicious_run57_access.log
?? data/raw/RB01_suspicious_run58_access.log
?? data/raw/S01_suspicious_run54_access.log
?? data/raw/S01_suspicious_run55_access.log
?? data/raw/S01_suspicious_run56_access.log
?? data/raw/S01_suspicious_run57_access.log
?? data/raw/S01_suspicious_run58_access.log
?? data/raw/S01_suspicious_run59_access.log
?? data/raw/S01_suspicious_run60_access.log
?? data/raw/S02_suspicious_run53_access.log
?? data/raw/S02_suspicious_run54_access.log
?? data/raw/S02_suspicious_run55_access.log
?? data/raw/S02_suspicious_run56_access.log
?? data/raw/S02_suspicious_run57_access.log
?? data/raw/S02_suspicious_run58_access.log
?? data/raw/S02_suspicious_run59_access.log
?? data/raw/S02_suspicious_run60_access.log
?? data/raw/SQ01_suspicious_run51_access.log
?? data/raw/SQ01_suspicious_run52_access.log
?? data/raw/SQ01_suspicious_run53_access.log
?? data/raw/SQ01_suspicious_run54_access.log
?? data/raw/SQ01_suspicious_run55_access.log
?? data/raw/SQ01_suspicious_run56_access.log
?? data/raw/SQ01_suspicious_run57_access.log
?? data/raw/SQ01_suspicious_run58_access.log
?? data/raw/SQ01_suspicious_run59_access.log
?? data/raw/SQ01_suspicious_run60_access.log
?? data/raw/XS01_suspicious_run51_access.log
?? data/raw/XS01_suspicious_run52_access.log
?? data/raw/XS01_suspicious_run53_access.log
?? data/raw/XS01_suspicious_run54_access.log
?? data/raw/XS01_suspicious_run55_access.log
?? data/raw/XS01_suspicious_run56_access.log
?? data/raw/XS01_suspicious_run57_access.log
?? data/raw/XS01_suspicious_run58_access.log
?? data/raw/XS01_suspicious_run59_access.log
?? data/raw/XS01_suspicious_run60_access.log
?? demo/backend/posture_api.py
?? demo/frontend/src/components/OperationalPosture.jsx
?? docs/posture/
?? evidence/branch2_captures/
?? outputs/branch2/live/
?? outputs/branch2/m5/
?? outputs/fusion/
?? scripts/run_posture.py
?? src/posture/
?? tests/test_current_active.py
?? tests/test_fresh_posture.py
?? tests/test_native_plan.py
?? tests/test_operational_posture.py
?? tests/test_posture_demo_patch.py
?? tests/test_posture_timeouts.py
?? tests/test_zap_active_gate.py
?? tests/test_zap_history.py
```
