# TASK 1C.2 — real execution proven, bounded PARTIAL result

**Not comprehensive DAST completion.** FULL_AUTHORIZED now performs real
discovery and Active Scan with nonzero enabled rules and target traffic. The
production run was time-limited and metadata export was incomplete. No claim
that all enabled rules ran, or that absent alerts prove security, is made.

First attempt: `posture-20261027T172357Z-b6df0bf04712` (UTC identifier), PARTIAL.
Native and discovery completed, but Active Scan startup was rejected. The
original transport did not retain ZAP's error enum, so the exact remote cause
is not proven. Read-only scope/seed checks passed. A SAFE-mode negative API
check produced mode_violation without starting a scan. Key-only SSH diagnostic
access was unavailable; no password was requested. The original snapshot was
not rewritten or relabelled.

The operator explicitly authorized **one** fresh retry after tests. Context-only
dispatch and an immediate `protect` check were added using the documented API.
The retry ran as `posture-20261027T174158Z-e94492f28474`. There was no third
assessment or scan.

Receipt:
`runtime/posture_acceptance/task1c2_posture-20261027T174158Z-e94492f28474/acceptance.json`

Receipt SHA256:
`d49d565bb52fa478c4de0764e90ea360206c9fb2e48006901ee796e01cb94a57`

## Requested structured report

1. **Architecture:** separate authorized target, full-profile API/provider and
   ZAP finding adapter; reused current Native, repository validators, canonical
   dedup, immutable snapshots and frozen Fusion/CQI.
2. **Profiles:** PASSIVE_BASELINE retains the old fresh-session/zero-rule gate.
   FULL_AUTHORIZED creates protected context, discovery and a real scan policy.
3. **Target:** configurable HTTP(S) base URL, origin/path/context include regex,
   narrowing excludes, discovery/auth mode and optional API-definition URLs.
4. **Other platform:** `https://moodle.example-university.kz/` passes synthetic
   configuration/API tests without source changes. No traffic was sent there.
   The Moodle-specific Native/behavioral collectors become explicitly unavailable
   rather than supplying unrelated lab evidence.
5. **ZAP:** 2.17.0 verified through the loopback tunnel.
6. **Add-ons:** 48; complete IDs/versions in `FULL_AUTHORIZED_CAPABILITIES.json`
   and the acceptance receipt inventory.
7. **Capability matrix:** see below. Installation/API availability is not proof
   of operational completion or execution.
8. **Mode/context:** fresh unnamed session; unique context matching the retry
   ID; exact HTTP origin and `/moodle/`; PROTECTED (`protect`) during execution;
   safe restored afterwards. API remains the existing loopback tunnel.
9. **Traditional Spider:** COMPLETE, 16 in-scope URLs, 4.034546 seconds.
10. **Client Spider:** installed/integrated/started. Published NOT_AVAILABLE after
    a 68.001455-second API/deadline failure. A later read showed its owned handle
    at 100%; no further stop was required. Do not relabel the original verdict.
11. **AJAX Spider:** PARTIAL at 60.042155 seconds, 70 additional URLs reported.
12. **Forced Browse:** installed `bruteforce` 20.0.0; no exposed control API in
    this daemon, not integrated/executed. Dictionary add-on presence is not a run.
13. **Fuzzer:** installed 13.16.0; specialized job contract exposed by the
    capabilities endpoint. Generic execution is not implemented or claimed.
14. **Imports:** OpenAPI 48.0.0, GraphQL 0.29.0, SOAP 29.0.0, Postman 0.9.0
    installed; optional URL-import adapters integrated. No definition configured
    or executed during Moodle acceptance; no real import acceptance claimed.
15. **Authentication:** anonymous. Verified ZAP credentials/role sessions
    NOT_CONFIGURED. Mode enums prepare later adapters; authenticated execution
    is not implemented/validated in this task.
16. **Policy:** `zap-full-authorized-1.0`, MEDIUM strength/threshold; unique
    named policy with effective rule IDs verified before dispatch. Ten explicit
    DoS/callback/custom-script/file-write/cross-origin exclusions are documented
    in `FULL_AUTHORIZED_ZAP.md`; ordinary injection tests are not excluded merely
    because they are active simulations.
17. **Installed active rules:** 53; passive rules: 61.
18. **Enabled active rules:** 43. Complete effective inventory is in the snapshot.
19. **Actually executed rule IDs:** NOT_DETERMINED by the implemented parser.
    Raw progress digest was retained; enabled is not tested. This remains a
    compatibility/observability limitation requiring a real-format fixture.
20. **Active traffic:** 1,740 recorded scan message IDs, history 332 → 2,100 at
    cancellation. Read-only polling also observed 1,741 requests at FINISHED;
    history later became 2,101. Exact membership of the additional record is not
    asserted, and frozen metrics were not silently revised.
21. **Active duration/result:** 600.064942 seconds, PARTIAL,
    ACTIVE_STAGE_DEADLINE, last recorded progress 19%. Limits were not widened.
22. **Passive findings:** 878 normalized current observations. Before-active
    passive queue completion and 878 alerts were recorded; final postprocessing
    did not publish a completed passive summary. Counts are derived from the
    hash-verified normalized source, not guessed from missing counters.
23. **Active alerts:** zero in the scan-owned alert-ID result and normalized
    source. This is not proof of vulnerability absence or full rule coverage.
24. **Passive-only canonical records:** 83 (including mapped and unmapped).
25. **Active-only canonical findings:** zero in this real run. Synthetic tests
    demonstrate their primary-list path without manufacturing a real weakness.
26. **Native-only canonical records:** 89 including 27 not-checked coverage slots;
    62 fresh Native-only observations. Native raw rows: 79, 30 HTTP requests.
27. **Multi-source:** four. Repository validation COMPLETE: one executed exposure
    validator, CONFIRMED; one unavailable prerequisite; 174 N/A rows.
28. **Dedup:** 971 source/coverage rows → 176 canonical records; 795 duplicates
    removed. Coverage slots are not fresh vulnerabilities.
29. **ZAP-only example:** ZAP-APPLICATION-ERROR, plugin 90022, MEDIUM,
    source confidence Medium, FAIL, `/moodle/admin/tool/dataprivacy/`, GET,
    ZAP_PASSIVE, existing Information Disclosure mapping, three retained members.
30. **Multi-source example:** DISC-001, Native + Passive, 71 members but one
    canonical control and contribution 0.25. No real four-source example exists.
31. **Independence:** the ZAP-only application-error record did not require a
    Native finding. Synthetic SQLi/XSS records likewise create independent FAIL
    findings and appear in the primary API/UI.
32. **Penalty proof:** all eligible canonical contributions equal the maximum
    eligible member contribution, never a sum. The four-source synthetic test
    preserves one penalty. Entire frozen Fusion outputs are unchanged before/
    after attaching repository-validation metadata.
33. **CQI:** 95 records have mapped categories (including coverage), 81 ZAP
    canonical records have CQI UNMAPPED. Native-only partial CQI
    40.23080444335938 → expanded current partial CQI 39.26910018920899.
    ZAP-APPLICATION-ERROR adds an existing mapped contribution 0.175.
    HDR-006 also changes: Native base-page PASS (0) conflicts with broader ZAP
    clickjacking evidence (0.175); the existing maximum policy uses one 0.175
    contribution. ZAP-COMMENT-DISCLOSURE contributes zero. The decrease is not
    attributed solely to the new application-error record or to duplicate sums.
34. **API/UI:** explicit target/profile/authorization controls; FULL stage summary;
    distinct ZAP_PASSIVE/ZAP_ACTIVE badges; first-class FAIL rows with separate
    CQI mapping, risk/confidence and sanitized technical details. Current and
    retained routes preserve provenance. Cancel endpoint stops owned jobs only.
35. **Files:** listed below; prior dirty work preserved.
36. **Focused tests:** 32 new FULL_AUTHORIZED cases including parametrization;
    focused transport/API run 100 passed before retry; reader-focused run 57
    passed after the first metadata fix.
37. **Regression:** final relevant Python suite 347 PASS, including the focused
    tests; no unrelated training pipelines.
38. **Frontend:** 46 tests PASS; production build PASS.
39. **Diff check:** PASS.
40. **Real ID:** `posture-20261027T174158Z-e94492f28474`; first failed ID above is
    preserved independently.
41. **Disk:** approximately 3 GB free; never crossed the 500 MB guard.
42. **Diff stat:** tracked diff includes prior work; exact final inspection is
    appended below. Untracked implementation is not counted by git diff --stat.
43. **Status:** dirty tree retained, nothing staged/committed/tagged.
44. **Behavioral v2:** unchanged canonical hash
    `59a8c7c5d3d51632d0afe45f8cd2fe50570b7af2943d26bb313888327ea9f436`.
    All 1,430 pre-existing protected files and 97 frozen source files unchanged;
    first attempt's seven files unchanged after retry. Frozen core Git diff empty.
45. **Remaining:** partial active coverage; installed-format per-rule parser;
    optional browser deadlines; incomplete history/form/method metadata export;
    unconfigured authentication/import/fuzz/sequence jobs; Forced Browse lacks
    the required API. Single-record export and interruption retention were fixed
    and unit tested after the run, without rewriting its evidence. The bounded
    read-only recovery did not complete, so forms/status distributions/exact
    active URL membership are not fabricated. No third recovery/scan is planned.
46. **Next task:** focused postprocessing/per-rule observability acceptance and
    coverage review before another separately authorized complete DAST run.
    Do not begin CQI redesign or platform normalization from this partial result.

## Capability matrix for the real retry

| Capability | Installed | Integrated | Executed / result |
|---|---|---|---|
| Traditional Spider | Yes | Yes | COMPLETE |
| Client Spider | Yes | Yes | Started; published NOT_AVAILABLE / deadline |
| AJAX Spider | Yes | Yes | PARTIAL / deadline |
| Passive scanner | Yes | Yes | Current findings retained; final summary incomplete |
| Active scanner | Yes | Yes | Real traffic; PARTIAL / deadline |
| OpenAPI / GraphQL / SOAP / Postman | Yes | URL adapters | NOT_CONFIGURED |
| Forced Browse | Yes | No control API | NOT_EXECUTED |
| Fuzzer | Yes | Job-contract boundary only | NOT_EXECUTED |
| Authentication/session support | Yes | Mode/config boundary | NOT_CONFIGURED |
| Sequence | Yes | No configured job | NOT_EXECUTED |
| Automation Framework | Yes | Python orchestration used | NOT_EXECUTED |
| Technology context | Yes/core | Yes | Context recorded; generic rules retained |

Availability flags in inventories describe installed/API capability, not proof
that browsers, credentials or a particular job completed successfully.

## Files changed in this task

New: `src/posture/target.py`, `zap_full_api.py`, `zap_full.py`,
`zap_normalize.py`; `tests/test_zap_full_authorized.py`;
`docs/posture/FULL_AUTHORIZED_ZAP.md`, `FULL_AUTHORIZED_CAPABILITIES.json`,
`TASK1C2_ACCEPTANCE.md`.

Modified: `src/posture/providers.py`, `model.py`, `orchestration.py`;
`demo/backend/schemas.py`, `adapters.py`, `posture_api.py`, `services.py`;
`demo/frontend/src/components/OperationalPosture.jsx`,
`demo/frontend/scripts/product_render.test.mjs`; `scripts/run_posture.py`.
Ignored frontend build assets regenerated. Only new runtime snapshots/receipts
were created; no previous evidence or snapshots were modified.

## Operational notes

The normal launcher required one retry before the first assessment; preflight
passed. The authorized assessment retry used the normal launcher successfully.
No unrelated processes were terminated. Runtime journals were preserved.

The postprocessing fixes are tested source changes, not a claim that the saved
run executed their later reader implementation. A read view may derive missing
summary counts from immutable normalized findings while retaining the original
failure and snapshot bytes. No model/scanner tuning was performed to improve
the observed result. CQI formula, coefficients, weights and mappings unchanged.

## Final Git inspection

```text
 demo/backend/adapters.py                      | 20 +++++++-
 demo/backend/app.py                           | 19 +++++--
 demo/backend/schemas.py                       | 53 +++++++++++++++++++-
 demo/backend/services.py                      | 71 +++++++++++++++++++++++++--
 demo/frontend/scripts/product_render.test.mjs | 70 ++++++++++++++++++++++++++
 demo/frontend/src/pages/ProductPages.jsx      | 14 ++++--
 docs/release/FINAL_ARCHITECTURE.md            | 21 +++++++-
 7 files changed, 253 insertions(+), 15 deletions(-)
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
?? tests/test_zap_full_authorized.py
?? tests/test_zap_history.py
```

Final read-only API check: PARTIAL, active messages 1740, active alerts 0, passive alerts 878, primary rows 176, ZAP-only rows 83. Original RESPONSE_SIZE_LIMIT retained; counts derived from hash-verified normalized findings. Final normal demo launcher: backend/frontend/runtime/model integrity OK; no new assessment started.
