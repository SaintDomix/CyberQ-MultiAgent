# Task 1C.3 — observability implemented; full completion NOT accepted

Exactly one new production-path FULL_AUTHORIZED assessment was submitted:
`posture-20261027T184230Z-2760023ac85e` against `http://192.168.226.132/moodle/`.
Its final overall and active statuses are **PARTIAL**, not COMPLETE.
No additional scan was submitted after this result. No model was retrained,
no CQI/scoring/mapping policy was changed, and no previous assessment was rewritten.

Started 2026-10-27 23:42:30 Asia/Qyzylorda (assessment identifier is UTC).
ZAP provider finished 2026-10-28 00:46:51 Asia/Qyzylorda.

Machine receipt: `runtime/posture_acceptance/task1c3_posture-20261027T184230Z-2760023ac85e/acceptance.json`
SHA256: `60de9c4e0739dbfad3f5eac59ff3348c8c491687b9dc17a8de35d09d1235b385`

Immutable snapshot: `runtime/posture/posture-20261027T184230Z-2760023ac85e/artifact_manifest.json`
SHA256: `7364fd795045d4a59128dba86b4f5f32d827a7eb199b5d973e5e496b9353ca06`

The original Task 1C.2 receipt and snapshot remain byte-identical. Diagnosis
obtained later from retained daemon counters is a separate supplement in
`runtime/posture_acceptance/task1c3_diagnostic/`, not a rewritten historical result.

## Requested 40-point report

1. **Previous 19%/600-second cause.** The global active cutoff truncated an
   uncapped-completion workload. Retained counters show nine rules started and
   three skipped under the former two-minute per-rule setting. Recorded times:
   SSI 181565 ms, Path Traversal 128231 ms, External Redirect 120164 ms. Low
   concurrency/rate and delay also constrained throughput, but their causal
   shares cannot be separated from this evidence. The old progress parser failed
   to decode ZAP's positional nested JSON lists, hiding rule outcomes. Timings
   are not necessarily additive; work/URL counters are not HTTP request counts.
2. **Endpoint workload.** Old assessment: 99 normalized endpoints. New discovery:
   223 in-scope URL entries, 220 endpoint/query-name identities, three value
   variants collapsed, 15 query-parameter occurrences. Client discovery expanded
   the current workload materially. This is not a controlled speed benchmark.
   Current tree metadata separately preserves 222 method/endpoint/parameter
   identities across 227 nodes. ZAP already collapses query-value variants; one
   context scan is dispatched, without repeat per-URL scans or dropped families.
3. **Old/new settings.** Threads 2 → 4; host rate cap 4 → 8 requests/s; delay
   250 → 100 ms; active 600 → 3660 s; overall 1000 → 4380 s; rule cap 2 minutes
   → zero independent rule cap (the active deadline remains finite). Client/AJAX
   60 → 90 s each; passive completion 60 → 120 s. Scanner response timeout stays
   20 s; bounded API transport unchanged. Four sequential GETs had median
   0.063887 s. Eight ordinary GETs at concurrency four all returned 200, median
   0.190311 s, elapsed 0.397614 s. Actual sampled request-counter rates reached
   8.126/s and included stalls. No whole-scan speedup,
   stress-test stability or causal latency improvement is claimed.
4. **Deadline derivation and limitation.** `ceil(600/.19*1.15/60)*60 = 3660 s`.
   This prospectively used the prior observed cutoff and 15% planning margin,
   without assuming a concurrency speedup. It proved insufficient: the old
   progress was from a capped run and the new discovery had 220 versus 99
   endpoints. Progress is not a calibrated linear ETA. No deadline was extended
   during this run. Absolute configurable ceilings remain active 5400 s, overall
   7200 s, four threads, 8 requests/s, disk minimum 500 MB. Bounded cleanup uses
   independent control deadlines after the execution deadline.
5. **Rule observability.** Parse actual seven-field ZAP 2.17 plugin arrays and
   nested JSON strings, plus named-field responses. Preserve live samples every
   ten seconds and final rule rows. Baseline-difference retained daemon counters
   so previous executions are not counted as current. Enabled is never proof of
   execution. COMPLETE requires owned `ascan.scans` FINISHED at actual 100%, not
   `status()` alone, which also returns 100 for stopped jobs.
6. **Installed active scanners:** 53; passive scanners: 61.
7. **Enabled active scanners:** 43, same comprehensive policy and ten exclusions.
8. **Observed executing:** 19 by authoritative started/time/request evidence;
   17 made positive recorded HTTP requests. Two completed rules had zero HTTP
   requests. Entering a rule is not proof that every technique was applicable.
9. **Not observed:** 24 enabled rules remain Pending/NOT_OBSERVED; ten policy
   exclusions are NOT_ENABLED. No NOT_APPLICABLE verdict was invented.
10. **Metadata export:** COMPLETE for the declared structural scope, history
    count 9978; body-free Sites Tree plus discovery
    metadata replaces default all-history response-body download. GET/POST and
    exposed statuses 200/303 are retained. Zero history bodies downloaded for
    export; no response bodies retained. Seed forms: zero. Full application form
    structure and all-history status distributions are NOT claimed; query-name
    counts do not enumerate every POST-body/cookie parameter. Legacy body-reader
    compatibility tests remain, but that reader is no longer the default path.
11. **Client Spider:** PARTIAL at 54%,
    92.397 s, 181 additional URLs.
    It had an owned handle, so it is not labelled unavailable. Stop uses a new
    bounded control deadline. Post-freeze status 100 is diagnostic only and
    does not rewrite the published PARTIAL cutoff result.
12. **AJAX Spider:** PARTIAL, 90.131 s,
    12 additional URLs; stop requested at the owned stage deadline. Later stopped
    state is cleanup evidence, not retroactive completion.
13. **Raw/normalized discovery:** Traditional Spider COMPLETE, 16 URLs,
    2.081 s; aggregate discovery
    223 → 220 endpoint/query-name identities. Metadata contains 227 tree nodes
    and 222 identities when method differences are included. These are different
    measurements; they are not interchangeable request counts.
14. **Passive repetition audit:** old 878 instances → 229 distinct
    plugin/route/parameter/method observations → 87 reviewed keys (83 passive-only
    plus four Native overlaps), 791 repeated members grouped. Timestamp rule
    10096 alone accounted for 605 instances. New 1435 passive instances → 432
    semantic observations → 162 reviewed keys (158 passive-only plus four Native
    overlaps), 1273 repeated members grouped. All instance evidence remains.
15. **Isolation:** fresh unnamed session verified at zero messages before any
    target collection; unique owned context; no historical finding import.
    Regression rejects a reset/no-op that leaves history before reading alerts.
    Active ownership uses scan alert IDs, not title/CWE guesses. Old snapshots
    are still hash-identical.
16. **Real assessment ID:** `posture-20261027T184230Z-2760023ac85e`; FULL_AUTHORIZED; ZAP 2.17.0,
    PROTECTED during assessment, SAFE restored; exact HTTP origin and `/moodle/`.
17. **Active Scan ID:** `0` in this new isolated session; context `posture-20261027T184230Z-2760023ac85e`.
18. **Final actual progress:** 43%.
19. **Active final status:** PARTIAL, ACTIVE_STAGE_DEADLINE. Not full DAST completion.
20. **Active duration:** 3660.135907 s (61-minute cutoff).
21. **Active messages:** 9353 scan-owned IDs recorded;
    history 579 → 9977 at
    active collection; metadata final count 9978.
    The one later history entry is not silently reclassified or added to the
    frozen active-ID count. Post-freeze history remains 9978.
22. **Passive alerts:** 1435 normalized observations; final passive queue drained.
23. **Active alerts:** one, ID 6638 reported by owned scan. Plugin 40018 SQL
    Injection; POST `/moodle/lib/ajax/service.php`, parameter `info`, HIGH risk,
    ZAP Medium confidence. This is scanner evidence, project NOT_CONFIRMED,
    not successful exploitation. It is CQI UNMAPPED and contributes no invented
    penalty. The primary API returns it as a first-class current FAIL finding.
24. **ZAP-only canonical findings:** 159: 158 passive-only, one active-only.
25. **Multi-source findings:** four Native + Passive groups. There is no real
    four-source group in this run; the four-source no-multiplication proof is
    synthetic and explicitly labelled as such.
26. **Before/after dedup:** 1515 provider source rows + 14 additional coverage
    rows = 1529 input rows → 252 canonical records, 1277 collapsed. Native-only
    canonical count 89 includes coverage slots. Mapped canonical records: 95,
    including unavailable coverage records; CQI UNMAPPED: 157.
27. **Application error 90022:** new current-session evidence contains 19 members
    grouped under existing `ZAP-APPLICATION-ERROR`, MEDIUM/Medium, Information
    Disclosure. One maximum contribution 0.175. Route/parameter/member evidence
    remains; grouping does not prove every server error has one causal bug.
    The earlier dataprivacy instance remains historical and unmodified.
28. **CQI:** Native-only partial projection 40.23080444335938 →
    combined partial projection 39.26910018920899, same as the prior combined
    value. Changes versus Native are a new mapped application-error key (0.175)
    and HDR-006's maximum source changing 0 → 0.175 from broader fresh missing
    clickjacking evidence, despite the Native base-page PASS. No score change
    comes from multiplying duplicate sources. The new active SQL alert is
    unmapped and has no CQI effect. Baseline equal 1/6 policy is unchanged;
    this partial projection renormalizes available dimensions, not missing data
    to PASS. D5 and D6 are unavailable. CQI is a quality index, not probability.
29. **Penalty proof:** every scored canonical record equals its maximum eligible
    member contribution. The receipt includes all multi-member checks. Removing
    attached Active Validation metadata leaves CQI identical. Synthetic Native
    + Passive + repository-validation + Active corroboration preserves one
    penalty. Existing maps/formula/weights and frozen Fusion files are unchanged.
30. **Focused tests:** 13 new completion/telemetry cases plus 32 existing full
    provider/API cases pass within the relevant suite. Initial focused
    freshness/history set: 88 passed before the real run; the later extra
    dirty-session regression also passes. Scope, cancellation, provenance,
    sanitization, late-result immutability and failure isolation are covered.
31. **Relevant regressions:** 360 Python tests passed (20.46 s final run).
    No expensive model/research pipeline was run. Native is COMPLETE with
    30 HTTP requests/79 source rows. Repository Active Validation is COMPLETE,
    two eligible, one executed/CONFIRMED, one unavailable, 250 N/A, two actual
    requests. It remains score-effect NONE.
32. **Frontend:** 48 tests passed; Vite production build passed. Live ascan
    progress takes precedence over its initial RUNNING placeholder. Rule
    execution is displayed independently from enabled policy and metadata stage.
33. **git diff --check:** PASS; frozen-core comparison with
    `milestone-3-end-to-end` remains empty. No staging/commit/tag occurred.
34. **Task-specific files:** listed below. Other pre-existing dirty work is
    preserved; aggregate git diff/stat must not be misrepresented as this task's
    source changes alone. Generated local Vite assets were rebuilt.
35. **Disk:** 3063500800 bytes free at report generation
    (2.853 GiB); above 500 MB guard.
36. **git diff --stat:** complete aggregate below.
37. **git status --short:** complete aggregate below; prior untracked data,
    evidence and outputs were preserved, not staged or deleted.
38. **Behavioral v2:** VERIFIED, canonical SHA256
    `59a8c7c5d3d51632d0afe45f8cd2fe50570b7af2943d26bb313888327ea9f436`.
    All 1447 pre-existing protected data/evidence/output/posture files and
    97 frozen implementation/cache files match the before inventory.
39. **Remaining blockers:** DOM-based XSS consumed 1369.932 s
    and remained at 77% (2040 rule requests); 24 enabled rules were still pending.
    Path Traversal consumed 762.670 s; SQLite time-based SQL 410.418 s;
    reflected XSS 233.321 s; SSI 188.657 s. These timings are not additive causal
    percentages. The target's ordinary GET stayed responsive (200, 0.071748 s)
    and three sampled completed scan messages had 8–34 ms RTT; no target outage
    is established. Runtime/browser scheduling, in-flight waits and endpoint-level
    cost cannot be fully separated by these API counters. Exact endpoint time
    dominance is NOT exposed by this API export, and is not fabricated.
    Current discovery is over twice the previous endpoint count, and the old
    per-rule-truncated percentage did not provide a reliable completion estimate.
    Client/AJAX discovery also remains bounded PARTIAL. All-history form/status
    coverage is explicitly limited; the UI's existing primary table displays up
    to 200 rows, with full records in the snapshot/paginated API. The real active
    SQL finding is within that primary page.
40. **Final verdict:** FULL_AUTHORIZED cannot be considered COMPLETE. Per-rule
    observability, metadata export and honest cutoff semantics are working, but
    the primary completion goal is unproven. A separately authorized focused
    DOM/browser/workload investigation and prospectively justified execution plan
    is needed before another expensive full acceptance. Do not disable families
    or relabel this result to force 100%. No further task has been started.

## Current dimension projection

| Dimension | Quality |
|---|---:|
| D1 | 4.533748626708989 |
| D2 | 91.44140625000001 |
| D3 | 13.601245880126944 |
| D4 | 47.50000000000001 |
| D5 | NOT AVAILABLE |
| D6 | NOT AVAILABLE |

## Per-rule evidence

Started/time/request evidence is separate from enabled policy. A zero request
count is not a tested-vulnerability claim. Full detail also exists in the CSV.

| Rule | Name | Execution state | Requests | Alerts | Final progress/status | Time ms |
|---|---|---|---:|---:|---|---:|
| 0 | Directory Browsing | NOT_OBSERVED | 0 | 0 | Pending | 0 |
| 6 | Path Traversal | EXECUTED | 891 | 0 | Complete | 762670 |
| 7 | Remote File Inclusion | NOT_ENABLED | NOT EXPOSED | NOT EXPOSED | NOT OBSERVED | 0 |
| 10045 | Source Code Disclosure - /WEB-INF Folder | EXECUTED | 5 | 0 | Complete | 1542 |
| 10047 | HTTPS Content Available via HTTP | NOT_ENABLED | NOT EXPOSED | NOT EXPOSED | NOT OBSERVED | 0 |
| 10048 | Remote Code Execution - Shell Shock | EXECUTED | 100 | 0 | Complete | 72710 |
| 10058 | GET for POST | NOT_OBSERVED | 0 | 0 | Pending | 0 |
| 10104 | User Agent Fuzzer | NOT_OBSERVED | 0 | 0 | Pending | 0 |
| 10106 | HTTP Only Site | NOT_ENABLED | NOT EXPOSED | NOT EXPOSED | NOT OBSERVED | 0 |
| 20015 | Heartbleed OpenSSL Vulnerability | EXECUTED | 0 | 0 | Complete | 2 |
| 20017 | Source Code Disclosure - CVE-2012-1823 | EXECUTED | 158 | 0 | Complete | 30138 |
| 20018 | Remote Code Execution - CVE-2012-1823 | EXECUTED | 454 | 0 | Complete | 67542 |
| 20019 | External Redirect | EXECUTED | 450 | 0 | Complete | 66682 |
| 30001 | Buffer Overflow | NOT_ENABLED | NOT EXPOSED | NOT EXPOSED | NOT OBSERVED | 0 |
| 30002 | Format String Error | NOT_OBSERVED | 0 | 0 | Pending | 0 |
| 40003 | CRLF Injection | NOT_OBSERVED | 0 | 0 | Pending | 0 |
| 40008 | Parameter Tampering | NOT_OBSERVED | 0 | 0 | Pending | 0 |
| 40009 | Server Side Include | EXECUTED | 200 | 0 | Complete | 188657 |
| 40012 | Cross Site Scripting (Reflected) | EXECUTED | 250 | 0 | Complete | 233321 |
| 40014 | Cross Site Scripting (Persistent) | EXECUTED | 0 | 0 | Complete | 10256 |
| 40016 | Cross Site Scripting (Persistent) - Prime | EXECUTED | 50 | 0 | Complete | 16566 |
| 40017 | Cross Site Scripting (Persistent) - Spider | EXECUTED | 227 | 0 | Complete | 39778 |
| 40018 | SQL Injection | EXECUTED | 1130 | 1 | Complete | 151935 |
| 40019 | SQL Injection - MySQL (Time Based) | EXECUTED | 500 | 0 | Complete | 72921 |
| 40020 | SQL Injection - Hypersonic SQL (Time Based) | EXECUTED | 500 | 0 | Complete | 72946 |
| 40021 | SQL Injection - Oracle (Time Based) | EXECUTED | 250 | 0 | Complete | 41618 |
| 40022 | SQL Injection - PostgreSQL (Time Based) | EXECUTED | 250 | 0 | Complete | 41609 |
| 40024 | SQL Injection - SQLite (Time Based) | EXECUTED | 449 | 0 | Complete | 410418 |
| 40026 | Cross Site Scripting (DOM Based) | EXECUTED | 2040 | 0 | 77% | 1369932 |
| 40027 | SQL Injection - MsSQL (Time Based) | NOT_OBSERVED | 0 | 0 | Pending | 0 |
| 40028 | ELMAH Information Leak | NOT_OBSERVED | 0 | 0 | Pending | 0 |
| 40029 | Trace.axd Information Leak | NOT_OBSERVED | 0 | 0 | Pending | 0 |
| 40032 | .htaccess Information Leak | NOT_OBSERVED | 0 | 0 | Pending | 0 |
| 40034 | .env Information Leak | NOT_OBSERVED | 0 | 0 | Pending | 0 |
| 40035 | Hidden File Finder | NOT_OBSERVED | 0 | 0 | Pending | 0 |
| 40042 | Spring Actuator Information Leak | NOT_OBSERVED | 0 | 0 | Pending | 0 |
| 40043 | Log4Shell | NOT_ENABLED | NOT EXPOSED | NOT EXPOSED | NOT OBSERVED | 0 |
| 40044 | Exponential Entity Expansion (Billion Laughs Attack) | NOT_ENABLED | NOT EXPOSED | NOT EXPOSED | NOT OBSERVED | 0 |
| 40045 | Spring4Shell | NOT_ENABLED | NOT EXPOSED | NOT EXPOSED | NOT OBSERVED | 0 |
| 40048 | Remote Code Execution (React2Shell) | NOT_OBSERVED | 0 | 0 | Pending | 0 |
| 50000 | Script Active Scan Rules | NOT_ENABLED | NOT EXPOSED | NOT EXPOSED | NOT OBSERVED | 0 |
| 90017 | XSLT Injection | NOT_OBSERVED | 0 | 0 | Pending | 0 |
| 90019 | Server Side Code Injection | NOT_OBSERVED | 0 | 0 | Pending | 0 |
| 90020 | Remote OS Command Injection | NOT_OBSERVED | 0 | 0 | Pending | 0 |
| 90021 | XPath Injection | NOT_OBSERVED | 0 | 0 | Pending | 0 |
| 90023 | XML External Entity Attack | NOT_ENABLED | NOT EXPOSED | NOT EXPOSED | NOT OBSERVED | 0 |
| 90024 | Generic Padding Oracle | NOT_OBSERVED | 0 | 0 | Pending | 0 |
| 90026 | SOAP Action Spoofing | NOT_OBSERVED | 0 | 0 | Pending | 0 |
| 90029 | SOAP XML Injection | NOT_OBSERVED | 0 | 0 | Pending | 0 |
| 90034 | Cloud Metadata Potentially Exposed | NOT_ENABLED | NOT EXPOSED | NOT EXPOSED | NOT OBSERVED | 0 |
| 90035 | Server Side Template Injection | NOT_OBSERVED | 0 | 0 | Pending | 0 |
| 90036 | Server Side Template Injection (Blind) | NOT_OBSERVED | 0 | 0 | Pending | 0 |
| 90037 | Remote OS Command Injection (Time Based) | NOT_OBSERVED | 0 | 0 | Pending | 0 |

## Task-specific source/test/document files

- `src/posture/zap_full.py`
- `src/posture/zap_full_api.py`
- `src/posture/zap_observability.py`
- `tests/test_zap_full_authorized.py`
- `tests/test_zap_completion.py`
- `demo/frontend/src/components/OperationalPosture.jsx`
- `demo/frontend/scripts/product_render.test.mjs`
- `docs/posture/TASK1C3_PROTOCOL.md`
- `docs/posture/TASK1C3_ACCEPTANCE.md`

Generated new operational evidence only: `runtime/posture/posture-20261027T184230Z-2760023ac85e/`, `runtime/posture_acceptance/task1c3_posture-20261027T184230Z-2760023ac85e/`,
`runtime/posture_acceptance/task1c3_diagnostic/`.
No full ZAP database, response-body archive, screenshots or browser download
was created. All prior snapshots remain untouched.

## Cleanup / post-freeze diagnostics

`postfreeze_runtime.json` confirms SAFE, no active/spider handles, AJAX stopped,
Client status 100, passive queue zero, and stable final history 9978. Client's
late completion does not rewrite its PARTIAL cutoff. No owned ZAP job was left
running. The normal demo backend/saved-model monitor remain in LIVE_LAB.

## Aggregate working-tree diff stat

```text
 demo/backend/adapters.py                      | 20 ++++++-
 demo/backend/app.py                           | 19 +++++--
 demo/backend/schemas.py                       | 53 +++++++++++++++++-
 demo/backend/services.py                      | 71 ++++++++++++++++++++++--
 demo/frontend/scripts/product_render.test.mjs | 78 +++++++++++++++++++++++++++
 demo/frontend/src/pages/ProductPages.jsx      | 14 +++--
 docs/release/FINAL_ARCHITECTURE.md            | 21 +++++++-
 7 files changed, 261 insertions(+), 15 deletions(-)
```

## Aggregate working-tree status

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
?? tests/test_zap_completion.py
?? tests/test_zap_full_authorized.py
?? tests/test_zap_history.py
```

HEAD remains `f3fdd199a1ffa9fa3f3b3c370f2ed48967328812`;
branch `work/posture-vnext-20261026`.

API parsing/completion claims were checked against the primary
[ZAP 2.17 implementation](https://github.com/zaproxy/zaproxy/blob/v2.17.0/zap/src/main/java/org/zaproxy/zap/extension/ascan/ActiveScanAPI.java).
See [protocol](TASK1C3_PROTOCOL.md) for prospective settings and primary
serialization/structural-parameter references.
