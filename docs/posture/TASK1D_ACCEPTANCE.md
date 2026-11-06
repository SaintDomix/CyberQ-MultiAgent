# Task 1D — Branch 1 profiles finalized operationally

**STANDARD acceptance PASS with explicit coverage limitations.** It is now the
normal default and is not passive-only. FULL_AUTHORIZED remains the separate
comprehensive deep profile; no new deep assessment was run. Overall posture
status remains PARTIAL because existing internal/legacy/patch prerequisites are
unavailable, not because STANDARD's scanner stages failed.

One real production-path assessment: `posture-20261028T174257Z-29abd4e2f0c9`.
Started 2026-10-28 22:42:57 Asia/Qyzylorda; completed 22:44:05.
UTC identifiers/timestamps remain unchanged in source artifacts.

Machine receipt: `runtime/posture_acceptance/task1d_posture-20261028T174257Z-29abd4e2f0c9/acceptance.json`
SHA256: `95db9a47d47c20f80d7a3d817b5f596c30a1f99190541db86b36a116e5883651`

Policy: [zap-standard-1.0](ZAP_STANDARD_POLICY.json)
SHA256: `5abb886aefe12f21b28fcb58898f090e135e2a62d478707a2e8a689611268065`

Snapshot: `runtime/posture/posture-20261028T174257Z-29abd4e2f0c9/artifact_manifest.json`
SHA256: `73e6cd7bdb08a2f46086234551ca25b244c341649b648855ce52e18ddda0e1ca`

## Requested 32-point report

1. **Architecture:** STANDARD (default routine assessment), FULL_AUTHORIZED
   (explicit deep DAST), PASSIVE_BASELINE (restricted). All share current Native,
   target model, ZAP executor, finding adapter, repository validation, canonical
   dedup, frozen CQI and immutable snapshots. No second scanner implementation.
2. **STANDARD:** fresh Native + fresh verified-empty ZAP session + seed and
   bounded Traditional Spider + passive + selected active + passive drain +
   canonicalization + repository Active Validation + snapshot + CQI on read.
   Repository validation retains its accepted post-canonicalization ordering.
3. **Deep preservation:** current installed inventory still derives exactly the
   previous 43 FULL enabled IDs; the ten exclusions and FullBudget match the
   protected deep snapshot. MEDIUM full strength, browser discovery, imports,
   context, cancellation and telemetry remain. Actual Full regression tests are
   synthetic; the real previous deep run remains PARTIAL and byte-identical.
4. **STANDARD policy:** `zap-standard-1.0`, LOW attack strength / MEDIUM threshold.
   These scanner settings do not change CQI severity/confidence coefficients.
5. **Enabled STANDARD IDs/names:** seven, listed with real execution below.
6. **Deep-only policy:** 36 of the 43 Full-enabled rules are deep-only; ten
   original Full exclusions remain separate. All 53 installed IDs, decisions,
   names, rationale, applicability and previous observed costs are in the JSON
   manifest and table below. Heavy is not labelled unsafe. New/unreviewed rules
   are denied in STANDARD; missing rules become NOT_INSTALLED.
7. **Measured rationale:** prior deep DOM XSS 1369.932 s, traversal 762.670 s,
   SQLite timing SQL 410.418 s, reflected XSS 233.321 s, generic SQL 151.935 s.
   Actual previous request counts are retained; unavailable measurements are
   null. Generic SQL and reflected XSS remain; DOM/browser work and exhaustive
   traversal stay deep-only. DB-specific timing rules require established
   applicability and are not selected by guessing the backend. Other selection
   considers security value, broad applicability and Native overlap. This is
   an operational coverage/cost decision, not ML tuning or a new attack benchmark.
8. **Discovery:** STANDARD depth three / ten children per node / 25 s maximum,
   seed plus Traditional Spider and current site tree. Actual Spider COMPLETE,
   16 URLs in 3.052 s;
   32 normalized endpoints, 3 query-name
   occurrences. Client/AJAX explicitly NOT_RUN_STANDARD. FULL retains expanded
   discovery and browser support; no historical URL seeds are inserted.
9. **Real STANDARD ID:** `posture-20261028T174257Z-29abd4e2f0c9`; target
   `http://192.168.226.132/moodle/`; production POST, authorization true.
10. **Total:** 68.424027 s by snapshot timestamps;
    68.397590 s worker processing; publication observed
    within 72.830 s including polling/API latency.
    Both <=300 s preferred and <=480 s hard bound. No cancellation required.
11. **Active duration:** 42.799967 s.
12. **Active count:** 329 scan-owned
    message IDs. Per-rule counts are separate scoped counters; do not substitute
    their sum for the scan's complete message count. Final history: 390.
13. **Native:** COMPLETE, 30 HTTP requests, 79 source rows;
    full calculated request plan remains bounded at 43 / 364 s, with shared
    STANDARD absolute deadline. No historical verdict substitution.
14. **Passive:** COMPLETE; 54 raw observations,
    passive queue drained before and after active. Twenty-one passive-only
    canonical groups plus three Native overlaps; raw observations are not
    independent weaknesses.
15. **Repository Active Validation:** COMPLETE; two eligible, one executed /
    CONFIRMED, one unavailable, 115 N/A. Two actual bounded requests. Its
    score_effect remains NONE; no parent finding is converted to PASS.
16. **STANDARD active:** COMPLETE, 100%, seven enabled and all seven observed
    executing with positive request counts. Three active indications: SQL
    injection (40018, GET course/view.php, id, HIGH/Medium), two directory-browsing
    observations (0, GET admin/tool/ and admin/tool/dataprivacy/, MEDIUM/Medium).
    Project confirmation remains NOT_CONFIRMED. No successful-exploitation claim.
17. **Source-only counts:** Native-only 90 (includes unavailable coverage slots),
    ZAP Passive-only 21, ZAP Active-only three. All three active findings are
    first-class current FAIL rows in the primary API/UI; they need no Native
    counterpart. Total ZAP-only canonical findings: 24.
18. **Multi-source:** three Native + Passive canonical groups; source membership
    and individual evidence retained. No fabricated real four-source example.
19. **Dedup:** 136 provider source rows + 14 additional coverage rows = 150 input
    rows → 117 canonical records; 33 duplicates collapsed. Existing maximum
    eligible member contribution is checked for every scored canonical group.
20. **CQI:** 40.23080444335938 current **partial posture-only projection**;
    94 mapped canonical records including coverage, 23 unmapped. D5/D6 unavailable,
    never PASS. Baseline equal 1/6 weights and all formulas/coefficient policy
    unchanged; existing available-dimension normalization applies. All three
    active indications are UNMAPPED and receive no invented penalty. The higher
    value than the last deep snapshot must not be called remediation: profile
    coverage differs. Same-profile before/after has no previous STANDARD value
    for this first real run. CQI is a quality index, not probability.
21. **Freshness/fix regression:** deterministic integration runs two STANDARD
    assessments through the actual Native HTTP adapter, scanner execution,
    canonicalization and CQI. Changed mocked CSP response FAIL → PASS increases
    CQI; Native sessions/requests, ZAP fresh sessions, Passive, repository
    validation and active dispatch rerun; first snapshot bytes remain unchanged.
    No real Moodle configuration was altered and no second real assessment ran.
22. **FULL remains:** explicit API/UI/CLI choice, same protected configurable
    target, comprehensive 43-rule selection, bounds, browser stages, policy
    exclusions and observation model. The proof is code/fixture/inventory/hash
    comparison, not a newly executed hour-long run. Historical mode is projected
    as assessment_profile on API reads without rewriting snapshot files.
23. **Focused:** 28 new profile cases passed, including default/auth, passive
    alias isolation, deep-policy preservation, unknown/missing scanners,
    non-Moodle targets, deadlines, fresh reruns, immutable history, ZAP-only
    visibility and canonical no-extra-penalty cases. Existing full/completion
    tests remain passing.
24. **Relevant Python regression:** 388 passed (20.46 s final run). No training
    or expensive research/model pipeline was run.
25. **Frontend:** 50 tests passed; production Vite build PASS. STANDARD selected
    by default with recommendation; FULL explicitly selected with time warning;
    passive retained. Browser non-execution is not shown as failure; partial
    findings are not visually erased.
26. **git diff --check:** PASS. Frozen-core diff against
    milestone-3-end-to-end is empty. Task files also checked for whitespace.
27. **Files:** exact modified/new source/test/doc list below. Legacy tests now
    select PASSIVE_BASELINE explicitly when testing old restricted behavior,
    while separate tests enforce the new default. No frozen core files changed.
28. **Free disk:** 2953203712 bytes
    (2.750 GiB); above 500 MB guard.
29. **git diff --stat:** below; tracked stat does not include new untracked files.
30. **git status --short:** below; pre-existing raw data/evidence/output paths
    remain untracked and preserved. No commit, tag, reset, clean or stash.
31. **Behavioral v2:** VERIFIED, expected root
    `59a8c7c5d3d51632d0afe45f8cd2fe50570b7af2943d26bb313888327ea9f436`.
    All 1464 pre-existing protected files and 97 frozen files remain byte-identical.
    Accepted historical Branch1, Full assessments, models, research outputs and
    CQI implementation remain unchanged.
32. **Finalized verdict:** YES for the requested Branch 1 operational-profile
    architecture and STANDARD acceptance, **with coverage limitations**. This is
    not a claim that every control was checked or that deep DAST has completed.
    The overall snapshot is honestly PARTIAL: 20 unreadable internal/config
    observations, six legacy identities without direct fresh emitters (current
    equivalents have separate IDs), one patch/local-baseline prerequisite.
    Verified role/session and authenticated-ZAP coverage remain conditional or
    not validated in the existing inventory. No privileges or server configuration
    were changed. No Branch2, normalization or CQI-redesign task was started.

## STANDARD rules — actual acceptance execution

| ID | Name | Prior deep seconds / requests | STANDARD seconds / requests | Alerts |
|---|---|---|---|---:|
| 0 | Directory Browsing | NOT OBSERVED / NOT OBSERVED | 7.294 / 33 | 2 |
| 20019 | External Redirect | 66.682 / 450 | 4.029 / 12 | 0 |
| 40003 | CRLF Injection | NOT OBSERVED / NOT OBSERVED | 5.994 / 28 | 0 |
| 40012 | Cross Site Scripting (Reflected) | 233.321 / 250 | 5.711 / 20 | 0 |
| 40018 | SQL Injection | 151.935 / 1130 | 6.814 / 34 | 1 |
| 40032 | .htaccess Information Leak | NOT OBSERVED / NOT OBSERVED | 5.111 / 21 | 0 |
| 40034 | .env Information Leak | NOT OBSERVED / NOT OBSERVED | 5.136 / 21 | 0 |

Different profiles, strengths and discovered inputs are not a paired speed
benchmark. Recorded costs justify the operational split, not an equivalent-
coverage acceleration claim. Named-policy DEFAULT strength/threshold in scanner
rows inherits the policy LOW/MEDIUM values.

## Complete scanner decision table

FULL exclusions are distinct from deep-only operational choices. Null previous
measurements are not replaced by invented values. JSON contains applicability
and telemetry source/hash for every row.

| ID | Name | FULL state | STANDARD state | Rationale |
|---|---|---|---|---|
| 0 | Directory Browsing | ENABLED | STANDARD_ENABLED | Directory-listing disclosure: bounded ordinary GET inspection; complements Native and supports other configured targets. |
| 6 | Path Traversal | ENABLED | DEEP_ONLY_RUNTIME | Exhaustive traversal consumed 762.670 seconds/891 requests. Existing bounded native exposure/traversal-relevant validation remains; not equivalent exhaustive coverage. |
| 7 | Remote File Inclusion | DISABLED_POLICY | NOT_APPLICABLE | Not part of either operational policy: Remote inclusion may fetch external payloads outside authorized target. |
| 10045 | Source Code Disclosure - /WEB-INF Folder | ENABLED | DEEP_ONLY_TECHNOLOGY_SPECIFIC | Requires separately established technology/protocol applicability or DB-specific timing work; no DB/backend guess. Generic SQLi and generic web/exposure checks remain in STANDARD. |
| 10047 | HTTPS Content Available via HTTP | DISABLED_POLICY | NOT_APPLICABLE | Not part of either operational policy: Changes HTTPS to HTTP; a second origin is not authorized by this profile. |
| 10048 | Remote Code Execution - Shell Shock | ENABLED | DEEP_ONLY_RUNTIME | Specialized, overlapping or unmeasured exhaustive work is reserved for deep assessment; bounded STANDARD prioritizes generic SQLi/XSS/header/redirect/disclosure checks. |
| 10058 | GET for POST | ENABLED | DEEP_ONLY_RUNTIME | Specialized, overlapping or unmeasured exhaustive work is reserved for deep assessment; bounded STANDARD prioritizes generic SQLi/XSS/header/redirect/disclosure checks. |
| 10104 | User Agent Fuzzer | ENABLED | DEEP_ONLY_RUNTIME | Specialized, overlapping or unmeasured exhaustive work is reserved for deep assessment; bounded STANDARD prioritizes generic SQLi/XSS/header/redirect/disclosure checks. |
| 10106 | HTTP Only Site | DISABLED_POLICY | NOT_APPLICABLE | Not part of either operational policy: Changes the configured HTTP origin to HTTPS; a second origin is not authorized by this profile. |
| 20015 | Heartbleed OpenSSL Vulnerability | ENABLED | DEEP_ONLY_TECHNOLOGY_SPECIFIC | Requires separately established technology/protocol applicability or DB-specific timing work; no DB/backend guess. Generic SQLi and generic web/exposure checks remain in STANDARD. |
| 20017 | Source Code Disclosure - CVE-2012-1823 | ENABLED | DEEP_ONLY_TECHNOLOGY_SPECIFIC | Requires separately established technology/protocol applicability or DB-specific timing work; no DB/backend guess. Generic SQLi and generic web/exposure checks remain in STANDARD. |
| 20018 | Remote Code Execution - CVE-2012-1823 | ENABLED | DEEP_ONLY_TECHNOLOGY_SPECIFIC | Requires separately established technology/protocol applicability or DB-specific timing work; no DB/backend guess. Generic SQLi and generic web/exposure checks remain in STANDARD. |
| 20019 | External Redirect | ENABLED | STANDARD_ENABLED | Open-redirect response behavior; generic input risk without assuming a database. |
| 30001 | Buffer Overflow | DISABLED_POLICY | NOT_APPLICABLE | Not part of either operational policy: Resource-exhaustion/buffer-overflow test; uncontrolled stress is prohibited. |
| 30002 | Format String Error | ENABLED | DEEP_ONLY_RUNTIME | Specialized, overlapping or unmeasured exhaustive work is reserved for deep assessment; bounded STANDARD prioritizes generic SQLi/XSS/header/redirect/disclosure checks. |
| 40003 | CRLF Injection | ENABLED | STANDARD_ENABLED | HTTP response/header injection indication; generic injection family. |
| 40008 | Parameter Tampering | ENABLED | DEEP_ONLY_RUNTIME | Specialized, overlapping or unmeasured exhaustive work is reserved for deep assessment; bounded STANDARD prioritizes generic SQLi/XSS/header/redirect/disclosure checks. |
| 40009 | Server Side Include | ENABLED | DEEP_ONLY_RUNTIME | Specialized, overlapping or unmeasured exhaustive work is reserved for deep assessment; bounded STANDARD prioritizes generic SQLi/XSS/header/redirect/disclosure checks. |
| 40012 | Cross Site Scripting (Reflected) | ENABLED | STANDARD_ENABLED | Reflected-XSS indication remains in routine coverage; LOW strength, no DOM/browser rule, no browser-discovered POST fan-out. |
| 40014 | Cross Site Scripting (Persistent) | ENABLED | DEEP_ONLY_RUNTIME | Specialized multi-stage persistent-XSS/priming/spider workflow is deep-only; routine STANDARD does not seek stored-content creation. Generic reflected XSS remains enabled. This is not an unsafe-rule label. |
| 40016 | Cross Site Scripting (Persistent) - Prime | ENABLED | DEEP_ONLY_RUNTIME | Specialized multi-stage persistent-XSS/priming/spider workflow is deep-only; routine STANDARD does not seek stored-content creation. Generic reflected XSS remains enabled. This is not an unsafe-rule label. |
| 40017 | Cross Site Scripting (Persistent) - Spider | ENABLED | DEEP_ONLY_RUNTIME | Specialized multi-stage persistent-XSS/priming/spider workflow is deep-only; routine STANDARD does not seek stored-content creation. Generic reflected XSS remains enabled. This is not an unsafe-rule label. |
| 40018 | SQL Injection | ENABLED | STANDARD_ENABLED | Generic SQL injection indication is retained; database backend is NOT inferred. |
| 40019 | SQL Injection - MySQL (Time Based) | ENABLED | DEEP_ONLY_TECHNOLOGY_SPECIFIC | Requires separately established technology/protocol applicability or DB-specific timing work; no DB/backend guess. Generic SQLi and generic web/exposure checks remain in STANDARD. |
| 40020 | SQL Injection - Hypersonic SQL (Time Based) | ENABLED | DEEP_ONLY_TECHNOLOGY_SPECIFIC | Requires separately established technology/protocol applicability or DB-specific timing work; no DB/backend guess. Generic SQLi and generic web/exposure checks remain in STANDARD. |
| 40021 | SQL Injection - Oracle (Time Based) | ENABLED | DEEP_ONLY_TECHNOLOGY_SPECIFIC | Requires separately established technology/protocol applicability or DB-specific timing work; no DB/backend guess. Generic SQLi and generic web/exposure checks remain in STANDARD. |
| 40022 | SQL Injection - PostgreSQL (Time Based) | ENABLED | DEEP_ONLY_TECHNOLOGY_SPECIFIC | Requires separately established technology/protocol applicability or DB-specific timing work; no DB/backend guess. Generic SQLi and generic web/exposure checks remain in STANDARD. |
| 40024 | SQL Injection - SQLite (Time Based) | ENABLED | DEEP_ONLY_TECHNOLOGY_SPECIFIC | Requires separately established technology/protocol applicability or DB-specific timing work; no DB/backend guess. Generic SQLi and generic web/exposure checks remain in STANDARD. |
| 40026 | Cross Site Scripting (DOM Based) | ENABLED | DEEP_ONLY_BROWSER | Browser-intensive DOM-XSS consumed 1369.932 seconds and remained at 77%; preserved unchanged in FULL_AUTHORIZED. |
| 40027 | SQL Injection - MsSQL (Time Based) | ENABLED | DEEP_ONLY_TECHNOLOGY_SPECIFIC | Requires separately established technology/protocol applicability or DB-specific timing work; no DB/backend guess. Generic SQLi and generic web/exposure checks remain in STANDARD. |
| 40028 | ELMAH Information Leak | ENABLED | DEEP_ONLY_TECHNOLOGY_SPECIFIC | Requires separately established technology/protocol applicability or DB-specific timing work; no DB/backend guess. Generic SQLi and generic web/exposure checks remain in STANDARD. |
| 40029 | Trace.axd Information Leak | ENABLED | DEEP_ONLY_TECHNOLOGY_SPECIFIC | Requires separately established technology/protocol applicability or DB-specific timing work; no DB/backend guess. Generic SQLi and generic web/exposure checks remain in STANDARD. |
| 40032 | .htaccess Information Leak | ENABLED | STANDARD_ENABLED | Read-only .htaccess disclosure check, complementary web-server configuration exposure. |
| 40034 | .env Information Leak | ENABLED | STANDARD_ENABLED | Read-only environment-file disclosure check; evidence values are withheld. |
| 40035 | Hidden File Finder | ENABLED | DEEP_ONLY_RUNTIME | Specialized, overlapping or unmeasured exhaustive work is reserved for deep assessment; bounded STANDARD prioritizes generic SQLi/XSS/header/redirect/disclosure checks. |
| 40042 | Spring Actuator Information Leak | ENABLED | DEEP_ONLY_TECHNOLOGY_SPECIFIC | Requires separately established technology/protocol applicability or DB-specific timing work; no DB/backend guess. Generic SQLi and generic web/exposure checks remain in STANDARD. |
| 40043 | Log4Shell | DISABLED_POLICY | NOT_APPLICABLE | Not part of either operational policy: Log4Shell callback/OAST outside the authorized application is not configured. |
| 40044 | Exponential Entity Expansion (Billion Laughs Attack) | DISABLED_POLICY | NOT_APPLICABLE | Not part of either operational policy: Billion Laughs deliberate resource exhaustion is prohibited. |
| 40045 | Spring4Shell | DISABLED_POLICY | NOT_APPLICABLE | Not part of either operational policy: Spring4Shell file-write/webshell probe is not a non-destructive vulnerability test. |
| 40048 | Remote Code Execution (React2Shell) | ENABLED | DEEP_ONLY_TECHNOLOGY_SPECIFIC | Requires separately established technology/protocol applicability or DB-specific timing work; no DB/backend guess. Generic SQLi and generic web/exposure checks remain in STANDARD. |
| 50000 | Script Active Scan Rules | DISABLED_POLICY | NOT_APPLICABLE | Not part of either operational policy: No operator-reviewed custom active scripts are configured. |
| 90017 | XSLT Injection | ENABLED | DEEP_ONLY_TECHNOLOGY_SPECIFIC | Requires separately established technology/protocol applicability or DB-specific timing work; no DB/backend guess. Generic SQLi and generic web/exposure checks remain in STANDARD. |
| 90019 | Server Side Code Injection | ENABLED | DEEP_ONLY_TECHNOLOGY_SPECIFIC | Requires separately established technology/protocol applicability or DB-specific timing work; no DB/backend guess. Generic SQLi and generic web/exposure checks remain in STANDARD. |
| 90020 | Remote OS Command Injection | ENABLED | DEEP_ONLY_TECHNOLOGY_SPECIFIC | Requires separately established technology/protocol applicability or DB-specific timing work; no DB/backend guess. Generic SQLi and generic web/exposure checks remain in STANDARD. |
| 90021 | XPath Injection | ENABLED | DEEP_ONLY_TECHNOLOGY_SPECIFIC | Requires separately established technology/protocol applicability or DB-specific timing work; no DB/backend guess. Generic SQLi and generic web/exposure checks remain in STANDARD. |
| 90023 | XML External Entity Attack | DISABLED_POLICY | NOT_APPLICABLE | Not part of either operational policy: External entity file/callback behavior lacks an authorized external target. |
| 90024 | Generic Padding Oracle | ENABLED | DEEP_ONLY_TECHNOLOGY_SPECIFIC | Requires separately established technology/protocol applicability or DB-specific timing work; no DB/backend guess. Generic SQLi and generic web/exposure checks remain in STANDARD. |
| 90026 | SOAP Action Spoofing | ENABLED | DEEP_ONLY_TECHNOLOGY_SPECIFIC | Requires separately established technology/protocol applicability or DB-specific timing work; no DB/backend guess. Generic SQLi and generic web/exposure checks remain in STANDARD. |
| 90029 | SOAP XML Injection | ENABLED | DEEP_ONLY_TECHNOLOGY_SPECIFIC | Requires separately established technology/protocol applicability or DB-specific timing work; no DB/backend guess. Generic SQLi and generic web/exposure checks remain in STANDARD. |
| 90034 | Cloud Metadata Potentially Exposed | DISABLED_POLICY | NOT_APPLICABLE | Not part of either operational policy: Cloud metadata access is outside the authorized application. |
| 90035 | Server Side Template Injection | ENABLED | DEEP_ONLY_TECHNOLOGY_SPECIFIC | Requires separately established technology/protocol applicability or DB-specific timing work; no DB/backend guess. Generic SQLi and generic web/exposure checks remain in STANDARD. |
| 90036 | Server Side Template Injection (Blind) | ENABLED | DEEP_ONLY_TECHNOLOGY_SPECIFIC | Requires separately established technology/protocol applicability or DB-specific timing work; no DB/backend guess. Generic SQLi and generic web/exposure checks remain in STANDARD. |
| 90037 | Remote OS Command Injection (Time Based) | ENABLED | DEEP_ONLY_TECHNOLOGY_SPECIFIC | Requires separately established technology/protocol applicability or DB-specific timing work; no DB/backend guess. Generic SQLi and generic web/exposure checks remain in STANDARD. |

## Current dimension projection

| Dimension | Quality |
|---|---:|
| D1 | 5.495452880859375 |
| D2 | 91.44140625000001 |
| D3 | 16.486358642578125 |
| D4 | 47.50000000000001 |
| D5 | NOT AVAILABLE |
| D6 | NOT AVAILABLE |

## Modified source/test/document files

- `demo/backend/posture_api.py`
- `demo/backend/schemas.py`
- `demo/frontend/scripts/product_render.test.mjs`
- `demo/frontend/src/components/OperationalPosture.jsx`
- `scripts/run_posture.py`
- `src/posture/active.py`
- `src/posture/native.py`
- `src/posture/orchestration.py`
- `src/posture/target.py`
- `src/posture/zap_full.py`
- `src/posture/zap_full_api.py`
- `tests/test_current_active.py`
- `tests/test_fresh_posture.py`
- `tests/test_operational_posture.py`
- `tests/test_posture_demo_patch.py`
- `tests/test_zap_active_gate.py`

## New source/test/document files

- `src/posture/zap_standard.py`
- `tests/test_posture_profiles.py`
- `docs/posture/ASSESSMENT_PROFILES.md`
- `docs/posture/ZAP_STANDARD_POLICY.json`
- `docs/posture/TASK1D_ACCEPTANCE.md`

New runtime artifacts only: `runtime/posture/posture-20261028T174257Z-29abd4e2f0c9/` and `runtime/posture_acceptance/task1d_posture-20261028T174257Z-29abd4e2f0c9/`.
No full ZAP database, response-body archive, browser download, model copy or new
research dataset was created by the assessment. Existing test fixtures use
isolated temporary directories. Final model/API health VERIFIED; runtime remains
LIVE_LAB. API accepts explicit STANDARD; the normal default is independently
verified through schema, API metadata and UI tests. The legacy passive URL
cannot silently inherit an active default.

## Same-profile comparison and limitations

Routine and deep assessments intentionally have different coverage. Absent
unexecuted deep findings do not establish remediation. The current before/after
view compares same target/profile only. The mapped-CSP fix test demonstrates
actual evidence change under one fixed profile, not a favorable coverage switch.
The 27 current unavailable canonical rows are not vulnerabilities or PASS results.
The current three ZAP_ACTIVE indications are retained for review and remain
unconfirmed; CQI UNMAPPED is a scoring-coverage fact, not absence of a finding.

## Aggregate tracked diff stat

```text
 demo/backend/posture_api.py                        | 38 +++++++-----
 demo/backend/schemas.py                            | 11 +++-
 demo/frontend/scripts/product_render.test.mjs      | 10 ++++
 .../frontend/src/components/OperationalPosture.jsx | 23 ++++----
 scripts/run_posture.py                             |  2 +-
 src/posture/active.py                              | 17 +++++-
 src/posture/native.py                              |  5 +-
 src/posture/orchestration.py                       | 55 +++++++++++++-----
 src/posture/target.py                              |  3 +-
 src/posture/zap_full.py                            | 67 ++++++++++++++++------
 src/posture/zap_full_api.py                        |  2 +-
 tests/test_current_active.py                       |  8 +--
 tests/test_fresh_posture.py                        | 20 +++----
 tests/test_operational_posture.py                  | 14 ++---
 tests/test_posture_demo_patch.py                   | 10 ++--
 tests/test_zap_active_gate.py                      | 10 ++--
 16 files changed, 196 insertions(+), 99 deletions(-)
```

## Complete git status

```text
 M demo/backend/posture_api.py
 M demo/backend/schemas.py
 M demo/frontend/scripts/product_render.test.mjs
 M demo/frontend/src/components/OperationalPosture.jsx
 M scripts/run_posture.py
 M src/posture/active.py
 M src/posture/native.py
 M src/posture/orchestration.py
 M src/posture/target.py
 M src/posture/zap_full.py
 M src/posture/zap_full_api.py
 M tests/test_current_active.py
 M tests/test_fresh_posture.py
 M tests/test_operational_posture.py
 M tests/test_posture_demo_patch.py
 M tests/test_zap_active_gate.py
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
?? docs/posture/ASSESSMENT_PROFILES.md
?? docs/posture/TASK1D_ACCEPTANCE.md
?? docs/posture/ZAP_STANDARD_POLICY.json
?? evidence/branch2_captures/
?? outputs/branch2/live/
?? outputs/branch2/m5/
?? outputs/fusion/
?? src/posture/zap_standard.py
?? tests/test_posture_profiles.py
```

HEAD before/after: `457db7b197b4d7ac5c6b4eb3495bf1d2b6576182`.
Branch: `work/posture-vnext-20261026`.
No source has been staged or committed by this task.

See [profile protocol](ASSESSMENT_PROFILES.md) for architecture, budget derivation,
exact CLI and interpretation. The running dashboard is at
`http://127.0.0.1:8000`; reload its page to load the new STANDARD-default assets.
