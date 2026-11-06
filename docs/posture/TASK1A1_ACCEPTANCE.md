# TASK 1A.1 — real two-run acceptance

Verdict: **TASK 1A ACCEPTED**. Branch `work/posture-vnext-20261026`, HEAD
`f3fdd199a1ffa9fa3f3b3c370f2ed48967328812`; changes remain uncommitted.

Authoritative receipt directory:
`runtime/posture_acceptance/task1a1_20261026T084316Z/`.
It contains `preliminary_pair.json`, `final_pair.json`, `integrity.json` and
`hashes.json`. The last excludes itself from its file hashes.

## Complete plan and bounded execution

See `native_plan.py` and `DYNAMIC_POSTURE_ASSESSMENT.md` for the exact URL/method
list and source-backed redirect analysis. There are 24 plain GET requests plus
four method/header variants: 28 planned unique requests. Plain GETs can also
reach three reviewed redirect destinations; each other method/header variant
has at most three redirect hops. Hard ceiling: (24+3)+4*(1+3)=43 requests.
Native deadline: 43*8 + collector 15 + bookkeeping 5 = 364 seconds.
Per-request connect/request controls remain 3/8 seconds; response caps are
unchanged. ZAP remains separately bounded to 20 requests / 60 seconds and uses
five no-follow GETs. No active validator or active scanner ran.

Completed responses, including redirect hops, are shared only within one new
anonymous assessment, keyed by method, URL and explicit headers. The header
matrix, Moodle checks and generic controls consume these same responses.
Configuration, filesystem, version/advisory and plugin rules require no HTTP
requests; role comparison itself consumes supplied role evidence, not HTTP.

## Preserved preliminary attempts

The first real pair was retained without any snapshot modification:

- `posture-20261026T082910Z-bbb3adf5f621`
- `posture-20261026T082921Z-469583c7dd4b`

Both ZAP collections completed with fresh sessions. Native's Moodle module
failed closed because the installed Moodle admin page redirected to the fixed
`admin/index.php?cache=1` transition. This was a scope-policy failure, not a
budget failure. It was not reported as successful full Native acceptance.

The installed `/var/www/html/moodle/admin/index.php:800` emits that exact
transition; line 804 requires login. The corrected Native wrapper permits only
this fixed query alongside the previously reviewed installer `lang=en` route.
It still denies cache=0, session/upgrade keys, arbitrary query combinations and
off-origin destinations. No existing Branch1 check implementation was modified.
The final plan version is `branch1-native-safe-plan-1.1`.

## Final consecutive production API runs

The operator restored the existing ZAP/tunnel. A real curl returned ZAP 2.17.0.
The verified owned demo backend was restarted using its normal stop/start
scripts with the supplied environment; no unrelated process was stopped. The
same production `POST /api/posture/assessments` used by the dashboard initiated
both assessments in LIVE_LAB mode. These are real, unmocked collections.

| Metric | A | B |
|---|---|---|
| Assessment ID | posture-20261026T084316Z-368a303e0a36 | posture-20261026T084323Z-f3b8e7b78dfb |
| Native / ZAP | COMPLETE / COMPLETE | COMPLETE / COMPLETE |
| Overall coverage status | PARTIAL | PARTIAL |
| Known inventory entries | 107 | 107 |
| Implemented Native/advisory controls | 87 | 87 |
| Currently evaluated, including applicability | 66 | 66 |
| Native source checks rerun | 61 | 61 |
| PASS / FAIL / PARTIAL | 29 / 17 / 12 | 29 / 17 / 12 |
| DISMISSED | 0 | 0 |
| NOT_AVAILABLE / NOT_APPLICABLE | 41 / 8 | 41 / 8 |
| Safe external controls NOT_AVAILABLE | 0 | 0 |
| Native HTTP requests / ceiling | 30 / 43 | 30 / 43 |
| Completed-response cache hits | 31 | 31 |
| ZAP target requests / ceiling | 5 / 20 | 5 / 20 |
| Fresh ZAP alerts | 28 | 29 |
| Mapped / unmapped alerts | 12 / 16 | 12 / 17 |
| Canonical findings | 110 | 111 |
| Deduplicated / multi-source | 11 / 3 | 11 / 3 |
| Posture-only partial CQI | 40.23080444335938 | 40.23080444335938 |

Counts above describe the known control inventory. Canonical rows additionally
retain fresh ZAP-only/unmapped observations; they are not the same denominator.
The 66 evaluated entries include eight explicit NOT_APPLICABLE decisions.
The partial posture-only CQI has no behavioral D6 input and is not a full live
system CQI. Identical scores do not imply cached collection: no Moodle weakness
was changed for this acceptance. Increased coverage versus preliminary runs is
not proof of a change in the underlying platform security.

## Real remaining prerequisites

Both runs have exactly these NOT_AVAILABLE groups:

| Entries | Reason |
|---|---|
| 20 internal/configuration/plugin controls | MOODLE_CONFIG_NOT_READABLE_BY_DEMO_UID; UID equivalence still required for web-server filesystem assertions |
| 1 patch control | PATCH-001 lacks an explicit compatible patch baseline |
| 6 role templates | Fresh verified role sessions and content/capability markers are not configured |
| 8 existing validator families | Deliberately disabled for this task; existing explicit context/session/budget gates remain |
| 6 legacy identities | No direct fresh emitter under those legacy IDs; historical verdicts are not substituted |

Every individual ID/reason is retained in `final_pair.json` and each immutable
snapshot's `check_coverage`. No check was skipped solely for request/time budget.
HTTP_ERROR transcript markers are expected 404/405 probe outcomes, not hidden
transport failures or reasons to drop controls.

## Session isolation and preservation

Both final ZAP lifecycles are COLLECTED, with 11 prior history messages, zero
target history after new-session creation, five freshly generated target
messages, a completed passive queue and scope-integrity PASS. The final history
contains five real target messages and six unsent internal site-tree ancestors;
there are no unexpected messages. B remains AVAILABLE/READY after completion,
not FRESH_SESSION_REQUIRED.

Session creation must return OK and pass the empty-history/empty-alert checks
before any proxy request. Each exported member belongs to its own assessment
ID. Alert IDs/content can repeat across unnamed sessions; their difference is
not used as a freshness proof. A's five snapshot files and both preliminary
snapshots were independently hash-verified unchanged after B. No retained row
was inserted into B's canonical results.

All 1,375 pre-existing protected files under data/evidence/outputs/runtime-posture
were byte-identical after acceptance. Frozen Branch1/Branch2/Fusion/reporting
diff from `milestone-3-end-to-end` is empty. Accepted Behavioral v2 verifies at
`59a8c7c5d3d51632d0afe45f8cd2fe50570b7af2943d26bb313888327ea9f436`.

133 focused Python tests passed; `git diff --check` passed. No full-suite run,
large build, model training, CQI policy change, new active validation, ZAP Active
Scan, commit or tag was performed. API keys were supplied only through the
runtime environment, not written into the new source/configuration/receipts.
