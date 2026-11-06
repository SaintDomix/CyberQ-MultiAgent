# Task 1C.3: observable full-scan completion

The earlier `posture-20261027T174158Z-e94492f28474` snapshot remains immutable.
Its 600-second, 19% cutoff and zero active alerts do not establish absence of
active vulnerabilities. This task adds observability without changing its
scanner policy, alert mappings, canonical grouping, CQI or Behavioral v2.

## Diagnosis before changing limits

The owned daemon retained counters for exactly one active scan. Nine rules had
started; three were marked skipped. The largest recorded rule times were SSI
40009 (181565 ms), Path Traversal 6 (128231 ms), External Redirect 20019
(120164 ms), and Remote Code Execution / CVE-2012-1823 20018 (62995 ms).
These counters supplement the historical receipt; times are not necessarily
additive and URL/work counters are not HTTP message counts. Two threads,
4 requests/second, a 250 ms delay and independent two-minute rule limits
restricted the old run. The relative contribution of delay, retries and server
latency cannot be causally separated from these observations.

Four ordinary sequential GETs had median 0.063887 s. Eight ordinary GETs at
concurrency four all returned HTTP 200, median 0.190311 s, elapsed 0.397614 s.
This small probe supports conservative bounded parallelism; it does not prove
stability under every active rule. See the hashed diagnostic in
`runtime/posture_acceptance/task1c3_diagnostic/`.

The old 878 normalized passive instances contain 229 distinct
plugin/route/parameter/method identities and 87 existing weakness keys, collapsing
791 repeated members. Timestamp disclosure 10096 accounts for 605 instances.
Existing canonical grouping merges four keys with Native, leaving 83 ZAP-only
findings. All instance provenance remains. This is traffic-level repetition,
not 878 independent weaknesses.

Rule 90022 has three passive instances on `/moodle/admin/tool/`,
`/moodle/admin/tool/dataprivacy/` and `/moodle/lib/ajax/`, one existing application
error weakness. Its MEDIUM/Medium support produces one existing Information
Disclosure contribution of 0.175. No exploit-success claim or new mapping is
introduced. Its payload is retained only as a digest/size in normalized evidence.

## Prospective execution settings

The 43 enabled/53 installed rule policy and ten reviewed exclusions are unchanged.
The active deadline is `ceil(600 / 0.19 * 1.15 / 60) * 60 = 3660 s`.
This progress-based estimate is not a calibrated linear ETA. No assumed gain
from concurrency is used to shorten it. Four threads, host cap 8 requests/s,
100 ms delay; scanner request timeout remains 20 s. The independent rule cap is
zero (no per-rule cutoff); every rule remains bounded by the active deadline.
ZAP's native fallback is 62 minutes, after the application deadline.

The default overall limit is 4380 s: active 3660 + Spider 120 + Client 90 +
AJAX 90 + Passive 120 + metadata 180 + control/cleanup allowance 120.
Absolute configurable ceilings are active 5400 s, overall 7200 s, four threads,
8 requests/s. No bounds expand during execution. Disk below 500 MB interrupts.
Only one new production-path assessment is authorized for this task.

## Authoritative progress and ownership

The installed 2.17 API serializes plugin progress as positional seven-element
lists, sometimes nested JSON strings: name, id, quality, status, milliseconds,
request count, alert count. Both that format and named fields are supported.
Live samples are captured every ten seconds and at completion/cutoff. Current
scan request/alert counts and individual rule statuses are retained. Numeric
daemon counters are baseline-differenced because newSession does not necessarily
reset statistics. Enabled does not mean executed; absent observations remain
NOT_OBSERVED. Work counters never masquerade as request counts.

Active COMPLETE requires the owned `ascan.scans` entry to be FINISHED at 100%,
as well as the status endpoint. The status endpoint alone returns 100 even for
stopped scans. A cutoff remains PARTIAL with actual scan progress.
An owned Client/AJAX job interrupted after startup is PARTIAL; NOT_AVAILABLE
means no owned handle was obtained. Stop uses an independent bounded control
deadline. Late completion cannot mutate an already returned/saved snapshot.

## Compact metadata and evidence

All-history response-body download is no longer the default export. The current
Sites Tree exposes body-free method, URI identity and message ID; discovery APIs
provide any status/method fields they actually expose. Seed form metadata is
parsed from the response already obtained, values discarded. Missing all-history
status/form coverage is explicit. Export failure preserves completed stages and
alerts, marks metadata partial, and never substitutes historical metadata.

ZAP already groups query-value variants in its Sites Tree. One owned context
scan is dispatched, not repeated per-URL scans. The diagnostic endpoint index
also collapses equivalent values while retaining paths and parameter names;
tree metadata separately preserves methods. No endpoint family is excluded to
force completion. Active alert provenance uses the owned scan's alert IDs;
other current-session alerts remain passive. Fresh verified-empty sessions
prevent earlier alerts becoming current.

Primary implementation references:
[ZAP 2.17 active API](https://github.com/zaproxy/zaproxy/blob/v2.17.0/zap/src/main/java/org/zaproxy/zap/extension/ascan/ActiveScanAPI.java),
[API list serialization](https://github.com/zaproxy/zaproxy/blob/v2.17.0/zap/src/main/java/org/zaproxy/zap/extension/api/ApiResponseList.java),
[structural parameters](https://www.zaproxy.org/docs/desktop/start/features/structparams/).
