# Fourth source: ZAP Active safety gate

Policy `zap-active-lab-reviewed-1.0`. **Executing scan support is blocked; this
release integrates a truthful NOT_AVAILABLE fourth stage, not a working active
scanner.** The task explicitly permits zero approved safe rules. Do not enable
the default policy to force a demonstration.

## Audit of the reused integration

`posture.providers.ZapAPI` accepts only an explicit HTTP 127.0.0.1 API port;
the API key comes from the backend environment and is sent in a header, never
snapshot data. Owned ephemeral runtime is mandatory. `ZapPassiveProvider`
creates an unnamed volatile session for each assessment, verifies empty target
history/alerts/queue, and retains saved repository snapshots unchanged.

The five passive no-follow GETs are `/moodle/`, `/moodle/login/index.php`,
`/moodle/my/`, `/moodle/course/`, `/moodle/admin/`. Existing limits stay 20
requests, 60 seconds, 2 MB response, connect 3 seconds, total/read 8 seconds.
Queue polling shares the assessment deadline. `zap_history.review_history`
matches actual target messages to the issued transcript, distinguishes exact
control-plane calls and unsent site-tree ancestors, and rejects unowned history.
Alert normalization exports structural fields and payload digests only.
`model.ZAP_RULES` and `deduplicate` use reviewed control IDs and maximum source
contribution; no fuzzy title merging or summed duplicate penalties.

Native, Passive and repository Active Validation retain their own results;
fourth-stage API/transport failure cannot erase them. Historical stage verdicts
are never loaded to fill current gaps.

## Installed rules and reviewed decision

The loopback daemon reports ZAP **2.17.0**, mode **safe**. Its default policy
enables **53 rules**, with eight threads, zero delay, and zero (unlimited) scan
and rule time limits. Those settings were inspected read-only and not changed.
The explicit per-ID review is `ZAP_ACTIVE_SCANNER_REVIEW.json`, including every
observed rule, safety decision and unknown behavior. Unknown IDs are always
DISABLED_UNREVIEWED; remote plugin descriptions cannot authorize execution.

Application enabled set: **empty**. Forbidden injection/execution, time delays,
stored-content, callback/metadata, fuzzing, scripting and exhaustion rules are
DISABLED_UNSAFE. Unrelated platform checks are DISABLED_NOT_RELEVANT. Other
rules remain DISABLED_UNREVIEWED; unknown request/state effects are explicitly
NOT_VERIFIED rather than asserted safe.

The comparatively simple Directory Browsing rule 0 performs a directory GET
but delegates redirect handling to core code. We have not verified the installed
add-on/core binding, exact resulting send count, anti-CSRF behavior or a
pre-send scope/method/request cap. HTTP Only Site 10106 changes HTTP to HTTPS
and handles redirects, violating this task's exact HTTP origin. No rule was
approved on its name alone.

Primary source review (upstream source is **not** installed binary proof):

- [Directory Browsing implementation](https://github.com/zaproxy/zap-extensions/blob/main/addOns/ascanrules/src/main/java/org/zaproxy/zap/extension/ascanrules/DirectoryBrowsingScanRule.java)
- [HTTP Only Site implementation](https://github.com/zaproxy/zap-extensions/blob/main/addOns/ascanrules/src/main/java/org/zaproxy/zap/extension/ascanrules/HttpOnlySiteScanRule.java)
- [ZAP modes](https://www.zaproxy.org/docs/desktop/start/features/modes/)

Safe mode prohibits active scanning. Protected mode with exact scope would be
the minimum future mode, with explicit owned-runtime lifecycle and restoration;
this task does **not** change global mode, context or scan settings. ATTACK mode
and public/LAN API binding remain prohibited.

## Current candidate selection and budget

Only the **current assessment's** COMPLETE passive transcript with scope PASS
and matching COLLECTED session identity is considered. Retain GET 2xx responses
on the five reviewed paths; reject redirect responses, arbitrary paths, host
changes, credentials, fragments and query-bearing URLs. Normalize port 80 and
deduplicate. No URL history, crawling, forms or guessed parameters. Current
policy has zero eligible query parameters. URL discovery must not invent
parameters merely to make an active rule run.

Planned work = current URLs × approved rule work = **0**. Hard target request
ceiling 0, per-target ceiling 0, scan duration 0, concurrency 0, passive-drain
timeout 0 (no active traffic). Read-only mode/history/inventory checks share an
8-second total control deadline with existing connect/read caps. Only
`ascan/view/scanners` was added to the closed API. There is deliberately no
`ascan/action/scan`, mode weakening or scan dispatch path.

This is a genuine hard zero-send bound, not asynchronous polling presented as
a pre-send hard request cap. Request-ceiling cancellation, executing-scan
timeouts, protected-mode setup/restoration, active-generated passive queue
drain and active-alert collection are **not implemented or accepted**. There is
no owned scan to cancel, and we never stop another process's scan.

## Result and immutable evidence

`ZapActiveStage.run` executes anew after the existing repository validation
stage. It publishes assessment/session ID, target/scope, sanitized current URLs,
parameter count, policy ID, per-rule decision inventory/hash, request plan,
mode, history counts/delta, zero active-send count, no scan ID, alert counts,
reason and explicit NOT_AVAILABLE status. Failure is isolated and sanitized.
`zap_active_status` and `zap_active_summary` are returned by the existing
assessment API, plus `/api/scanners/zap/active-status`. No raw payload, body,
cookie, key or query value is exported. UI separates SUMMARY and TECHNICAL.

Immutable snapshot version `operational-posture-1.2` adds `zap_active.json` to
the exact manifest membership. Old 1.0/1.1 snapshots still verify. No active
rows can enter current canonical computation under this zero-rule policy.
Passive alerts are never relabelled ZAP_ACTIVE. The UI shows the unavailable
stage, not a successful empty scan. All current active alert/mapped/unique
counts are zero.

There are no new active mappings or severity/coefficient changes. A synthetic
test proves that the same reviewed control with Native/Passive/active-source
members still has one canonical contribution; repository validation stays
non-scoring metadata. This is a dedup regression, **not** proof of an executed
four-source live scan. Actual executing normalization and provenance collection
remain blocked, rather than accepting arbitrary unowned alert JSON.

## Next prerequisite, not performed

Bind one suitable installed rule and core implementation to verified artifacts,
review its exact sends/redirects/anti-CSRF behavior, and establish enforceable
pre-send target/method/request/response caps plus clean owned cancellation.
Only then add an explicit small rule policy and protected context adapter.
Do not redesign CQI or relax safety to obtain an alert. No active scan or
vulnerability claim is made by this stage.
