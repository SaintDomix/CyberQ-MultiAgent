# TASK 1B — current safe active evidence

The operational layer reuses `branch1.active.Registry`, `run_active`, all eight
accepted validators, `RuntimeContext` and the existing read-only `Executor`.
`src/posture/active.py` is an adapter/scope guard, not a second scanner or a new
validator implementation. Frozen Branch1, Behavioral v2 and Fusion/CQI source
and accepted artifacts are unchanged.

## Existing framework audit

| Existing implementation | Finding/indication | Prerequisites | GET requests | Existing safe behavior / evidence | Laboratory use |
|---|---|---|---:|---|---|
| `validators.py:SensitivePath` | Supported exposure profiles: server-status, phpinfo, Git HEAD, environment file, directory index | Explicit reviewed path and recognizable profile; current FAIL/PARTIAL | 2 | Candidate path + inert nonexistent control; content signature and body difference. CONFIRMED means readable exposure only. Bodies/secrets are never exported. | Enabled for matching reviewed Native exposure IDs; other profiles need a reviewed context |
| `validators.py:OpenRedirect` | Open redirect indication | Anonymous read-only endpoint and explicit redirect parameter | 2 | Baseline + reserved `.invalid` destination parameter; inspect Location without following. Confirms controlled redirect behavior only. | Conditional; absent mapping => unavailable |
| `advanced.py:SQLInjection` | SQL injection / SQLi indication | Read-only URL, parameter, short benign baseline string | 4 | Baseline/one quote/baseline/quote; stable database-specific error differential. No UNION, stacking, delay, writes, metadata extraction or bypass. Existing support is LIKELY, not confirmed SQLi/exploitation. | Conditional; no current SQLi finding is manufactured |
| `advanced.py:UnsafeReflection` | XSS / unsafe reflection indication | Explicit read-only URL/parameter | 3 | Baseline and repeated inert delimiters; classify encoding/context. No script execution or stored content. Unsafe context remains LIKELY; raw reflection CONTEXTUAL. | Conditional; no current XSS finding is manufactured |
| `advanced.py:AccountEnumeration` | Enumeration / account recovery indication | Two authorized test identifiers, read-only URL/parameter, lookup_only=true | 4 | A/B/A/B lookups; normalized repeated differences. No passwords, recovery email or state change. | Conditional; identifiers stay in ephemeral runtime configuration |
| `advanced.py:AccessControl` | Access-control indication | Distinct authorized sessions/roles, identity markers, privileged content markers, expected-denied policy and read-only endpoint | 4 | Restricted/privileged comparisons repeated. HTTP 200/link differences alone never confirm unauthorized capability. Existing LIKELY result retained. | Conditional; adapter also requires roles_verified=true; no login/brute force |
| `advanced.py:SessionControl` | Explicit session behavior/lifecycle indication | Reviewed read-only session context and cookie name; identity marker if authenticated; already-invalidated test session if used | 2 or 4 | Repeated effective attributes and optional already-invalidated-session observations; no logout/invalidation/rotation action is performed. | Conditional; authenticated references additionally require session_verified=true. Direct cookie controls are N/A |
| `advanced.py:SSRFContext` | SSRF context indication | Explicit feature-enabled, fetch-available and feature-evidence context | 0 | Prerequisite-only assessment; CONTEXTUAL, never SSRF confirmation | Request-free only. No callbacks, internal/cloud discovery or fetch test |

Implementation paths above are under `src/branch1/active/`. The existing
planner's missing-context, false-positive, session-role and request-safety gates
remain in force. A generic Authentication & Session category is insufficient to
select a session-behavior check. Explicit source assertion or reviewed mapping
is required; no relevance is invented from co-occurrence.

## Applicability and current evidence

Only current FAIL/PARTIAL indications are potential targets. PASS, dismissed,
missing, unmapped and version-only findings are not reactivated. TLS/headers,
cookie attributes, version/advisories, patch, filesystem, plugin and direct
configuration controls are N/A: their direct evidence is retained without an
"exploit test". No inherited historical verdict, session or active result is
used. The server-only existing `B1_ACTIVE_CONTEXT` environment contract supplies
reviewed mappings and cookie environment-variable references; the frontend
cannot supply URLs, paths, credentials or validator arguments.

Each Run Security Posture now performs fresh Native -> fresh ZAP Passive ->
existing canonical dedup -> selected existing active protocols -> immutable
snapshot. Native no longer performs a separate optional active execution before
ZAP; its provenance says DEFERRED. The independent post-passive stage runs on
every new assessment even if the legacy optional-active environment flag is 0.
This is explicitly authorized safe validation, not ZAP Active Scan.

## Result states and scientific language

`active_validation` contains validator ID, status, current assessment/finding/
parent evidence IDs, timestamp, prerequisite/execution state, request attempts,
sanitized path, baseline/probe observations, reason, source outcome/result/
confirmation, ordinal support, safety classification, score_effect=NONE,
causal=false and successful_exploitation_confirmed=false. `results` retains all
corresponding validator results. `validation_sources` adds ACTIVE_VALIDATION for
executed/context-assessed results without changing passive source membership.

- CONFIRMED: existing validator confirmed a relevant bounded weakness observation
  (for example distinct readable server-status content), never exploitation.
- NOT_CONFIRMED: bounded check did not obtain sufficient corroboration. It is
  **not false positive, not PASS**, and does not remove the parent finding.
  Existing LIKELY/CONTEXTUAL support is preserved in `support_level` rather than
  silently promoted to confirmed vulnerability/exploitation.
- NOT_APPLICABLE: no appropriate protocol for this current control/assertion.
- NOT_AVAILABLE: missing real context/session/role prerequisite, failed
  transport or denied request. Reason is explicit; no old result substitutes.
- NOT_RUN: complete protocol excluded by the global bound, parent unchanged.

## Derived bounds and scope

Existing protocol maxima are 2+2+4+3+4+4+4+0 = **23 request attempts**. This is the
global hard ceiling, lower than the old framework's maximum supported 40. The
actual assessment budget is the sum of complete eligible protocols admitted
within 23, ordered deterministically by source severity, finding ID and validator.
No partial protocol is admitted merely to fill remaining slots. Skipped complete
protocols are NOT_RUN with a budget reason. Every request must match an exact
in-memory approved RequestSpec fingerprint and pass the existing policy.

The original timeout is 5 seconds, rate 0.25 requests/second and response cap
65,536 bytes. For N planned attempts the additional stage deadline is
N*5 + max(0,N-1)/0.25 seconds: maximum 203 seconds, or 14 seconds for two requests.
Failed attempts consume budget. Transport timeouts are socket bounds; streaming
and stage checks reject late responses and stop further requests rather than
claiming hard real-time process cancellation. Zero-request contextual checks
have an effective network budget of zero; the adapter permits no request even
though the old executor dataclass internally requires a minimum budget of one.

Network scope is exactly HTTP `192.168.226.132:80`, `/moodle/`, plus the four
existing reviewed Native exposure paths and their existing inert control paths.
Encoded/traversal/state-changing endpoints, credential-bearing query contexts,
POST/other methods and off-lab destinations are denied. Redirects are never
followed. The reserved redirect test value is only a query parameter, not a
contacted external service. SSRF runs no HTTP requests at all.

Native's complete 43-request/364-second plan and ZAP's independent 20/60 passive
profile are unchanged. Active failure cannot prevent either provider completing.

## Privacy, CQI and persistence

No request/response body, cookie, identity marker, session reference, credential
or query value is exported. Evidence retains statuses, lengths, SHA256, sanitized
paths, safe redirect classification and existing outcome/support. Request plan
records retain paths and fingerprint hashes, not query values or session IDs.
Raw framework contexts/transcripts and child finding objects remain in memory.

Active evidence is attached **after** the existing dedup, outside the frozen
Fusion adapter's scoring fields. Parent severity, result, confirmation,
evidence ID, passive source members and dedup maximum remain unchanged. Existing
child active findings are deliberately not appended as new posture penalties.
Tests assert byte-equivalent Fusion/CQI artifacts before/after attachment.

New operational manifest version 1.1 requires `active_validation.json` alongside
request/native/zap/snapshot files. It is hash-verified on every read. Old 1.0
snapshots remain byte-identical/readable with their original membership. Each
new assessment has new parent/candidate IDs, fresh execution and its own immutable
active artifact; no cross-assessment cache exists.

The UI shows separate finding and active badges with SUMMARY and TECHNICAL
EVIDENCE. Historical snapshots without an active result say NOT RUN rather than
being retrospectively relabelled. Real acceptance details are recorded separately
after the one authorized production-path run; synthetic tests are not live proof.

The Task 1A Native coverage inventory is a different contract from current
active results. Its legacy optional-validator template prerequisites must not
be interpreted as an execution gate for this stage. Current per-finding active
status/counts come from `active_validation` / `active_validation_summary`.
