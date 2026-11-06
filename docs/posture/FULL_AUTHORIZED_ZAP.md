# FULL_AUTHORIZED DAST profile

This is a separate operational profile from the accepted restricted passive and
zero-rule gate. It does not change Behavioral v2, accepted snapshots, or CQI
formula/weights. ZAP-only vulnerabilities are primary findings, not merely
corroboration of Native checks. Findings and CQI mapping are separate concepts.

## Configuration and authorization

`AuthorizedTarget` in `src/posture/target.py` accepts an explicit authorized
HTTP(S) application base URL ending in `/`. Origin, base path and exact escaped
context include regex are derived, not supplied as a wildcard. Exclusions can
only narrow it. Credentials, fragments, query-bearing seeds, ambiguous paths,
loopback and metadata addresses are rejected. IPv6 is currently unsupported.

The default development URL is `http://192.168.226.132/moodle/`. A configured
`https://moodle.example-university.kz/` target needs no source changes for ZAP.
No request to that example host was made during development or acceptance.
The existing Native implementation and repository validators still require
their Moodle laboratory prerequisites. They explicitly become unavailable on
another target; lab findings or behavioral telemetry are never substituted.
Other-LMS Native/behavioral accuracy is not claimed.

Authentication modes NONE, FORM, HTTP, SCRIPT, EXISTING_SESSION are represented
for future adapters. Only anonymous operation is implemented/validated here.
Non-NONE configuration is reported NOT_CONFIGURED, not silently authenticated.
Verified roles and secure environment/session credential references remain
future work. No password/session credential field is accepted by this API.

Optional `api_imports` maps openapi/graphql/soap/postman to an in-application
definition URL (GraphQL URL is its endpoint). OpenAPI uses target host override
and context; other imports feed the same current site tree/context. Local file
imports are intentionally not arbitrary filesystem APIs. Import success does
not prove that imported definitions describe all application endpoints. Imported
external references may be resolved by add-ons; only in-context endpoints are
eligible for active testing. No API definition was supplied for Moodle.

## Execution and boundaries

`FullZapAPI` reuses the existing bounded loopback/key transport but exposes a
separate closed RPC surface. It has no shell execution, session load/save,
shutdown, wildcard scope or ATTACK-mode action. `FullZapProvider`:

1. Inventories version, 48 installed add-ons, 53 active and 61 passive rules in
   the observed 2.17.0 installation. Capability flags separately state installed,
   available, integrated and executed. See `FULL_AUTHORIZED_CAPABILITIES.json`.
2. Requires an owned idle safe-mode daemon; never adopts/stops shared jobs.
3. Creates a fresh volatile session, verifies empty history, creates a unique
   application context, installs exact include/narrowing excludes and scopes it.
4. Uses **PROTECTED**, API token `protect`, not `safe`, standard or attack.
5. Seeds current traffic with no-follow GET, runs scoped traditional Spider,
   attempts installed Client/AJAX browser discovery separately, and drains the
   passive queue. No historical tree or alert is used as current evidence.
6. Creates a unique scan policy, disables its defaults, enables the effective
   installed applicable rules, verifies the resulting ID set, and actively scans
   the current discovered context. It requires no Native finding.
7. Collects current scan message/alert IDs, per-rule request counts where the API
   exposes them, final passive analysis and sanitized current findings.
8. Stops/removes only owned scan handles, restores recorded settings, removes
   its temporary policy/rate rule and restores safe mode. Cleanup failures are
   explicit, never claimed successful. Snapshot history is not deleted.

Scope does not disable ordinary injection testing. SQLi, reflected/persistent
XSS, CRLF, command/code/template injection, traversal and parameter tests are
enabled where installed. This profile does not constitute unrestricted stress
testing, post-exploitation or permission to contact third-party callback hosts.

Ten explicit exclusions from the observed 53 rules (43 enabled):

| ID | Reason |
|---|---|
| 7 | Remote inclusion with external payload/callback behavior |
| 30001 | Buffer overflow / resource-exhaustion testing |
| 40043 | Log4Shell external OAST callback not authorized/configured |
| 40044 | Deliberate Billion Laughs resource exhaustion |
| 40045 | Spring4Shell file-write/webshell probe |
| 50000 | No operator-reviewed custom active scripts configured |
| 90023 | External entity file/callback behavior not authorized |
| 90034 | Cloud metadata outside target identity |
| 10106 | HTTP-to-HTTPS changes the configured authorized origin |
| 10047 | HTTPS-to-HTTP changes the configured authorized origin |

The default policy is never used to scan everything. Effective IDs, thresholds,
strength and exclusions are recorded per assessment. Generic rules are not
removed solely because Moodle is the development target. Technology context
is recorded without narrowing away generic web tests. Rule enabled does not
mean executed; positive per-rule request counts are reported separately.

Spider is recursive within the context/subtree, two threads, no arbitrary POST
form submission, logout avoidance, and no root-level robots/sitemap expansion.
Browser discovery uses the context/subtree and available headless Firefox; no
browser download occurs. Browser failure is an optional-stage result. Forms
are represented as action/method/parameter names, never values.

## Operational bounds

| Control | Default |
|---|---:|
| Full ZAP overall execution deadline | 1000 seconds |
| Traditional Spider | 120 seconds |
| Client Spider | 60 seconds |
| AJAX Spider | 60 seconds |
| Active scan | 600 seconds / ZAP native 10-minute cap |
| Per active rule | ZAP native 2-minute cap |
| Passive drain | 60 seconds |
| Active/Spider concurrency | 2 |
| Per-host rate | 4 requests/second |
| Active delay | 250 ms |
| Local disk stop threshold | 500,000,000 bytes |

No Native-sized hard request cap is applied. Time-limited partial scans are
reported PARTIAL; enabled rules alone are not a coverage claim. API control
requests retain 3-second connect/8-second total/read bounds and 5 MB JSON cap.
Metadata history export is capped at 5000 records without limiting the scan's
request count. Bodies are parsed transiently for form metadata and discarded;
no response archives, screenshots or ZAP database exports are generated.

Cleanup is also finite (each recorded restore action has an 8-second bound)
and may extend beyond the execution deadline. Native retains its separate
43-request/364-second worst-case policy. A lost tunnel can prevent successful
remote stop/restore; this is recorded and requires operator inspection rather
than falsely asserting that remote jobs stopped.

## Findings, provenance and scoring

`zap_normalize.py` uses scan-owned alert IDs to distinguish **ZAP_ACTIVE** from
**ZAP_PASSIVE**. It preserves plugin, risk, original confidence, CWE/WASC,
method, sanitized endpoint/parameter, solution, rule reference, assessment,
session/scan identity and payload digests. Raw bodies, attack values, cookies,
headers, credentials and token/query values are not exported.

ZAP-only findings retain FAIL/severity even if `cqi_mapping=UNMAPPED`.
False-positive source status remains DISMISSED. ZAP confidence is preserved
and is not promoted into project CONFIRMED or exploit-success evidence.
Only existing `model.ZAP_RULES` mappings score; no new weights or categories
are manufactured. Unmapped findings remain in the primary API/UI, excluded
from CQI by the unchanged Fusion policy.

Identity uses family/CWE, normalized endpoint, parameter and method; endpoint
query values do not create duplicate weaknesses. SQLi and XSS remain distinct.
SQLi/XSS plugin variants may share a canonical family only with matching CWE,
endpoint and parameter. Reviewed Native control equivalence uses the existing
keys and maximum contribution, not summed corroboration. Repository Active
Validation remains metadata with score_effect NONE. Canonical target identity
is configurable so findings from different targets cannot share a control ID.

## Capability limits

Traditional Spider and active/passive scanning are integrated. Client/AJAX are
attempted if installed, with explicit optional failures. OpenAPI/GraphQL/SOAP/
Postman URL imports are optional configured discovery mechanisms. No Moodle API
definition is required. Forced Browse is installed but has no exposed control
API in this daemon; its GUI/add-on installation is not execution acceptance.
Fuzzer requires a current message, injection locations, controlled payload
source, processors and a finite job budget. `/api/scanners/zap/capabilities`
exposes this contract; generic fuzz-job execution is not implemented.
Sequence and Automation Framework are inventoried, not falsely claimed executed.
Python orchestration remains the reproducible execution plan.

## API / operator commands

The existing POST `/api/posture/assessments` accepts `mode=FULL_AUTHORIZED`,
`target_url`, `authorized=true`, discovery/authentication profile, exclusions
and optional API imports. Local control header is required. The UI defaults
to FULL_AUTHORIZED with an explicit authorization checkbox. PASSIVE_BASELINE
remains selectable and retains its original closed target/policy.

```bash
curl --fail -sS -X POST http://127.0.0.1:8000/api/posture/assessments \
  -H 'Content-Type: application/json' -H 'X-Product-Control: 1' \
  --data '{"mode":"FULL_AUTHORIZED","target_url":"http://192.168.226.132/moodle/","authorized":true}'
```

Read `/api/posture/assessments/{assessment_id}` for progress/results. Cancel
only that owned job with POST `/api/posture/assessments/{assessment_id}/cancel`
and the same control header. CLI alternative:

```bash
.venv/bin/python -B scripts/run_posture.py assess --authorized \
  --profile FULL_AUTHORIZED --target-url http://192.168.226.132/moodle/
```

These commands generate real vulnerability-test traffic; they are not replay.
Do not run them against a target without authorization. This implementation
does not claim successful exploitation or comprehensive vulnerability absence.

Primary API references: [ZAP modes](https://www.zaproxy.org/docs/desktop/start/features/modes/),
[Active Scan API implementation](https://github.com/zaproxy/zaproxy/blob/main/zap/src/main/java/org/zaproxy/zap/extension/ascan/ActiveScanAPI.java).
Installed endpoint/parameter documentation was inspected directly before use.
