# Milestone 1B — unified security-posture assessment

Production package: `src/branch1/`. Entry point: `scripts/run_branch1.py`.
Canonical schema and Milestone 1A adapters are unchanged. No behavioral model,
root-cause fusion, or CQI is implemented here. Milestones 1C/1D provide the
separate bounded active stage described below.

## Milestone 1C — linked active validation

`src/branch1/active/` exposes a Validator protocol and an ordered Registry. Each
validator proposes an applicability/context decision, specifies read-only
requests, and classifies responses. Supply another Registry to `run_active` to
add validators without changing canonical contracts or posture orchestration.
The stage is invoked after canonical posture findings are produced. It never
modifies parents, upgrades advisory versions, or revives dismissed candidates.

```bash
.venv/bin/python -B scripts/run_branch1.py --mode offline --plan-active \
  --out outputs/branch1_active_plan_m1c
```

Planning constructs no HTTP client and makes zero requests. It records an entry
for every parent (multiple validators can produce multiple entries). Every entry
links both parent IDs, names a validator when one exists, and records applicability,
reason, required context, authentication requirement and execution status.
APPLICABLE means a bounded content check exists; without a target the required
context explicitly states that authorization and a target are still needed.
All unexecuted validations have confirmation NOT_TESTED. Milestone 1D integrates
SQLi, XSS, enumeration, access-control, session-control
and SSRF-context validators; missing prerequisites are MISSING_CONTEXT, never
simulated tests. Other finding types are NOT_APPLICABLE to this registry.

Actual execution requires all of `--plan-active --active --authorized --target`.
For later review and authorized lab use only (not executed in this milestone):

```bash
.venv/bin/python -B scripts/run_branch1.py --mode offline --plan-active \
  --active --authorized --target http://192.168.226.132/moodle/ \
  --active-budget 20 --active-timeout 5 --active-rate 0.25 \
  --out outputs/branch1_active_lab_run01
```

Offline execution rechecks explicit historical URLs; it does not retarget them.
Exact scheme/host/port scope is mandatory; paths outside Moodle's base path on
that origin are permitted for historical server-status and diagnostic evidence.
Use live-passive mode with the same active flags and fresh prerequisite evidence
to validate newly collected posture findings. Planning without active execution
is restricted to offline mode so live-passive collection cannot violate the
zero-network planning guarantee. Existing passive collection has its separate
documented bounds; active limits apply only to active requests.

Defaults: 20 total attempts (maximum 40), 5-second timeout (maximum 10), 0.25
requests/second (maximum 0.5), 64 KiB default response cap. A reviewed runtime
may explicitly select a cap up to 256 KiB; over-limit responses fail in full,
never become truncated negative observations. Path/redirect checks require
two requests; advanced checks require two to four requests (SSRF context requires
zero); insufficient budget skips the entire check. Failed attempts consume
budget. Redirects are never followed. GET only; mutation paths, traversal,
credential/token queries are rejected. Environment proxy/netrc use and automatic
cookie replay are disabled. Optional authorized test sessions use ephemeral
environment references as described
below. No password inputs, brute force, state-changing payloads, persistence or
load tests are supported by the generic executor. The isolated Moodle acceptance
adapter permits one credential POST per authorized identity solely to bootstrap
ephemeral sessions; it shares explicit scope, budget, timeout and rate bounds.
Explicit supported profiles or reviewed read-only
runtime context are required; endpoints/parameters are
never inferred from version advisories.

Milestone 1E prepares two experiments without executing them: the isolated
[controlled benchmark](../lab/branch1_validator_benchmark/README.md) exercises
the normal generic input validators, and the
[Moodle role acceptance](acceptance/M1E_MOODLE_ROLE_ACCEPTANCE.md) bootstraps
verified ephemeral student/admin sessions for a read-only report comparison.
Role denial acceptance requires a verified privileged identity/content comparator;
an unavailable comparator remains NOT_TESTED. The historical dismissed /admin/
candidate is never reactivated.

Sensitive-path profiles cover Git HEAD, environment files, PHP diagnostics,
Apache status and directory indexes. A distinctive content signature must differ
from an inert nonexistent-path control. Not-found/auth-denied/generic/error
responses do not confirm exposure. HTTP 200 alone is inconclusive. Open redirect
requires `evidence.active_context` with `url`, `redirect_parameter`, and
`read_only: true`; authentication defaults to anonymous. A recognized redirect
status must return exactly the inert `https://branch1-validation.invalid/return/`
destination with candidate ID. Internal or unrelated SSO redirects do not prove
an open redirect, and the destination is never contacted.

Outputs add `active_validation_plan.json`, `active_validation_results.json`,
`active_validation_evidence.json` (bounded request metadata/body hashes, never
body contents), and `active_validation_findings.json` (canonical linked findings
for attempted HTTP checks and explicitly completed request-free SSRF
assessments). Errors remain ERROR / NOT_TESTED; negative completed
checks are NOT_CONFIRMED, never a system-wide safety claim. Positive checks are
CONFIRMED only for the observed exposure/controlled redirect predicate. Parent
severity is retained only on positive linked evidence, and confidence remains
unknown. Summary reports active counts separately from the unchanged 40 parents.
No deduplication or fusion is performed.

Active-enabled exports redact secret/token/cookie fields, URL credentials and
secret query values, assignment strings, authorization headers and hidden inputs.
Parent objects and historical source files are unchanged. Parent IDs/provenance
hashes identify original source evidence, not redacted report copies; export
mapping notes state this distinction. Summary provides exported artifact hashes
where fresh passive artifacts may also have been redacted. Active transcript
provenance refers to its exact sanitized artifact. Original 1A/1B exports remain
unchanged. Active runs require a new empty output directory; planning reruns
accept identical outputs only.

## Milestone 1D — advanced safe active validation

Production additions: `active/advanced.py` and `active/runtime.py`. All eight
families use the existing Registry, SafetyPolicy, Executor and linked evidence
orchestrator. Canonical contracts and historical parents are unchanged.
Planning remains network-free. No Milestone 1D live lab acceptance is claimed.

| Validator ID | Explicit context | Maximum requests per candidate | Interpretation |
|---|---|---:|---|
| sql_injection | url, parameter, short benign baseline_value, read_only=true | 4 | Baseline/quote/baseline/quote. Stable new database/parser errors give LIKELY SQLi relevance, never confirmed exploitation; ordinary/unstable differences are NOT_CONFIRMED. |
| unsafe_reflection_xss | url, parameter, read_only=true | 3 | Baseline then repeated inert unique delimiter marker. No reflection/encoded/raw/potentially unsafe attribute or script/ambiguous are distinct. Raw is CONTEXTUAL, unsafe context LIKELY; no JavaScript execution or stored payloads. |
| account_enumeration | url, parameter, two test_identifiers, read_only=true, lookup_only=true | 4 | Two alternating repetitions per authorized identity. Input echoes in body/Location are normalized; stable distinctions confirm only the observed account-dependent response. Dynamic/error differences remain inconclusive. No password attempts or recovery mail; timing is not assessed. |
| access_control | url, read_only=true, expected_denied=true, distinct restricted/privileged roles and session refs, identity_markers, privileged_markers | 4 | Two role pairs. Response identity and privileged content are required; link-only/generic 200 differences remain inconclusive. Repeated restricted content gives LIKELY unauthorized-content relevance, not confirmed function execution. |
| session_control | url, cookie_name, read_only=true; optional session_ref | 2 (4 with prior session) | Repeated effective Secure/HttpOnly/SameSite/transport attributes; configuration mismatch recorded separately. CONFIRMED describes observed attributes only. Missing emitted cookies are NOT_TESTED. |
| ssrf_context | boolean feature_enabled/url_fetch_available and feature_evidence reference | 0 | Request-free contextual prerequisite assessment. Unavailable surface gives NOT_APPLICABLE; available surface gives CONTEXTUAL, never confirmed SSRF. No fetch URL, metadata, internal network or callback is contacted. |

For SQLi, XSS and enumeration, optional `session_ref` refers to an authorized
session. SQLi baseline values accept only up to 128 alphanumeric, space, dot,
underscore or hyphen characters; only a single quote is appended. Endpoints
and parameters are never derived from advisory names or version matches.
Read-only and lookup-only assertions must be reviewed against actual lab behavior
before execution; a GET endpoint is not intrinsically side-effect-free.

Session-cookie results evaluate the parent predicate independently: Secure,
HttpOnly or SameSite is selected from the parent finding ID/type and recorded as
`session_predicate`. Context cannot override a recognized parent's predicate.
All effective attributes and both observations remain in linked evidence. A
missing Secure flag cannot turn present HttpOnly or SameSite=Lax into failures.
Specific predicate failures are FAIL/CONFIRMED; successful bounded checks are
PASS/NOT_CONFIRMED and make no overall safety claim. SameSite accepts Lax/Strict
and None with Secure by default; a stronger policy must be explicitly supplied
as `samesite_policy` (a lowercase allowed-value list). General session assessment
and prior-session behavior remain available under `all_attributes`; lifecycle
observations do not override specific cookie predicates.

`configuration_mismatch` is nullable: true/false compares parsed explicit
expectations relevant to the parent predicate; null means not assessed/unknown.
`configured_attributes` supports secure/httponly booleans and samesite strings;
`configured_settings` also accepts cookiesecure/cookiehttponly/cookiesamesite
from explicit internal evidence. Boolean strings such as "1" are parsed;
missing/null/unrecognized values remain unknown. A configuration reference alone
is not a parsed expectation and is never silently read during validation.
Per-attribute comparisons and parsed expectations are retained separately, so
unrelated configuration differences cannot confirm a parent's weakness. A setting
versus emitted-attribute difference does not by itself prove faulty configuration
application: HTTPS/proxy conditions can explain it. No defaults are invented.

Session `require_authenticated=true` requires `session_ref` and an explicit
`authenticated_marker` verified in both responses. `configured_attributes` may
contain secure/httponly booleans and lowercase samesite; it does not replace HTTP
evidence. Optional `invalidated_session` plus `expected_invalidated=true` and
`authenticated_marker` probes a previously invalidated dedicated test session
with two read-only requests. Denial is recorded as an observation, not proof of
invalidation; repeated authenticated content yields LIKELY failure relevance.
No lifecycle transitions are executed. Rotation remains explicitly NOT_TESTED;
login/logout workflow changes need a separately reviewed safe implementation.

Runtime role metadata and policy are operator assertions; response identity
markers strengthen them but do not independently verify Moodle capability
assignments. Access comparison follows the existing `roles.py` methodology:
permission/login barriers matter, and privileged-looking links alone do not
prove accessible functions. Historical FALSE_POSITIVE parents are never revived.

### Ephemeral runtime interface

Python: `RuntimeContext(mappings=..., sessions=...)`, passed to `run_active` or
`Registry.plan`. CLI: `--active-context-env B1_ACTIVE_CONTEXT` loads JSON from
that environment variable, never from credential files. Mappings are keyed by
exact parent evidence ID (preferred) or finding ID, then validator ID. Unknown
IDs do not generate candidates. Mappings apply to a temporary parent copy.

Example structure (replace example endpoints/markers only after lab review):

```json
{
  "mappings": {
    "EXPLICIT_PARENT_ID": {
      "sql_injection": {
        "url": "http://192.168.226.132/moodle/EXPLICIT_READ_ONLY_ENDPOINT.php",
        "parameter": "EXPLICIT_PARAMETER",
        "baseline_value": "1",
        "read_only": true,
        "session_ref": "student-test"
      }
    }
  },
  "sessions": {
    "student-test": {"role": "student", "cookie_env": "B1_STUDENT_COOKIE"}
  }
}
```

Session entries accept only role and cookie_env. Literal password, authorization,
cookie and token fields are rejected. Populate cookie environment variables
through a private ephemeral input; do not save secrets to files, shell history
or repository documentation. The executor resolves a Cookie header only after
scope/authorization checks, does not replay response cookies, clears its jar
between requests and never records request header values. Secret cookies,
identity markers/identifiers and account parameter values are redacted. Response
bodies are hashed, never exported. Authenticated/account response Location values
are redacted to prevent indirect identifier/session leakage. Planning only checks
session availability and role metadata; it creates no client.

Plans/results now include MISSING_CONTEXT and exact missing prerequisites,
authentication requirements and explicit context. APPLICABLE means an implemented
predicate has sufficient context; it does not mean a vulnerability exists.
A target is still required for execution. UNSUPPORTED remains available for
future registry extensions. Unexecuted results remain NOT_TESTED regardless of
parent status. Completed SSRF assessments use execution_status CONTEXTUAL_ASSESSED
and a canonical linked record referencing the sanitized empty request transcript;
parent/context evidence, not HTTP evidence, supports that observation.
All results include applicability, rationale, both parent IDs, validator ID/version
and request indices. CONFIRMED PASS observations carry no inherited weakness
severity. No confidence values or root causes are invented.

### Reproduction and later lab review

Fixture suite and exact baseline planning command:

```bash
.venv/bin/python -B -m unittest discover -s tests -v
.venv/bin/python -B scripts/run_branch1.py --mode offline --plan-active \
  --out outputs/branch1_active_plan_m1d
```

The baseline has 40 candidates: sensitive_path 5; session_control 4;
unsafe_reflection_xss 2; access_control 2; sql_injection 1; ssrf_context 1;
none 25. Account enumeration/open redirect have no baseline candidate.
Applicability: APPLICABLE 5, MISSING_CONTEXT 9, NOT_APPLICABLE 26.
All 40 planning results are NOT_TESTED with zero requests.

Proposed commands for later authorized acceptance from Kali (not executed as part
of Milestone 1D). First populate reviewed ephemeral mappings/sessions; use new
empty output directories. Offline execution preserves historical URLs; mappings
provide only explicitly reviewed runtime surfaces. The global budget may skip
whole candidates, so use focused mappings/parents for selected acceptance checks.

```bash
.venv/bin/python -B scripts/run_branch1.py --mode offline --plan-active \
  --target http://192.168.226.132/moodle/ --active-context-env B1_ACTIVE_CONTEXT \
  --out outputs/branch1_active_plan_m1d_review

.venv/bin/python -B scripts/run_branch1.py --mode offline --plan-active \
  --active --authorized --target http://192.168.226.132/moodle/ \
  --active-context-env B1_ACTIVE_CONTEXT --active-budget 20 \
  --active-timeout 5 --active-rate 0.25 \
  --out outputs/branch1_active_lab_m1d_run01
```

For fresh candidates, use the existing live-passive command with fresh internal
and role prerequisites plus the same active flags/context. Do not treat the
previous server-host smoke observation of `/server-status` as external exposure;
final external acceptance must run from Kali. New results must remain separate
from all historical artifacts. Supporting scanners, Branch 2, Fusion and CQI
are outside Milestone 1D.

## Offline replay

```bash
.venv/bin/python -B scripts/run_branch1.py --mode offline
```

The four module callables reuse saved canonical adapters, not live rule execution:

| Module | Historical source | Records |
|---|---|---:|
| external | external_mvp | 23 |
| intelligence | deep_v2 CORE-/PATCH-/ADV- checks | 12 |
| internal | remaining deep_v2 checks | 4 |
| roles | role_review_v3 | 1 |

Total 40; full records, identities, provenance and ordering equal Milestone 1A.
Fresh rule improvements do not rewrite or reclassify historical results. Replay
never constructs an HTTP client or executes a collector/probe. The historical
student admin-home candidate remains DISMISSED / FALSE_POSITIVE.

Outputs default to `outputs/branch1_unified/`: canonical findings JSON/CSV and
`branch1_summary.json`. Summary includes counts by module, original source,
category, check result, confirmation and severity (UNKNOWN for null). It also
records module assignments and source hashes. Counts are not vulnerability counts.
No deduplication occurs: duplicate evidence identities are rejected. Identical
offline reruns reuse artifacts without rewriting; different existing files are
never overwritten. Historical output directories are protected.

## Live passive mode (not network-validated in Milestone 1B)

```bash
.venv/bin/python -B scripts/run_branch1.py --mode live-passive --authorized \
  --target http://192.168.226.132/moodle/ \
  --internal-evidence /path/to/fresh/internal_evidence.json \
  --role-evidence /path/to/anonymous.csv /path/to/student.csv /path/to/admin.csv \
  --webserver-uid 33 --out outputs/branch1_unified_live_run01
```

`--authorized` asserts authorization for the supplied target; it is not a request
to discover or scan additional hosts. Server-side collection and authenticated
role probes remain explicit prerequisites. Review JSON may be supplied instead
of role CSVs. Do not mix those formats. The v2 collector JSON and v3 role CSV
formats are supported; no passwords are accepted or stored by this runner.
Supplied role names/identity metadata are not independently verified against
Moodle capabilities. Missing authentication/comparator evidence stays NOT_TESTED.

External requests are bounded to 80 actual HTTP requests, 6 redirect hops per
request chain, a positive timeout (default 8 seconds), and 2 MB per response.
Only GET, OPTIONS and TRACE are used, plus one TLS handshake for HTTPS. Host/
port scope is enforced before requests and redirects; HTTP/HTTPS counterparts
on normal ports are allowed for transport checks. Environment proxy/netrc use
is disabled. No credential submission, stress testing or exploit payloads occur.
Public endpoint probing, CORS Origin/preflight and method checks are included in
"passive" posture mode; this is bounded HTTP observation, not packet-only capture.
TLS examines a negotiated connection, not every supported cipher/protocol.

`external_evidence.json` retains bounded request observations and derived rule
records; Set-Cookie values are redacted while attributes are preserved. External
findings reference its exact SHA-256. Cross-role CSV analysis produces
`role_comparison_evidence.json`, including all supplied rows/file hashes and
comparisons. Internal/advisory findings retain input file paths/hashes and
relevant rule inputs; advisory evidence additionally references catalog hash and
record index. Fresh input files remain untouched. Keep them for reproduction.
Live runs require a new empty output directory.

Runtime dependency: requests, already present in the repository environment.
`src/branch1/requirements.txt` declares it. HTML selectors use standard-library
HTMLParser; BeautifulSoup is not required. No dependency was installed here.

## Ported behavior and justified changes

External generic/Moodle/cookie/TLS rules were ported from
`legacy/branch1/first_branch_v22/scanner/` into `external_rules/`; runtime imports
only local production files. The internal rules reuse the v2 evidence semantics.
The advisory JSON is a byte-identical copy of the historical catalog. Cross-role
logic reuses v3 anonymous/admin/content comparison with deterministic ordering.

Fresh-input differences are intentional:

- Optional diagnostic HTTP 404 remains non-confirmation, not unauthorized access.
  A reachable HTTP 200 without a clear barrier becomes PARTIAL / NOT_CONFIRMED;
  permission markers and login redirects are considered. Link differences alone
  remain review evidence, never confirmed unauthorized functions.
- Moodle deployment-artifact exposure requires format/content signatures and
  rejects generic HTML pages. Cookie checks remain per-cookie. Request failures
  become ERROR / NOT_TESTED; incomplete endpoint matrices cannot return PASS.
  A Moodle-phase request failure records incomplete external coverage rather
  than inventing results for checks that did not complete.
- Missing/uninterpretable internal values become NOT_TESTED, not false or PASS.
  Filesystem writability is explicitly about the collector account. Supplying
  `--webserver-uid` requires matching collected UID before interpreting that
  account as the web-server account; UID is never guessed.
- Restored Moodle debug-display check uses `debugdisplay`, not debug level alone.
  PHP display_errors is scoped to the collected SAPI (CLI in v2 evidence) and
  cannot establish browser disclosure; enabled display is PARTIAL configuration
  evidence. Missing settings remain unknown.
- Restored internal Secure-cookie check applies to explicit HTTPS wwwroot and
  cookiesecure. HTTP yields NOT_APPLICABLE because transport comes first. Null
  cookiesecure/HttpOnly is unknown, not a disabled control or an inferred default.
  Proxy configuration is retained; emitted cookie behavior requires HTTP evidence.
- Web-service-enabled/disabled/unknown context accompanies version matches.
  Disabled services reduce exposure context without erasing VERSION_BASED.
  Enabled services do not establish accessible vulnerable functions.

The older internal implementation was read only to verify these regression
concerns. Its CLI-PHP-to-browser inference and null-to-false handling were not
copied. Restored checks are for fresh input analysis, never added to the frozen
40-record replay. Direct explicit configuration observations can remain CONFIRMED.

## Advisory limitations

The packaged catalog is a historical snapshot with incomplete upstream source/
retrieval provenance; this milestone does not verify vendor announcements or
claim it is current. Default matching uses the existing branch/upper-build
semantics, preserving integer-build grouping of Moodle maintenance suffixes.
Optional affected_min is supported when supplied; no lower bound is invented.
Unsupported branches produce core evidence but no invented advisory matches.
Plugin inventory/mismatch checks exist; plugin advisory intelligence is not supplied.

There is no implicit "latest release" constant in live analysis. An optional
`--patch-baseline BUILD` is an operator-supplied, branch-compatible comparison
baseline, not an assertion about current Moodle releases. Use `--advisories FILE`
for an explicitly curated catalog. All affected-range/patch comparisons stay
VERSION_BASED. No confidence magnitude or root cause is fabricated.

## Extension points and validation

`pipeline.DEFAULT_MODULES` is a simple ordered mapping of names to functions
accepting Context and returning lists of canonical SecurityFinding. Pass an
extended mapping to `run()` to add a source or future validation stage. External
and internal `assess()` accept additional rule callables. No plugin loader or
legacy sys.path manipulation exists. Active Validation can consume category,
finding type, source observations, asset and advisory-surface context without
changing the canonical contracts.

```bash
.venv/bin/python -B -m unittest discover -s tests -v
.venv/bin/python -B scripts/run_branch1.py --mode offline
```

Tests use real saved inputs and explicitly synthetic HTTP/configuration fixtures;
they do not send live requests. They cover replay equivalence, provenance,
preservation, status semantics, internal regressions, role comparison and scoped
external behavior. Live collection requires a separate authorized acceptance run.
