# Branch 1 operational assessment profiles

STANDARD is the default repeated **current-state** measurement. FULL_AUTHORIZED
is a separately selected deep DAST assessment. PASSIVE_BASELINE preserves the
restricted profile. All use the same finding, provenance, canonicalization,
maximum-member deduplication, CQI and immutable-snapshot implementation.

## Why two profiles exist

The frozen Task 1C.3 deep run used 43/53 active rules, 220 discovered endpoints,
9353 recorded active messages and 3660 seconds, stopping PARTIAL at 43%.
DOM XSS consumed 1369.932 seconds (still at 77%), traversal 762.670 seconds,
SQLite timing SQL 410.418 seconds, reflected XSS 233.321 seconds and generic SQL
151.935 seconds. Enabled was not inferred to mean executed. These measurements
show deep DAST has substantial operational cost; they do not mean ZAP cannot
execute. The deep policy, discovery, rule strengths, bounds and observability
remain available unchanged. No deep scan is run for Task 1D acceptance.

## STANDARD / zap-standard-1.0

Fresh Native assessment → fresh unnamed ZAP session → seed + bounded Traditional
Spider → passive queue → selected ZAP Active → passive queue → canonicalization
→ repository Active Validation → immutable snapshot → existing CQI on read.
The repository validation stage retains its existing post-canonicalization order
so it can also reconsider current scanner findings. It is isolated from scanner
failure and does not alter parent scores.

Explicit active IDs: **0, 20019, 40003, 40012, 40018, 40032, 40034**:
directory browsing, external redirect, CRLF injection, reflected XSS, generic
SQL injection, .htaccess disclosure and .env disclosure. LOW attack strength,
MEDIUM threshold. These are scanner settings, not CQI coefficients. No claim of
coverage equivalent to the deep profile is made. No database backend is guessed.

[Machine policy](ZAP_STANDARD_POLICY.json) records every installed rule, deep
and standard decisions, rationale and actual previous runtime/request counts.
Missing measurements stay null. New/unreviewed rules are denied in STANDARD;
missing rules are NOT_INSTALLED. Heavy rules are deep-only, not labelled unsafe.
Existing deep safety exclusions remain separately documented.

STANDARD uses only newly discovered URLs from its own fresh session. Traditional
Spider has depth three, ten children per node and 25 seconds; forms are parsed
but POST submission remains disabled. The seed is the configured target, not a
sanitized or historical Native URL. Client/AJAX stages are explicitly
NOT_RUN_STANDARD. Browser discovery/import functionality remains in the deep
profile. API-definition imports are not automatically executed in STANDARD.
One context scan uses ZAP's existing structural/query-value normalization.

The same AuthorizedTarget model supports STANDARD and FULL_AUTHORIZED. Exact
origin/path context, exclusions, loopback-only control API, explicit authorization,
fresh-session isolation, cancellation, body caps and sanitization remain.
Existing Native and repository validators run for the configured Moodle lab;
other authorized targets receive honest unavailable Native/validator coverage
until an appropriate existing collector is configured. This task does not add
platform normalization or claim equivalent cross-platform coverage.

## Finite performance policy

Preferred total <=300 seconds, **hard assessment bound 480 seconds**, including
Native, ZAP, validation and publication. No acceptance bound may be widened.
The Native plan stays at its calculated 43-request/364-second maximum; a shared
absolute deadline may shorten remaining time without changing its checks.

STANDARD ZAP work: maximum 300 seconds, active stage 180, Spider 25, each passive
drain 20, metadata 20; concurrency four, host rate eight requests/s and 100 ms
active delay (the prior measured stable settings). Cleanup has at most 32 seconds
and prioritizes owned cancellation and SAFE restoration. ZAP receives an absolute
deadline reserving 20 seconds for validation and 15 for publication; cleanup is
included in that allowance. Slow Native execution therefore cannot grant a new
full ZAP budget after exhausting the whole-assessment budget. Repository
validation admits only complete existing protocols that fit remaining time and
guards each request against the absolute deadline. Missing time becomes an
explicit NOT_RUN/PARTIAL condition, not PASS. The independent native ZAP scan
timer is also configured as a bounded fallback. Loss of the control tunnel is
reported as failed cleanup rather than an assertion that remote cancellation
was verified.

The seven-rule selection, smaller current site tree and LOW strength are
prospectively selected from security value, measured costs, protocol applicability
and overlap. Unmeasured inexpensive-looking rules remain subject to the same
hard active deadline; runtime is not fabricated or guaranteed by rule names.

If Active times out, Native, completed passive and active evidence, repository
validation and the current snapshot survive as honest PARTIAL results. No
previous deep alerts are recycled. Current DAST indications remain first-class
FAIL findings even when CQI UNMAPPED. Scanner confidence is not exploit proof;
NOT_CONFIRMED is not false positive. No new scoring mapping or duplicate penalty
is introduced. CQI remains a policy-derived quality index, not probability.
The UI/API before/after comparison selects the same target **and profile**.
STANDARD and FULL have different tested coverage; a higher STANDARD CQI than a
previous FULL result is not evidence that a weakness was remediated. Missing
internal dimensions and unexecuted deep checks remain explicit limitations.

## API / CLI / UI

`POST /api/posture/assessments` accepts `mode: STANDARD` (default),
`FULL_AUTHORIZED` or `PASSIVE_BASELINE`. STANDARD and FULL require
`authorized: true`. Every new request/snapshot includes `assessment_profile`.
Historical responses derive the label from their original mode without changing
their bytes or treating historical FULL results as STANDARD.

The normal UI selects STANDARD — Recommended for normal assessment. Deep scan
requires explicit selection and shows a time warning. Restricted passive remains
available. Partial findings are displayed rather than falsely reporting zero.

```bash
.venv/bin/python -B scripts/run_posture.py assess --authorized --profile STANDARD
```

The CLI uses the same orchestrator. For acceptance, the running dashboard's
production POST route is used exactly once. Tests use synthetic transport and
temporary output directories, including FAIL → fresh PASS → CQI improvement,
fresh scanner sessions, immutable earlier snapshots and unchanged deep policy.
