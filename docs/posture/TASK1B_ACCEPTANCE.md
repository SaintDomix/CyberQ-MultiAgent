# TASK 1B — operational acceptance

One real production-path assessment was submitted after focused tests passed:
`posture-20261026T191552Z-8027185eb9ba` (UTC assessment identifier).

Receipt:
`runtime/posture_acceptance/task1b_posture-20261026T191552Z-8027185eb9ba/acceptance.json`

SHA256:
`2c27e43b248647e89c4edb85e07a02748a231ed7ab237c61937e0e6684872964`

Native COMPLETE (30 requests), ZAP Passive COMPLETE (5 requests, fresh session,
scope PASS), current active stage COMPLETE (2 GET attempts). Overall posture
coverage remains PARTIAL because real internal/role/baseline prerequisites are
not fabricated. ZAP Active Scan was not implemented or invoked.

## Active counts, per canonical finding

| State | Count |
|---|---:|
| Relevant eligible indications, including prerequisite-limited | 2 |
| Ready | 1 |
| Executed | 1 |
| CONFIRMED | 1 |
| NOT_CONFIRMED | 0 |
| NOT_APPLICABLE | 108 |
| NOT_AVAILABLE | 1 |
| NOT_RUN | 0 |

`EXPOSURE-001`, sensitive_path: GET /server-status returned 200 with recognizable
Apache server-status content. Its existing inert nonexistent control returned
404 with different content. Active CONFIRMED means readable exposure only;
successful exploitation is not established. The parent remains FAIL/MEDIUM.

`ACCESS-003`, access_control: NOT_AVAILABLE because reviewed URL/policy, verified
role sessions, identities and privileged-content comparators were absent. No
role login, password attempts or guessed context were introduced. No current
SQLi/XSS finding was eligible and no SQLi/XSS probe was sent.

Actual active budget: 2/2 attempts, global ceiling 23, timeout 5 seconds, rate
0.25 requests/second, no redirect following, 65,536-byte response cap. The
computed additional stage deadline is 14 seconds; the general maximum is 203.
Existing timeout/deadline rejection limitations are explained in the protocol.

## Integrity and limitations

Independent snapshot manifest verification passed. Full frozen Fusion outputs
were identical with and without attached active metadata. The posture-only
partial CQI remained 40.23080444335938; no active penalty/multiplier was added.
All 1,399 pre-existing protected files remained byte-identical. Frozen research
source and accepted Behavioral v2 verified unchanged at
`59a8c7c5d3d51632d0afe45f8cd2fe50570b7af2943d26bb313888327ea9f436`.

277 focused Python tests, 41 frontend tests and the production build passed.
Synthetic two-assessment tests prove fresh execution/new IDs and preserve the
first six-file snapshot; a second real assessment was deliberately not run.

One normal launcher attempt failed before assessment submission. Preflight
passed and one normal retry succeeded. One completion poll returned 503; a
read-only retry returned 200, and independent hash/CQI reads passed. This is
recorded as a transient operational issue, not hidden as scanner success or
used to rewrite any evidence. Atomic publication/status hardening remains a
separate reliability consideration. Task 1C was not started. No commit/tag.
