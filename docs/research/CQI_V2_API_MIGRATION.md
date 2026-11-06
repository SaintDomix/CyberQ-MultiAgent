# CQI v2 API migration

The mathematical redesign is an explicitly versioned API, not a rewrite of
historical values. Existing `/api/cqi`, `/api/cqi/dimensions` and the CQI field in
`/api/application/snapshot` remain `fusion-cqi-1.1`. Existing dashboard clients
therefore retain their accepted behavior until a separate presentation migration.

New clients request:

```text
GET /api/cqi/v2?mode=ACCEPTED_REPLAY&replay=BENIGN_TEST
GET /api/cqi/v2?mode=LIVE_LAB
GET /api/cqi/v2/policy
```

The new response is `scientific-cqi-response-2.0`, policy `cqi-evidence-2.0`.
It includes:

- `overall`: conservative coverage-bound index, nullable if nothing is observed.
- `overall_score_kind`: explicit warning against treating a lower bound as a
  fully observed quality measurement.
- `conditional_overall`, `quality_bounds`, `overall_status` and `coverage`.
- D1–D6 with supported hazard, missing-control allowances and contributions.
- Behavioral active/history distinctions, recovery semantics and missing reasons.
- Policy, registry, source identities and deterministic result SHA256.
- `comparison_context`: legacy scalar, policy version, source scope and as-of semantics.

LIVE defaults to actual UTC as-of. Replay defaults to the explicit evidence clock.
An explicit `as_of` must be UTC. A stale journal does not imply current normal
traffic. The current CQI does not import another target's Moodle observations.

Consumers must display the score **together with coverage and conditional bounds**.
Zero can result from unavailable D6 and means conservative uncertainty, not
observed universal failure. Comparisons across changed policy, scope or coverage
must not be presented as actual remediation. Parameters are policy-derived,
not calibrated probabilities. No confidence interval interpretation is supported.

No frontend redesign or automatic switch of the current score widget is part
of Task 3A. No monitor/backend restart is performed. The newly added route loads
at the next operator-approved ordinary deployment. In-process FastAPI tests
exercise the real route and verify unchanged legacy output.

Verified lifecycle records are accepted by the mathematical layer as explicit
inputs. An operator incident-review/closure interface, verification workflow and
persistence of those decisions are not introduced or implied by this endpoint.
