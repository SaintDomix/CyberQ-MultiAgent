# Intentionally vulnerable Branch 1 benchmark

Disposable, isolated standard-library HTTP application; fictitious fixtures only.
Never deploy to a production system. No Moodle database, user or credential is
used. Each SQL request creates an in-memory fixture database, enables query_only
and performs SELECT only; the vulnerable input is restricted to `lesson` and the
validator's single-quote perturbation. No query extraction, writes from requests,
stacked SQL, schema enumeration or delays. Initial CREATE/INSERT seed the disposable
fixture only. XSS output uses inert delimiter markers, with CSP script-src none;
no browser/JavaScript execution is needed. Enumeration only compares two fictitious
identifiers and never sends mail or changes account state. Requests are not logged,
and payloads/fixtures are never written to disk.

`app.py` does not bind until explicitly launched. --bind/--port/--authorized are
mandatory. Ctrl-C stops the server. The banner identifies this vulnerable lab.
The default context template uses loopback so server and worker can both run on
Kali. If hosted elsewhere, explicitly review the listening address/firewall and
change all template URLs to that same authorized origin before planning. No crawl
or discovery is performed.

| Family | Positive endpoint (GET q) | Negative endpoint (GET q) | Expected positive | Expected negative |
|---|---|---|---|---|
| SQLi | /sql/vulnerable | /sql/safe | REPRODUCIBLE_DB_ERROR / PARTIAL / LIKELY | NO_SQLI_SIGNAL / PASS / NOT_CONFIRMED |
| Reflection | /xss/unsafe | /xss/encoded | POTENTIALLY_UNSAFE_CONTEXT / PARTIAL / LIKELY | ENCODED_REFLECTION / PASS / NOT_CONFIRMED |
| Enumeration | /accounts/distinct | /accounts/normalized | REPRODUCIBLE_ACCOUNT_DISTINCTION / PARTIAL / CONFIRMED | NO_ACCOUNT_DISTINCTION / PASS / NOT_CONFIRMED |

`runtime_context.template.json` declares endpoints/parameters/benign values.
`expected_outcomes.json` is machine-readable **expected** design, not experimental
results. The runner creates canonical declared NOT_TESTED parents and uses the
unchanged production Registry -> SafetyPolicy -> Executor -> validators -> linked
evidence path. No special benchmark detection is in the production validators.
Expected-vs-actual comparison is null/unassessed for plans, skips or errors; active
runner exit 2 means acceptance is incomplete or differs from expected. 22 attempts
are needed for all six pairs; budget=24, timeout=5s, rate=0.5 requests/s, default
64 KiB response cap, no redirect following. Do not report these expected labels as
measured results until a later actual HTTP run is retained.

## Proposed Kali commands (not executed in implementation)

Terminal 1, from the repository checkout on Kali:

```bash
.venv/bin/python -B lab/branch1_validator_benchmark/app.py \
  --bind 127.0.0.1 --port 8765 --authorized
```

Terminal 2, same checkout:

```bash
export B1_BENCH_CONTEXT="$(cat lab/branch1_validator_benchmark/runtime_context.template.json)"
.venv/bin/python -B lab/branch1_validator_benchmark/run.py \
  --target http://127.0.0.1:8765/ --out outputs/branch1_m1e_benchmark_plan01
.venv/bin/python -B lab/branch1_validator_benchmark/run.py \
  --target http://127.0.0.1:8765/ --active --authorized \
  --out outputs/branch1_m1e_benchmark_run01
```

Stop terminal 1 with Ctrl-C. Keep the run directory and exact commands/config for
reproduction; always choose a new empty output directory. JSON/CSV observations,
transcript hashes, expected/actual comparison and source provenance are exported.
Fixture tests call Application directly through a mocked requests transport,
exercise the normal engine, and prohibit sockets; they do not start this server.
