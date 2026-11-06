# Demonstration and examination preparation

## Three-minute Assignment 4 demonstration

1. Run the documented preservation/source-proof check from the coursework root.
   Explain that the original source commit/tag/status and saved models remain
   protected, and the shared laboratory is locked.
2. Build using the bundled coursework Node and start `coursework_serve.py` from
   README.md. Open localhost:8001 → the unified home assessment dashboard.
   Existing independent views remain available through navigation and shortcuts.
3. Select OFFLINE_EVIDENCE and an evidence selection, press **Run Full Assessment**,
   and show its task ID and six role states. LIVE_LAB is selectable but blocked
   without separate authorization. Show the compact findings, verification,
   limitations, workload and CQI summary, then open detailed messages/logs.
   Native/ZAP/Behavioral produce distinct evidence; Verification consumes all
   three message IDs; Quality depends on its verification result.
4. Expand the JSON messages and real invocation trace. Show 12 calls, actual
   file/database source references and hash checks. No hosted LLM was called.
5. Show the partial temporal verification findings. Native has no asserted
   collection time; ZAP is real but unpaired. Do not describe it as a fresh scan.
6. Show the final versioned CQI D1–D6 and comparison PASS against the unchanged
   replay implementation. Explain why ZAP is not double-counted in that score.
7. Show measured shares: Native 16.67%, ZAP 16.67%, Behavioral 25%, Verification
   25%, Quality 16.67%. LLM denominator zero → N/A. Coordinator domain calls zero.
8. Export the task, then show the executed scenario matrix. Missing/conflicted
   evidence, timeout and lab-lock handling are tests of controls, not successful
   cybersecurity assessments. Stop only the coursework foreground process.

## CLI fallback (independent of browser availability)

```bash
cd /mnt/assignment/cyberquality_multiagent
/usr/bin/python3 -I -S scripts/coursework_check.py --preservation --source-proof
timeout 110s .venv-coursework/bin/python -I -B scripts/run_multiagent.py --scenario sqli_run --export
timeout 180s .venv-coursework/bin/python -I -B scripts/validate_multiagent.py
```

Seven genuine scenarios are supported: all accepted attack runs, all accepted
benign runs, complete SQLi, XSS, traversal, brute-force and UNKNOWN-containing
runs. Scenario selection uses saved evidence labels/decisions, not invented
findings. Models are never fitted or tuned by this integration.

For the integrated local monitoring fixtures, run both suites sequentially:

```bash
timeout 200s .venv-coursework/bin/python -I -B scripts/validate_multiagent.py --platform
```

This exercises the original 26 checks plus 12 local integration checks. The real
LiveEngine reads only a synthetic coursework file and produces actual windows,
inference, TreeSHAP and incidents. The five-agent task reuses those committed
records without starting or stopping the monitor. Results explicitly say
TEST_ONLY_LOCAL_FIXTURE. Production authorization is unchanged; no actual shared
lab test or handoff is represented as passed.

Demonstrate independent access separately: Native-only uses the original
restricted posture request; STANDARD/FULL/PASSIVE profiles remain available;
Behavioral Monitoring retains start/stop/status; incidents, Explain, CQI and
reports do not require a full task. Operation POSTs remain locked. A future
authorized LIVE_LAB assessment requires an already-owned coursework monitor and
current matching Native/ZAP posture, captures its bounded journal snapshot, and
rejects unsupported session/time assumptions. See README for snapshot lineage
and remaining authorization prerequisites.

## Final-exam scenario coverage

The executable matrix includes the seven real scenarios and these control cases:
missing evidence, contradictory delivered claims, invalid message schema, tool
failure, actual bounded tool timeout, one bounded retry recovery, retry exhaustion,
all three live-profile locks, workload exhaustion, incomplete/extra input,
CQI inconsistency, idempotency, exclusive runner ownership, interrupted-task
recovery, tool/message limits, invalid artifact hash and exact duplicate claims.
Every scenario has an actual pass/fail outcome and a task trace where a task was
created. Input rejection before task creation has no invented task ID or calls.

## Readiness checklist

- [x] One reproducible five-specialist workflow and final CQI.
- [x] More than five real passing Assignment 4 scenarios.
- [x] More than ten executed final-exam/control scenarios.
- [x] Explicit registry, tool ownership, typed messages, dependencies and shared state.
- [x] Actual attempt counts, separate tool/LLM denominators and 40% workload check.
- [x] Substantive independent verification and truthful partial-evidence results.
- [x] Persistent logs, retries, budgets, idempotency, concurrency and crash controls.
- [x] Existing backend/frontend regression checks and new production build.
- [x] Loopback HTTP integration through the built frontend and actual task API.
- [x] Report/presentation generator using actual execution receipts (7/9 pages).
- [ ] Real browser click-through: no runnable local browser was available; do not claim a browser pass.
- [ ] Any live laboratory capability test: separate explicit authorization and ownership handoff required.
- [ ] LLM-agent-specific rubric interpretation: confirm against the missing formal DOCX. Current agents are deterministic and model-backed, with zero LLM calls.
- [ ] Forcible cancellation of native ML calls: current deadlines are cooperative and discard late results; CLI timeout is the process-level fallback.
- [ ] Rehearse the presentation and answer provenance/partial-data questions.

## Questions to be ready to answer

- Why is this collaboration? One shared task, dependency-bound JSON messages,
  five actual specialist executions, real registered tools and one gated result.
- What does verification add? Independent byte anchors, identity/content checks,
  duplicate/conflict detection, temporal limitations and SQLite cursor integrity.
- Why not include every ZAP alert in the score? That would mix unpaired collection
  periods and change frozen replay semantics; evidence remains visible separately.
- Does 25% prove equal intelligence? No; it measures registered tool attempts,
  not cognitive effort, token use, or internal filesystem operations.
- Why are LLM shares N/A? No LLM was called; dividing zero calls by zero is invalid.
- What is the final result? A versioned historical CQI reanalysis with explicit
  limitations, never an exploit-success claim or attack probability.
