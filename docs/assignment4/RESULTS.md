# Actual results and workload report

Primary localhost task: `ma-b13d670f88e3480aaf257f74f873f4bf`.

This task actually executed all five specialists. It completed historical reanalysis with partial temporal provenance; it is not a fresh cybersecurity assessment.

## Executed checks

| Check | Actual outcome |
| --- | --- |
| Genuine Assignment 4 scenarios | 7 passed |
| Multi-agent scenario/control checks | 26 passed, 0 failed |
| Existing backend regression checks | 170 passed, 3 intentionally deselected |
| Frontend unit and React server-render checks | 70 passed |
| New production build and loopback HTTP task | PASS; actual five-specialist task, built JS/CSS, schema rejection, locked live request |
| Browser click-through | NOT TESTED: no runnable local browser |
| Shared lab live capabilities | BLOCKED; not executed |

## Actual call distribution

| Role | Tool attempts | Tool share | LLM calls | LLM share |
| --- | ---: | ---: | ---: | --- |
| native | 2 | 16.67% | 0 | N/A |
| zap | 2 | 16.67% | 0 | N/A |
| behavioral | 3 | 25.00% | 0 | N/A |
| verification | 3 | 25.00% | 0 | N/A |
| quality | 2 | 16.67% | 0 | N/A |
| Coordinator | 0 | 0% of domain calls | 0 | N/A |

Denominators: 12 specialist tool attempts, 0 LLM calls. Maximum normal share is 25%; all five roles satisfy the stated 40% threshold. Coordinator dispatches are orchestration messages, not fabricated LLM/tool calls. Failed/retried attempts are counted on entry. Internal helper calls, SQL queries and audit persistence do not inflate the registered-tool denominator.

The controlled transient recovery task made 13 attempts (one real failed adapter invocation plus a retry). The exhausted-step test openly reports a 100% partial-run Native share and no final assessment; this is not hidden or averaged into normal-task compliance.

Actual overall historical CQI: `0.17002940689377427` under `cqi-evidence-2.0`. Six dimensions match the unchanged existing replay implementation. This numeric result is derived from the selected genuine run, not a hardcoded UI success. It is not an attack probability.

## Detailed executed scenario matrix

| Scenario/check | Test result | Task terminal state | Interpretation |
| --- | --- | --- | --- |
| `test_real_five_specialist_workflow[sqli_run]` | passed | COMPLETED | ACTUAL_HISTORICAL_REANALYSIS |
| `test_real_five_specialist_workflow[xss_run]` | passed | COMPLETED | ACTUAL_HISTORICAL_REANALYSIS |
| `test_real_five_specialist_workflow[traversal_run]` | passed | COMPLETED | ACTUAL_HISTORICAL_REANALYSIS |
| `test_real_five_specialist_workflow[bruteforce_run]` | passed | COMPLETED | ACTUAL_HISTORICAL_REANALYSIS |
| `test_real_five_specialist_workflow[benign_replay]` | passed | COMPLETED | ACTUAL_HISTORICAL_REANALYSIS |
| `test_real_five_specialist_workflow[attack_replay]` | passed | COMPLETED | ACTUAL_HISTORICAL_REANALYSIS |
| `test_real_five_specialist_workflow[unknown_run]` | passed | COMPLETED | ACTUAL_HISTORICAL_REANALYSIS |
| `test_missing_evidence_is_not_success` | passed | FAILED | SYNTHETIC_MISSING_REFERENCE_HANDLING |
| `test_conflicting_delivered_evidence_is_not_success` | passed | FAILED | SYNTHETIC_CONFLICTING_MESSAGE_HANDLING |
| `test_invalid_message_schema_is_terminal` | passed | FAILED | SYNTHETIC_INVALID_MESSAGE_HANDLING |
| `test_tool_failure_is_logged_and_terminal` | passed | FAILED | SYNTHETIC_TOOL_FAILURE_HANDLING |
| `test_actual_tool_timeout_discards_late_result` | passed | TIMED_OUT | CONTROLLED_REAL_TIME_TIMEOUT_HANDLING |
| `test_retry_recovers_and_counts_failed_attempt` | passed | COMPLETED | CONTROLLED_RETRY_RECOVERY_WITH_REAL_REANALYSIS |
| `test_retry_exhaustion_is_bounded` | passed | FAILED | CONTROLLED_RETRY_EXHAUSTION_HANDLING |
| `test_laboratory_lock_is_never_bypassed[PASSIVE_BASELINE]` | passed | BLOCKED | ACTUAL_LAB_LOCK_HANDLING |
| `test_laboratory_lock_is_never_bypassed[STANDARD]` | passed | BLOCKED | ACTUAL_LAB_LOCK_HANDLING |
| `test_laboratory_lock_is_never_bypassed[FULL_AUTHORIZED]` | passed | BLOCKED | ACTUAL_LAB_LOCK_HANDLING |
| `test_step_workload_limit_is_enforced_and_distribution_is_not_hidden` | passed | LIMIT_EXCEEDED | ACTUAL_WORKLOAD_LIMIT_HANDLING |
| `test_incomplete_input_and_extra_fields_rejected` | passed | REJECTED_BEFORE_TASK | SCHEMA_REJECTION_NO_ASSESSMENT |
| `test_corrupted_cqi_output_is_rejected` | passed | FAILED | CONTROLLED_CQI_CONSISTENCY_HANDLING |
| `test_idempotency_prevents_duplicate_tool_writes` | passed | COMPLETED | IDEMPOTENCY_WITH_REAL_REANALYSIS |
| `test_exclusive_runner_blocks_another_coordinator` | passed | COMPLETED | EXCLUSIVE_RUNNER_WITH_REAL_REANALYSIS |
| `test_interrupted_state_is_preserved_and_not_resumed` | passed | COMPLETED | INTERRUPTION_RECOVERY_WITH_REAL_REANALYSIS |
| `test_registry_tool_limits_and_message_strictness` | passed | N/A: schema-only | Contract check |
| `test_invalid_artifact_hash_is_explicitly_invalid` | passed | FAILED | CONTROLLED_INVALID_HASH_HANDLING |
| `test_duplicate_delivered_evidence_is_reported` | passed | FAILED | CONTROLLED_DUPLICATE_MESSAGE_HANDLING |

A passed rejection/failure-control check is not a successful security assessment. Every created task keeps its actual invocation audit; pre-task schema rejection has no invented task ID. Fault cases alter delivered memory or test adapters only.

## Safety proof

Original HEAD and tag commit: `95513fc10dd4356352f9bc935ba8bcf63532a04e`.
Original annotated tag object: `938ca9a60585c90660af44a11c6f1d4a43e6e956`.
Original status digest matches the before-task baseline. 2801 copied artifact files remain byte-identical; 1792 original research artifact files were independently read-only hashed and match the preserved-copy baseline. No source symlink or Git remote was introduced.
Final read-only host observation still found original Python PID 415036 and the same port 8000 socket inode 3323673, with port 80 also listening. No port 8001 listener remained after the owned HTTP harness stopped its child. No original/shared service action was executed.

The Python boundary confines application writes to coursework state. Setup, source edits and Node tools also stayed inside the authorized coursework project. Existing Vite dependency-cache metadata may be refreshed by legacy rendering tests; generated task state, builds, receipts and materials are ignored by Git. No push, system install or remote configuration occurred.

## Reproducible evidence locations

- Scenario matrix: `runtime/coursework/assignment4/validation-953414d769b943bdbaa51eb6d04947cf/matrix.json`
- Frontend receipt: `runtime/coursework/assignment4/frontend-receipt.json`
- HTTP receipt: `runtime/coursework/http-receipt.json`
- Safety receipt and changed files: `runtime/coursework/assignment4/safety-receipt.json`
- Seven-page report: `runtime/coursework/assignment4/materials/2861f473378c41d3b803b931285d39a4/exam-report.pdf`
- Nine-slide presentation: `runtime/coursework/assignment4/materials/2861f473378c41d3b803b931285d39a4/presentation.pdf`
- Full task, results and editable Markdown: `runtime/coursework/assignment4/materials/2861f473378c41d3b803b931285d39a4/`
- Task state/event source of truth: `runtime/coursework/multiagent/tasks.sqlite3`
- JSON schemas and actual message examples: `schemas.json`, `real-messages.json`

## Existing files changed in this task

- `demo/frontend/scripts/product_render.test.mjs`
- `demo/frontend/src/App.jsx`
- `demo/frontend/src/api/client.js`
- `demo/frontend/src/styles/index.css`
- `demo/frontend/src/utils/product.js`
- `demo/frontend/src/utils/product.test.js`
- `docs/COURSEWORK_ISOLATION.md`
- `scripts/coursework_check.py`
- `scripts/coursework_http_check.py`
- `scripts/coursework_serve.py`

## Added implementation and documentation files

- `README.md`
- `coursework/multiagent/__init__.py`
- `coursework/multiagent/agents.py`
- `coursework/multiagent/api.py`
- `coursework/multiagent/engine.py`
- `coursework/multiagent/models.py`
- `coursework/multiagent/store.py`
- `coursework/multiagent/tools.py`
- `demo/frontend/scripts/build_coursework.mjs`
- `demo/frontend/scripts/multiagent_render.test.mjs`
- `demo/frontend/src/components/MultiAgent.jsx`
- `docs/assignment4/ARCHITECTURE.md`
- `docs/assignment4/DEMONSTRATION.md`
- `docs/assignment4/RESULTS.md`
- `docs/assignment4/VERIFICATION.md`
- `docs/assignment4/real-messages.json`
- `docs/assignment4/schemas.json`
- `scripts/assignment4_safety.py`
- `scripts/build_assignment4_materials.py`
- `scripts/check_coursework_frontend.py`
- `scripts/export_multiagent_fixture.py`
- `scripts/run_multiagent.py`
- `scripts/validate_multiagent.py`
- `tests/test_multiagent.py`

All listed paths are inside `/mnt/assignment/cyberquality_multiagent`. Private generated task databases, test logs, fixtures, cache and versioned frontend/report artifacts are under `runtime/coursework` and are not research-baseline changes.
