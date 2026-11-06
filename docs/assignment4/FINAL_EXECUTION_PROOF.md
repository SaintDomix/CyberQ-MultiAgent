# Fresh offline execution proof — 6 November 2026

> Historical execution trace, retained for reproducibility. Its stored CQI values
> are not endorsed as validated research findings while calculation/mapping is
> under audit. Its live-access observations describe that run, not current lab
> readiness. See the [current project summary](../../README.md).

Task `ma-7d024c962c8a4acaa40d751cd31c5701` is newly created, OFFLINE_EVIDENCE / attack_replay,
COMPLETED. All five specialists executed in one dependency-coordinated task.
No production workflow, model, scoring or isolation code was changed for this
verification. Instrumentation passively observed Python function entry/return
with `sys.setprofile`; it did not replace tools, functions or model outputs.

Elapsed **52.327151 seconds**, including profiling/persistence
overhead. UTC tool completion timestamps span 2026-11-06T09:39:30.415111+00:00 through
2026-11-06T09:40:22.036183+00:00. Agent wall durations include routing/persistence;
nested function timings overlap and must not be added to tool times.

| Specialist | Agent wall seconds | Registered calls | Share |
| --- | ---: | ---: | ---: |
| native | 0.250580 | 2 | 16.67% |
| zap | 7.389396 | 2 | 16.67% |
| behavioral | 16.937953 | 3 | 25.00% |
| verification | 0.561755 | 3 | 25.00% |
| quality | 26.321175 | 2 | 16.67% |

12 actual registered attempts, all successful; no retries in this run. Maximum
share **25%**, under 40%. Combined and tool-only denominators are 12. LLM-only
calls are zero, denominator zero, shares **N/A**. Coordinator has zero domain
tool calls, five persisted dispatches and final routing. Internal library calls
are not relabelled as registered tools. Tools per specialist: 2/2/3/3/2, all ≤5.

| Registered operation | Seconds | Outcome | Evidence refs |
| --- | ---: | --- | ---: |
| native.read_baseline | 0.030544 | completed | 1 |
| native.map_controls | 0.149542 | completed | 1 |
| zap.read_assessment | 7.017317 | completed | 4 |
| zap.check_profile | 0.230482 | completed | 4 |
| behavior.extract_features | 14.620745 | completed | 17 |
| behavior.infer | 2.041346 | completed | 17 |
| behavior.explain_incidents | 0.019505 | completed | 17 |
| verify.artifacts | 0.122651 | completed | 22 |
| verify.consistency | 0.035041 | completed | 0 |
| verify.journal | 0.016431 | completed | 3 |
| quality.evaluate | 0.045504 | completed | 0 |
| quality.check_result | 26.002562 | completed | 0 |

Zero direct refs on consistency/CQI operations means they consume the dependency
messages and their evidence; they do not claim an additional external artifact.

## Actual computation and cache boundaries

- Native: 40 authentic frozen findings read and mapped anew; no new HTTP posture
  collection. VERSION_BASED and CONFIRMED remain distinct.
- ZAP: authentic saved STANDARD assessment
  `posture-20261105T074340Z-c6f295f4251b`, 56 findings. No new scan. Its unpaired
  temporal scope is supplementary and excluded from this replay's CQI scoring.
- Behavioral: **68 windows**, existing 83-feature reconstruction from preserved
  attack logs; actual **OCSVM scoring and XGBoost probability inference** through
  `Package31.predict`, with native exact **TreeSHAP available for all 68**.
  Existing episode and human-explanation functions executed, yielding 16 incidents.
  This is new inference from historical requests, not live monitoring.
- Saved predictions are also read for selection/record identity and independent
  comparison. Frozen models and explanation reference statistics are loaded,
  never fitted. In-process anchors/ZAP selection and application projections/model
  checks are cached where existing implementations do so. These do not replace
  the freshly observed `behavior.infer` call. Reference replay/quality comparison
  can use precomputed predictions; it is not represented as new inference.
- Verification actually checks hashes against preserved bindings, identity,
  provenance, record consistency, temporal scope and a historical SQLite journal
  opened immutable/read-only. **30 VERIFIED, 2 PARTIAL** outcomes. Native missing
  timestamp and unpaired saved ZAP metadata prevent an unqualified VERIFIED result.
  Retained journal corroboration is not scored or called an active monitor.
- Quality calls the unchanged `cqi_v2.evaluate`, followed by independent existing
  application replay comparison. Final status **PARTIAL_EVIDENCE**, verification
  **PARTIAL**. Successful orchestration does not imply secure Moodle or complete
  evidence. No new training, traffic collection, scan or confirmed exploitation.

Observed function entries inside registered tools (not synthetic tool counts):

| Registered tool | Existing function | Actual entries |
| --- | --- | ---: |
| behavior.explain_incidents | episodes | 1 |
| behavior.explain_incidents | human_explain | 1 |
| behavior.extract_features | Application.replay | 1 |
| behavior.extract_features | episodes | 1 |
| behavior.extract_features | features31.extract | 68 |
| behavior.infer | Booster.predict | 8 |
| behavior.infer | OneClassSVM.score_samples | 1 |
| behavior.infer | Package.shap | 1 |
| behavior.infer | Package31.predict | 1 |
| behavior.infer | XGBClassifier.predict_proba | 1 |
| quality.check_result | Application.replay | 1 |
| quality.check_result | cqi_v2.evaluate | 1 |
| quality.check_result | episodes | 1 |
| quality.check_result | features31.extract | 68 |
| quality.check_result | human_explain | 68 |
| quality.evaluate | cqi_v2.evaluate | 1 |
| verify.journal | read_journal | 1 |

## Final existing CQI

Overall **0.092709191499/100**, policy `cqi-evidence-2.0`;
conditional overall **21.5625**, observability coverage
**0.517495**. Conservative coverage-bound semantics
are unchanged; this score is not an attack probability.

| Dimension | Score | Status |
| --- | ---: | --- |
| D1 | 0.2322670146489691 | PARTIAL_EVIDENCE |
| D2 | 2.3841857910156247e-05 | PARTIAL_EVIDENCE |
| D3 | 0.002273067418094942 | PARTIAL_EVIDENCE |
| D4 | 69.49591099211686 | PARTIAL_EVIDENCE |
| D5 | 0.4645340292979378 | PARTIAL_EVIDENCE |
| D6 | 1.5625000000000007 | SCORED |

## Durable proof and reproducibility

Coursework-only storage:

- `runtime/coursework/multiagent/tasks.sqlite3`: persisted task, **11
  JSON messages**, **48 timestamped/hash-chained events**. Operation names,
  attempt IDs, timings, outcomes and exact evidence references are in the export.
- `runtime/coursework/final_bounded/ma-7d024c962c8a4acaa40d751cd31c5701/proof.json`: observed calls,
  durations, summaries and distribution.
- Same directory, `task-export.json`: actual persisted public state and events.
- `runtime/coursework/final_bounded/prove_execution.py`: passive proof driver;
  repeat from the coursework root with
  `.venv-coursework/bin/python -I -B runtime/coursework/final_bounded/prove_execution.py`.
  Each invocation creates another genuine task; timings vary with caches/profiling.

Relevant checks executed after presentation edits: **38/38** multi-agent/platform
checks (including seven real historical scenarios and explicitly labelled failure
handling/local live fixtures), **72/72** Node/React checks. Failure-handling passes
are not successful security assessments. The existing offline backend suite also
passed **170 tests, 3 intentionally deselected**, in **14.59 seconds**. The excluded
tests require locked worker starts or a prohibited symlink; isolation was not
relaxed to admit them. Synthetic extraction produced 83 features and exact SHAP
additivity error was about 1.43e-6. Production Vite build passed; no browser
executable was available, so interactive browser validation was **NOT TESTED**.
New assets are selected on coursework server restart, not by changing an already
running server's selected static directory.

Commands:

```bash
cd /mnt/assignment/cyberquality_multiagent
.venv-coursework/bin/python -I -B scripts/validate_multiagent.py --platform
.venv-coursework/bin/python -I -B scripts/export_multiagent_fixture.py
/usr/bin/python3 -I -S scripts/check_coursework_frontend.py
.venv-coursework/lib/python3.10/site-packages/playwright/driver/node demo/frontend/scripts/build_coursework.mjs
/usr/bin/python3 -I -S scripts/coursework_check.py --preservation --source-proof
/usr/bin/python3 -I -S scripts/assignment4_safety.py
```

Live operations remain BLOCKED. See [operator guide](LIVE_LAB_OPERATOR_GUIDE.md)
for existing commands, prerequisites, missing configuration and handoff blockers.

Final preservation/source-proof and Assignment 4 safety checks passed: 2,801 copied
artifact files unchanged, 1,792 original protected artifact hashes matched,
original commit/tag/status unchanged, no Git remotes, `/dev/sdb`, 23 symlinks
checked, live lock intact. Read-only host observation still found original PID
415036 and the same loopback 8000 socket inode 3323673; no service was signaled.

Exact source/document edits in this bounded task (all under coursework):

- `demo/frontend/src/components/MultiAgent.jsx`
- `demo/frontend/src/styles/index.css`
- `README.md` (two documentation links)
- `docs/assignment4/FINAL_EXECUTION_PROOF.md`
- `docs/assignment4/LIVE_LAB_OPERATOR_GUIDE.md`

Generated proof, task records, test receipts, UI fixture/cache and versioned build
are confined to `runtime/coursework`. No production Python, isolation safeguard,
research artifact or dependency was edited. Git is still unborn/untracked, so
an empty ordinary `git diff` is not proof; the pre-task hash comparison confirms
the two presentation source edits and unchanged existing backend/guard files.
