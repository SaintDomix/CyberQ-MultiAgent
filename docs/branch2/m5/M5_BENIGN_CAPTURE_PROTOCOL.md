# Additional genuine-browser capture proposal

No traffic is collected by this document or `plan-benign`. The exact seeded,
non-secret schedule is `outputs/branch2/m5/capture_plan_01/capture_plan.json`.
It proposes 24 fresh sessions (six protocols × four runs) with partitions
reserved before capture: 12 TRAIN / 6 VALIDATION / 6 TEST. Six additional
fresh external sessions are reserved for blind replication after model freeze.
These are coverage quotas, not statistically powered population guarantees.

## Why additional captures are needed

Historical benign captures do contain AJAX, assets, POST, quiz and profile
paths. However no benign window meets the declared >=2 requests/s rapid proxy;
the actual external browser generated74 requests in10seconds. Three B04
administrator runs use HTTP clients without fetching embedded assets. Verified
student/teacher browser action protocols, incorrect-then-successful login, and
role-linked course switching remain unproven. Merely lowering a threshold to
fit the observed session would not remedy this coverage gap.

| Protocol | Four independent sessions each |
| --- | --- |
| P01 | Successful authorized login, dashboard, ordinary navigation, own logout |
| P02 | One incorrect test-account password then successful login, stop on warning |
| P03 | Existing accessible course navigation; switch only if two courses actually exist |
| P04 | Own profile and available quiz information page; no profile edits or quiz submission |
| P05 | Cold-cache dashboard/course loading with normal automatic AJAX/assets |
| P06 | Warm-cache rapid human navigation followed by slow pauses; no synthetic request flood |

Use a real browser, fresh session per run, seeded protocol ordering/pause plan,
120/150/180 seconds per scheduled run. Cache behavior and roles are documented
experimental factors; repetitions are controlled laboratory sessions, not
independent samples of the global Moodle user population. Administrator and
student profiles are proposed; no role/endpoint is silently assumed available.
Unavailable course/quiz/role steps remain excluded with reasons. Keep attack
class semantics and existing v1 partitions unchanged; an expanded future study
needs its own declared split manifest, never ad-hoc random window allocation.

## Commands and secure collection procedure for a later authorized step

```bash
cd /home/saintdomix/dissertation_model
.venv/bin/python -B scripts/run_branch2_m5.py plan-benign --seed 42 --out outputs/branch2/m5/capture_plan_next_01
```

This command is offline and makes zero requests. Before any collection, review
the plan and create a separate approved browser-capture protocol using the
existing server byte-offset capture concepts. Existing M2B traffic-generation
commands are **not** a valid substitute: they do not emulate browser assets.
M5 does not extend the accepted capture coordinator or automatically run a
new workload.

For each future run: record UTC/server offset boundaries and actor pseudonym;
execute the reserved browser sequence with environment/hidden-input test
credentials; record only action/outcome categories in a diary. Never export
HAR files, request bodies, passwords, tokens or cookies. Independently verify
login/role via sanctioned identity/audit evidence. Verify no foreign actor or
MoodleBot contamination; reject and preserve contaminated runs, never filter
them silently. Restrict raw server-log retention locally; derive sanitized
canonical features with byte hashes before source rotation. A capture is not
BENIGN merely because XGB predicts BENIGN.

The existing live engine's `windows.jsonl` plus byte hashes support safe
reconstruction while source bytes remain available. To inspect a newly
approved session without training or automatically relabeling it:

```bash
.venv/bin/python -B scripts/run_branch2_m5.py diagnose --session runtime/demo/APPROVED_NEW_SESSION/live_001 --out outputs/branch2/m5/diagnostic_new_01
```

The path is an explicit placeholder for a later real session; M5 automatically
discovers the latest existing session if `--session` is omitted. Do not use
the October9 diagnostic session as new TRAIN data. Future import requires
manual protocol/audit adjudication, exact bounds, source hashes, contamination
checks and a new Dataset v3 inventory; no automatic relabelling tool is added.

Aim for >=100 nonempty benign VALIDATION windows before resolving a1% empirical
FPR target. If six planned validation sessions yield fewer, record counts and
predeclare extra validation replicates before fitting. Do not manufacture
windows or force continuous traffic to meet the target. A statistical claim
about population FPR needs a separate sample-size/uncertainty analysis.

Blind replication begins only after final candidate configuration is hashed.
The six new external sessions must not guide feature, threshold, model or
persistence choices; retain negative results and require renewed study design
for any subsequent tuning.
