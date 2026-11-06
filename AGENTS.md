# Dissertation Repository Rules

Project:
AI-Based Model for Analysis and Evaluation of Cybersecurity Quality
in Adaptive Educational Platforms.

Primary experimental platform:
local/authorized Moodle laboratory.

Source of truth:
 /home/saintdomix/dissertation_model

Kali is a security-testing worker, not the source-of-truth repository.

## Preservation

- `legacy/` is reference material. Do not delete or silently rewrite it.
- Never delete raw logs, experiment metadata, baseline evidence, saved models
  or previous outputs without explicit approval.
- Never fabricate findings, labels, vulnerabilities, metrics or experiments.
- Every reported result must come from an actual reproducible run.
- Prefer integrating verified working code over rewriting it from scratch.

## Security Testing

Active testing is permitted ONLY against the local laboratory or an explicitly
authorized copy of the system.

Default active-validation behavior must be:
- scoped;
- non-destructive;
- reproducible;
- evidence-producing.

Do not perform destructive exploitation, persistence, uncontrolled stress
testing or denial-of-service testing.

## Finding Semantics

Keep these statuses distinct:

- CONFIRMED
- VERSION_BASED
- LIKELY
- CONTEXTUAL
- NOT_CONFIRMED
- NOT_APPLICABLE
- NOT_TESTED
- FALSE_POSITIVE

A vulnerable-version match is NOT equivalent to confirmed exploitation.

## Behavioral ML Methodology

- Prevent train/test leakage.
- Split data by complete experimental runs, not random windows from the same run.
- Isolation Forest is trained on benign traffic only.
- Controlled attack labels are used for evaluation and supervised classifiers.
- Preserve random seeds and experiment configurations.
- Do not tune parameters solely to make the final test metrics look better.
- Clearly distinguish anomaly severity from attack probability.

## Architecture

Read before major work:

- `docs/CURRENT_BASELINE.md`
- `docs/PROJECT_SCOPE.md`
- `docs/IMPLEMENTATION_PLAN.md`

Do not silently change:
- architecture;
- feature schema;
- attack taxonomy;
- scoring methodology;
- train/test protocol;
- evidence status semantics.

If a material design decision changes, update the corresponding documentation.

## Development Workflow

Before major changes:
1. inspect existing code;
2. identify the working implementation;
3. preserve useful behavior;
4. state what will be changed.

After changes:
1. run tests or a reproducible experiment;
2. inspect actual outputs;
3. inspect `git diff`;
4. report exactly what works and what remains incomplete.

The objective is a defensible research system with correct results,
not artificially perfect metrics.
