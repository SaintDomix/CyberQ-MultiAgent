# Frozen candidate blind BENIGN TEST collection

Candidate `m5-v3.1-b57550611aa11e00b4bb` and all 23 frozen artifacts remain
immutable. No feature, estimator, threshold, preprocessing, confidence or
reconciliation/episode setting may be changed after TEST is opened.

The external wrapper `scripts/run_m5_blind_test_capture.py` adds collection
orchestration only. It does not modify frozen modules or execute inference,
training, evaluation, traffic holdouts, promotion, Fusion or dashboard work.

## Prospective integrity receipt

`prepare` verifies the expected canonical freeze root, artifact hashes, Model v1
core and package hashes, original plan and development dataset/manifest. It
checks the freeze's no-TEST-selection declarations before checking TEST-directory
absence. Any failed check stops before writing a PASS receipt or opening TEST.
The write-once receipt is
`outputs/branch2/m5_final_day/blind_benign_test_01/pre_test_integrity.json`.

Reserved TEST sessions are unchanged: 019 B01, 020 B02, 021 B04, 022 B06,
023 B07, 024 B09 (prefix M5FD-20261014-, role student). No replacement of
an unavailable/failed protocol is permitted. TRAIN/VALIDATION directories are
not opened by collection. Their already-frozen dataset is hashed for integrity.

From the repository directory and credential-bearing operator terminal:

```bash
.venv/bin/python -B scripts/run_m5_blind_test_capture.py collect --authorized
```

The wrapper rechecks integrity and the prospective receipt, collects only these
six sessions using the unchanged browser engine, and independently replays each
COMPLETE capture. Cookies, tokens and credentials remain in memory. Ambient
traffic stays in raw provenance and never enters features. Existing COMPLETE
captures are reverified and skipped; INVALID captures are preserved on explicit
resume. Missing resources are recorded INVALID/unavailable without substituting
navigation. Unexpected new failures stop; repeat the same command only to resume
remaining reservations, never to replace an attempted ID. Partial captures or
failed verification stop safely. No exception secrets are exported.

Each invocation writes a new collection summary beneath `collection_runs/`.
When every reservation has a terminal state, it writes the immutable
`test_evidence_manifest.json` and its SHA256 sidecar. The manifest contains all
reserved states, independent verification, window counts, capture/feature/provenance
hashes, schema and freeze identity. An INVALID capture is never labelled BENIGN.
No model metrics are computed before or after this lock by the collector.

## Prospective benign-only classification

The integrity receipt declares the following reporting policy before outcomes:

- PASS: all six sessions verified; zero false known-attack windows; zero alerted
  benign runs; raw novelty window FPR ≤5%; episode alert rate no worse than v1.
- FAIL: integrity failure (stop without metrics), raw novelty FPR ≥50%, episode
  run alert rate ≥50%, false known-attack window rate ≥10%, or candidate episode
  run alert rate exceeding v1 by at least 1/3.
- MIXED: other evaluable outcomes, including unavailable/INVALID reservations.

These are transparent small-sample reporting criteria, not empirically calibrated
population guarantees or model-selection rules. PASS does not authorize promotion;
fresh controlled attack sensitivity has not been evaluated. No TEST-driven tuning
is permitted, even if the result is poor. This stage stops before evaluation when
credentials are unavailable to the implementation process.
