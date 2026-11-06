# LIVE observation explainability — Task 2A.1

## Diagnosis

The running product returned the legacy explanation payload: `shap`,
`robust_deviations`, reconciliation reason and non-causal semantics, without
Task 2A's structured anomaly/classification interpretation. All seven current
LIVE journal records already retained their original 83-feature inference
vectors and SHAP. A fresh projection using the source tree could explain them
before this patch. Missing feature collection or missing SHAP was therefore
not the cause of the observed product fallback; the loaded backend needed a
reload while retaining the selected journal.

The fallback now identifies `LEGACY_API_EXPLANATION_PAYLOAD` and recommends
reloading that backend, rather than implying that all technical evidence is
missing. Genuine resolver failures have specific reason codes.

## Production path

The existing live engine persists `window.row.features` with its prediction in
the journal. The application reads that journal in a read-only SQLite
transaction, verifies each payload SHA256 and accepted package/schema identity,
and resolves this retained inference vector. The resolver checks window,
observation, source and actor identities, exact feature membership, finite
numeric values and consistency with retained numeric deviations.

It adds a canonical vector SHA256, original journal payload SHA256, package
root/schema identity and `recomputed=false`. No feature extraction or model
inference is invoked by this resolver. Numeric evidence goes to the unchanged
Task 2A explanation engine and its existing benign TRAIN reference. The same
observation API and application snapshot consumed by the frontend expose the
structured explanation. Private resolver transport fields are removed before
prediction grouping and Fusion input construction.

Failure codes include `FEATURE_VECTOR_NOT_RETAINED`,
`FEATURE_VECTOR_SCHEMA_MISMATCH`, `FEATURE_VECTOR_IDENTITY_MISMATCH`,
`FEATURE_VECTOR_INCOMPLETE`, `FEATURE_VECTOR_NONFINITE_OR_INVALID` and
`FEATURE_VECTOR_PREDICTION_MISMATCH`. A genuinely absent vector may degrade to
explicitly partial saved robust deviations. A mismatched vector is rejected for
interpretation. Neither case changes the saved prediction or incident.

## Presentation and privacy

The existing drawer presents observed values, benign TRAIN medians, comparison,
direction and signed selected-class margin contributions when available.
Technical details preserve the exact numeric vector, reference statistics,
saved SHAP, package identity and structural provenance. Raw payloads, cookies,
tokens, query values and bodies are not added to explanation evidence.

OCSVM explains novelty only. XGBoost scores remain uncalibrated class scores.
An UNKNOWN_ANOMALY can show its raw highest-scoring SQLI_ATTEMPT class without
asserting a known attempt when the frozen reconciliation threshold is not met.
Missing SHAP does not disable feature/reference interpretation and is stated
explicitly inside LIVE technical details. Associated deviations and SHAP are
interpretation aids, not causal or successful-exploitation evidence.

## Actual product acceptance

Evidence directory: `outputs/explainability/task2a1_live_01/`.

- Existing selected LIVE journal:
  `runtime/behavioral_v2/ui-b76d7b3c052d469cb08e4b2b43121cc3`.
- All seven API observations match their original saved 83-feature vectors and
  journal hashes. All prediction fields outside explanation remain unchanged.
- Actual loopback dashboard drawers passed for the BENIGN observation
  `2f79153944e9c5010c44b8af0bbed91d0b24db0255a64a7044a659f920dab7d8`
  and UNKNOWN_ANOMALY observation
  `fe96f21029e2a529dbf2354e85b4641c7979a87f75fccc43eb939a40b6babee3`.
- BENIGN: five non-asset requests versus benign median six; zero 4xx share;
  three parent paths versus five. OCSVM NORMAL, XGBoost BENIGN.
- UNKNOWN: 50% redirects versus zero median; navigation share 100% versus
  12.5%; mean request gap 0.8889 s versus 0.09091 s; five comment-like query
  sequences versus zero. OCSVM ANOMALOUS; raw XGBoost SQLI_ATTEMPT score
  0.7703124881 is below the unchanged 0.8 threshold.
- Both selected records have saved SHAP. No confidently reconciled known
  attack exists in this current stream; none was manufactured.
- Exact pre-task adapter versus actual API equality holds for all 101 accepted
  replay observations, 16 replay incidents and the one current LIVE incident.

The stream above is existing real LIVE evidence, not accepted replay. Its
monitor had intentionally stopped and remains stopped. The UI continues to
identify retained telemetry rather than claiming a running live process.
Browser checks permit only loopback GET/HEAD requests and generate no target
traffic. Harness corrections addressed API ordering and CSP-compatible waits;
neither changed product predictions or weakened browser CSP.

## Operation and verification

An explicit read-only retained-session restart is available when reloading
backend code without creating a new monitoring session:

```sh
./scripts/stop_demo.sh
./scripts/start_demo.sh --mode LIVE_LAB \
  --retained-session runtime/behavioral_v2/ui-b76d7b3c052d469cb08e4b2b43121cc3
```

The path must identify a valid accepted v2 journal under
`runtime/behavioral_v2`. This option never starts/adopts a monitor. Normal
startup without the option retains its existing behavior.

The API acceptance script refuses to overwrite its output directory:

```sh
PYTHONPATH=src:. .venv/bin/python -B scripts/accept_live_explainability.py \
  --out outputs/explainability/another_fresh_receipt
```

For render checks against the saved real API-shaped receipt:

```sh
cd demo/frontend
LIVE_EXPLANATION_PAYLOAD=../../outputs/explainability/task2a1_live_01/live_api_payload.json \
  npm run test:live-explainability
```

Verification: 20 focused tests; 166 total relevant Python regressions including
those 20; 57 existing frontend tests; five real API payload render checks;
production frontend build; actual browser drawers; protected-artifact hashes.
The accepted engine, feature catalog, benign reference, models, thresholds,
persistence, CQI and scanner profiles are unchanged.
