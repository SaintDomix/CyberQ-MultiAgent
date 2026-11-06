# Application architecture

This is a presentation/orchestration layer around accepted research components.
No saved model, feature/adapter configuration, detector cutoff, confidence,
reconciliation, persistence, Fusion coefficients or CQI equation is changed.

```
Accepted Branch1 findings ───────────────────┐
Accepted saved predictions OR v2 SQLite ────┼─ Application adapters/service
Accepted package manifest + locked metrics ─┘          │
                             existing Fusion/CQI assemble()
                                                      │
                                         typed FastAPI application API
                                                      │
                                         React/Vite seven-page frontend
```

The selectively restored M4 primitives, CSS, utilities and launcher come from
checkpoint `a3f9100`. No branch merge or research artifact checkout was used.
New code is in `demo/backend/` and `demo/frontend/`; the research core stays
unchanged. Stable domain entities are Pydantic PostureFinding,
BehaviorObservation, Incident, FusionEvent, Dimension and CQI.

## Evidence sources

- Accepted 40-record posture: `outputs/branch1_m1d_acceptance_lab_run02/findings.json`.
- Package: `outputs/branch2/accepted_behavioral_v2/`; canonical root is checked
  against the accepted identity, and all file/source bindings verify before use.
- Blind benign results and predictions: M5 `blind_benign_test_01/evaluation/`.
- Fresh attack results and predictions: M5 `fresh_attack_holdout_01/`.
- Live runtime: explicitly selected/owned session under `runtime/behavioral_v2/`.

`demo/artifact_sources.json` binds immutable source manifests and posture hashes.
It contains provenance, not duplicate metrics. Changed accepted evidence is an
unavailable/integrity-failed source, never silently accepted as a new snapshot.

GET requests never run inference or research experiments. The service verifies,
normalizes and caches the current Fusion projection by an input-generation
digest. Immutable model metadata is cached using artifact and bound-code stat
fingerprints. Runtime is read in a SQLite read-only transaction; observation and
incident payload hashes, sequences, model/schema identity and episode cursor
consistency are checked. Neither the database nor its JSON projections are
rewritten by presentation. No raw Apache source is read by the API.

Only explicit loopback POST controls can launch the existing accepted-v2 passive
runner. It writes a unique `runtime/behavioral_v2/ui-<uuid>/`; no accepted output
is overwritten. Commands use argument arrays and `shell=False`, with no browser
paths, credentials or arbitrary arguments. Duplicate owned jobs are rejected.
Graceful SIGINT precedes bounded termination fallback. Shutdown stops only the
owned child. Externally managed processes are never killed or claimed running.

The one-generation `/api/application/snapshot` avoids mixing independently
polled domain entities. The frontend polls every 2.5 seconds. No heartbeat is
presented as new evidence. Failed refreshes visibly mark retained UI data stale.

This is a local dissertation product prototype, not an internet-facing,
multi-tenant production service. There is no population-scale performance claim.
