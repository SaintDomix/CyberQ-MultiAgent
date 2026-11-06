# Evidence verification and score semantics

The Verification Agent is a separate dependency gate, not aggregation. It runs
after all three evidence specialists and before Quality. Its outcomes are
`VERIFIED`, `PARTIAL`, `CONFLICTED`, `MISSING`, or `INVALID`; these are verification
statuses, separate from existing finding confirmation statuses such as
`CONFIRMED`, `VERSION_BASED`, `NOT_CONFIRMED`, and `FALSE_POSITIVE`.

| Check | Independent work | Failure effect |
| --- | --- | --- |
| Availability/confinement | Resolve server-selected paths inside coursework; check actual files | MISSING/INVALID; no final CQI |
| Provenance/identity | Compare current SHA-256, producer-read SHA-256, expected SHA-256 and original preservation inventory | INVALID; no final CQI |
| Accepted model | Existing package/source/schema/origin verifier | Failure; no model loading success invented |
| Delivered Native and ZAP content | Compare records against hash-bound source content and saved assessment identifiers | CONFLICTED; no final CQI |
| Identity/status/time | Evidence IDs, allowed confirmation statuses, start/end ordering, observation IDs, schema, model ID and training=False | INVALID/CONFLICTED |
| Duplicates/contradictions | Same evidence ID + identical content distinguished from same ID + conflicting content | Explicit outcome/reason; conflicting content rejected |
| Feature/inference consistency | Existing 83-feature matrix validation and actual re-inference compared to preserved predictions | INVALID/CONFLICTED; no final CQI |
| Incident relationships | Every member observation must belong to the delivered prediction set | INVALID |
| Temporal coherence | Inspect available timestamps; report missing Native collection time, historical age and unpaired ZAP evidence | PARTIAL; historical replay only |
| Independent SQLite journal | Existing immutable reader validates record hashes, sequence, model/schema IDs and incident projection cursor | INVALID/MISSING; no final CQI |

SHA-256 values are computed from actual bytes and compared with preserved
anchors. A newly generated reference ID identifies this integration's reference;
it is not represented as an original source identity. Actual source IDs are
preserved separately. No absent evidence timestamp is filled with mtime or task
time. Task/event timestamps reflect actual execution, not evidence collection.

The local hash chain detects accidental audit corruption. It is not a signed
external attestation against an attacker who can rewrite the entire workspace.
No original data is changed to demonstrate a failure. Fault scenarios alter only
delivered in-memory claims or test adapters, are labelled synthetic in the matrix,
and retain actual failed invocations. They are never new vulnerability findings.

## Why normal verification is PARTIAL

The preserved Native research baseline has no asserted collection timestamp.
Saved ZAP assessments and the accepted behavioral holdout are genuine but belong
to different collection periods. Differences in a named control across those
sources are contextual, not proof of a simultaneous contradiction or remediation.
Saved evidence is stale for current-live assertions, while remaining useful for
an explicitly declared historical replay.

The normal outcome therefore contains VERIFIED integrity/identity checks and
PARTIAL temporal checks. These limitations materially constrain Quality:

1. Any MISSING, INVALID or CONFLICTED verification result prevents a final CQI.
2. PARTIAL temporal provenance permits only historical research reanalysis.
3. The CQI uses the Native baseline and freshly re-inferred accepted behavioral
   rows with the unchanged existing `cqi-evidence-2.0` replay policy.
4. Unpaired ZAP findings remain visible supplementary evidence. They are not
   merged into that frozen replay score or counted twice.
5. The existing replay implementation's policy clock is preserved explicitly.
   It is not an assertion that Native evidence was collected at that time.
6. Quality independently compares the overall and six dimension scores against
   the existing application replay calculation. A changed/mismatched score fails.

The SQLite journal corroborates model/schema and persisted-record integrity; it
is not silently substituted for the behavioral run being assessed. A passing
failure-handling test is a successful control test, not a successful assessment.

## Live architecture remains protected

All existing Native, Apache monitoring, ZAP PASSIVE_BASELINE/STANDARD/
FULL_AUTHORIZED implementations and their safety gates are preserved. The new
multi-agent endpoint does not authorize or dispatch live adapters. Requesting any
live profile yields BLOCKED before a registered tool call. Existing operational
POST endpoints remain HTTP 423 under the coursework launcher.

There was no live handoff, new scan, Apache log consumption, session reset, SSH,
service stop or system configuration change. The future user-controlled handoff
is defined in COURSEWORK_ISOLATION.md. A coursework-only lock cannot compel the
unchanged original application to cooperate; no live exclusivity is claimed.
