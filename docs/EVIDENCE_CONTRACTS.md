# Milestone 1A: canonical evidence contracts

Schema version: `1.0`. Package: `src/evidence_contracts`. Standard library only.
This milestone normalizes saved evidence offline. It does not collect evidence,
reassess historical checks, implement fusion/scoring, or change behavioral models.

## Separate concepts

- `check_result`: PASS, FAIL, PARTIAL, NOT_APPLICABLE, NOT_TESTED, ERROR,
  DISMISSED. Unknown results are null. A role's HTTP status is evidence only.
- `confirmation_status`: CONFIRMED, VERSION_BASED, LIKELY, CONTEXTUAL,
  NOT_CONFIRMED, NOT_APPLICABLE, NOT_TESTED and FALSE_POSITIVE. Unknown is null,
  distinct from NOT_TESTED and NOT_CONFIRMED.
- `severity`: INFO, LOW, MEDIUM, HIGH, CRITICAL, or null.
- `confidence`: optional `{value, label, method}`; value is a finite evidence-
  confidence estimate in [0, 1]. No estimate is inferred from legacy tokens.
- `provenance`: source-relative path, source-file SHA-256, zero-based record
  index, canonical-record SHA-256, source record ID, adapter/version, mapping notes.

`SecurityFinding` is Branch 1; `BehavioralSecurityEvent` is Branch 2. Shared
fields include asset/component, source, category/type, observation/expectation,
root cause, evidence, explanation, recommendation, optional UTC interval, and
the complete `raw_record`. They support `to_dict`, `to_json`, `from_dict`,
`from_json`; `evidence_from_dict` dispatches using `record_type`.

The event contract separates anomaly assessment, raw anomaly score, 0–100
anomaly severity, threat class, 0–1 threat probability, evidence confidence,
model reference, feature-schema version, and optional features. It does not
populate these fields or impose a new attack taxonomy on existing models.

## Baseline mappings

| Source | Mapping |
|---|---|
| External MVP | Original status → check result; original severity retained; indicator → finding type; reason → explanation; explicit evidence URL → asset only when the entire field is a URL |
| Deep v2 | Same status/severity/type mapping; observed/context retained as structured evidence; missing expected value/asset remain null |
| Role review v3 | DISMISSED_LIKELY_GENERIC → DISMISSED + FALSE_POSITIVE; review candidates → PARTIAL + NOT_CONFIRMED; HTTP status/link comparisons/snapshot path retained as evidence |

Legacy `confidence` contains confirmation/evidence-semantic tokens, not measured
confidence. `VERSION-BASED` becomes VERSION_BASED; known ADV-/PATCH- version checks
also remain VERSION_BASED even if an inconsistent source token says CONFIRMED.
HEURISTIC becomes NOT_CONFIRMED. CONFIRMED preserves a source observation claim,
including PASS/PARTIAL observations; it is not a new assertion of exploitation.
NOT_APPLICABLE/NOT_TESTED/error results carry their respective applicability or
testing semantics. Unknown tokens remain raw and generate mapping notes.

FALSE_POSITIVE means the role-access candidate was dismissed by that historical
heuristic; it does not establish that all access control is correct. No severity,
confidence, recommendation, or root cause is invented for that record.

All baseline confidence estimates, components, root causes and collection times
remain null. No collection time is inferred from file modification times. The
deep observed string `"None"` remains a source string; normalization does not
silently reinterpret it as a missing JSON value. Context and source-specific
role fields remain available without being converted to scoring inputs. Historical
snapshot paths are retained verbatim, not assumed to resolve on this machine.
Raw payloads can contain historical cookie values; these local audit artifacts
are not sanitized publication reports.

Milestone 1C uses the existing SecurityFinding contract for linked active
observations. `evidence.parent_finding_id` and `evidence.parent_evidence_id` link
the unchanged parent; validation outcomes and request indices stay in evidence.
The parent confirmation status is never overwritten. Unexecuted plans and
unsupported checks are NOT_TESTED results, not new canonical vulnerability
observations. Attempted validation errors and negative checks are explicit
linked evidence. Active-enabled report copies redact secrets and add a provenance
note explaining that parent IDs/source hashes refer to original retained sources,
not the redacted representation. Active observations reference an exact sanitized
request-transcript artifact hash. See `BRANCH1_PIPELINE.md` for controls and CLI.

Milestone 1D preserves schema 1.0 and adds no confirmation statuses. Planner
MISSING_CONTEXT is an applicability state, distinct from canonical NOT_TESTED.
SQLi parser differentials and potentially unsafe reflection remain LIKELY;
raw reflection and SSRF prerequisites are CONTEXTUAL. Confirmed account-response
distinctions and effective cookie attributes describe only their measured
predicates. Linked results include applicability, missing prerequisites,
authentication requirement, validator version and bounded response characteristics.
Request-free completed SSRF assessments link to the empty sanitized transcript
and retain explicit feature-context references, without claiming HTTP testing.
Ephemeral runtime inputs enrich a temporary parent copy; parent IDs/provenance
remain unchanged. See BRANCH1_PIPELINE.md for context fields and limitations.

## Identity and future fusion

`finding_id` preserves the source finding/check ID where available. `evidence_id`
is the global observation key: SHA-256 over canonical JSON of schema version,
source name, repository-relative source path, and the complete source record.
Role records without a source ID use that deterministic key as finding_id.
Dictionary order, absolute checkout location, unrelated source records and record
ordering do not change the ID. Changed payloads or source-relative paths do.
Exact duplicate source observations are rejected during baseline export rather
than silently removed. Identity is not a root-cause key: fusion must not merge
findings solely by finding_id, category, or ID digest. Root cause remains null
until supported by a later explicit correlation/deduplication method.

## Reproduction and preservation

```bash
.venv/bin/python -B -m unittest discover -s tests -v
.venv/bin/python -B scripts/normalize_baseline_evidence.py
```

Outputs: `outputs/normalized_baseline/findings.json`, `findings.csv`, and
`normalization_summary.json`. JSON is authoritative; nested CSV cells contain
JSON and null scalar CSV cells are blank. Summary counts include passes and
dismissed candidates and must not be called vulnerability counts.

The CLI reads the three declared source JSON files only and performs no network
requests. `--project` selects a checkout; `--out` must be below its outputs
directory and outside preserved historical output directories. Identical repeat
exports are accepted without rewriting files. Different existing artifacts are
never overwritten: use a new output directory. Symlink output files are rejected.
