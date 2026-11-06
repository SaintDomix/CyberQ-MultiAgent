# Dataset v2 next authorized capture plan — proposed, not executed

Existing counts come from provisional_existing_01 inventory/sufficiency JSON.
No planned run is counted as a captured run. S03 is a provisional reconstructed
burst class because protocol/source disagree; archive the conflict, and resolve
future scenario names explicitly. If that reconstruction is rejected, burst needs
10 new runs rather than eight; retain S03 for unlabeled/exploratory analysis.

| Class | Existing independent runs | Existing windows | Provisional XGB | Final collection target | Additional runs |
|---|---:|---:|---|---:|---:|
| BENIGN | 7 | 58 | eligible, weak | 12 | 5 |
| BRUTE_FORCE | 3 | 6 | eligible, very weak | 10 | 7 |
| ENUMERATION_RECONNAISSANCE | 2 | 4 | insufficient | 10 | 8 |
| ADMIN_PROBING | 0 | 0 | unavailable | 10 | 10 |
| REQUEST_BURST_DOS_LIKE | 2 | 4 | insufficient; reconstructed | 10 | 8 |
| SQLI_ATTEMPT | 0 | 0 | unavailable | 10 | 10 |
| XSS_ATTEMPT | 0 | 0 | unavailable | 10 | 10 |
| PATH_TRAVERSAL_ATTEMPT | 0 | 0 | unavailable | 10 | 10 |

68 additional independent runs for these planning targets. A minimum provisional
extension needs one enumeration run, one burst run, and three runs per absent
class (14 runs total); that minimum is not a defensible final eight-class evaluation.

## Planned run IDs and scenarios

- BENIGN: B02-run03, B03-run03, B04-run01–03. B01 already has three runs;
  B04 normal administrator navigation adds missing benign privileged-path coverage.
- BRUTE_FORCE: S01-run04–10, controlled unsuccessful authentication attempts.
- Enumeration: S02-run03–10, mixed content/path reconnaissance; keep distinct
  from specifically privileged-resource probes.
- Burst: S03-run03–10, clearly renamed/described as request burst in the new
  per-run manifest. If preserving old S03 protocol causes ambiguity, assign a new
  distinct scenario ID and retain the same class with explicit basis.
- ADMIN_PROBING: AP01-run01–10, read-only privileged-resource probing with
  authorized identities; no reliance on 200 as evidence of successful access.
- SQLI_ATTEMPT: SQ01-run01–10, bounded inert quote/syntax/query probes on a
  separately reviewed read-only authorized lab interface. Observe URLs, not POST bodies.
- XSS_ATTEMPT: XS01-run01–10, inert encoded delimiter/reflection-style URL markers;
  no script execution or stored mutation.
- Traversal: PT01-run01–10, bounded traversal-like URL input to a disposable
  lab interface; no secrets/filesystem extraction or internal-network targets.

Only add new label mappings after actual capture/source manifests establish what
was performed. No future dataset examples or labels are currently generated.
The current builder accepts explicit scenario mappings, so these new IDs require
an extended reviewed manifest before rebuilding. Do not silently repurpose S02
windows as a new labelled class.

## Independent-run protocol

Each new run: planned 180-second capture, actual UTC start/end from capture process,
a fresh authorized browser/test session, distinct run ID, no overlapping capture,
no background scanner/automation, retained access/error logs and SHA-256 hashes.
Collect runs across at least three days and multiple authorized test identities
where possible; record actual actor pseudonym, session-bootstrap reference (no
cookie), platform/deployment version, scenario script/config hash, intended label,
actual actions/time ranges, request counts/rates and stop conditions. Missing actor
identity in Apache still remains absent in canonical events; manifest actor is
experimental metadata, not log-observed authentication.

Balance benign and suspicious environments, duration, clients/user-agents and
normal resource mix. Include legitimate login/quiz/admin peaks, API/AJAX activity
and normal query syntax; otherwise models may learn script/tool artefacts rather
than security behavior. Ten independent runs per attack class is a capture goal,
not proof of power. Final protocol should lock a run manifest and evaluation split
before model fitting, keep untouched test runs, and evaluate scenario/day/actor
robustness separately from this provisional run holdout. Do not tune using final test.

Active laboratory actions require separate authorization and source-supported
read-only endpoints. No new traffic generator is implemented or invoked here.
Authentication tests must use dedicated/fictitious test identities, no brute force
against real accounts. Burst means a controlled change in request density, **not**
DoS: use a reviewed finite request/rate/concurrency budget with abort thresholds;
if a useful signal cannot be collected safely, leave the class insufficient.
Exact action URLs and budgets must be reviewed before execution; they are not
invented from intended class names. SQL/XSS/traversal target availability remains
a capture prerequisite. Capturing harmless ignored URL indicators establishes an
attempt-pattern dataset, not successful exploitation.

The existing capture helper may be reused only after checking new output filenames;
it is preserved unchanged and can overwrite a same-named raw log. For example,
**later**, in the authorized lab, after confirming neither B04-run01 raw file exists:

```bash
scripts/capture_experiment.sh B04 benign 01 180
```

This is a proposed capture step, not a command executed in Milestone 2A. Perform
normal authorized administrator navigation during the capture. Do not use the
old burst/password generator without separately reviewing authorization/bounds.
Inspect actual manifests/logs afterward; capture durations and action intervals
must be recorded as observed, never filled with planned timestamps.
