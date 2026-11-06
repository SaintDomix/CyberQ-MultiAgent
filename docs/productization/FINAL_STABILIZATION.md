# Final product stabilization — candidate, not deployed

4 November 2026. Branch `work/ux-clarity-20261104`.

## Reviewed C2 recovery checkpoint

Exactly 18 reviewed C2 implementation/test/doc files were staged explicitly,
checked against the C2 source hashes, scanned for obvious secrets, inspected
with `git diff --cached --name-status` and checked with
`git diff --cached --check` before the authorized commit:

- `a92b445b602adda70f7bf7ccb9b324d5be94e5fb`
- `checkpoint(ux): preserve C2 candidate before final stabilization`
- Annotated tag `ux-c2-candidate-20261104` (new; no existing tag moved).

Excluded: data, evidence, outputs, runtime/DBs, preview assets, screenshots,
credentials, temporary files and unrelated untracked material. All 18 staged
blobs matched the reviewed receipt. No active custom Git hooks were present.
`pre-ux-20261104`/`backup/pre-ux-20261104` remain at `a6d31a2`;
`ux-phaseb-candidate-20261104` remains at `fe6f4c8`; rejected experiment/stash
remain at `f69aec9`. No merge or push. The later stabilization changes remain
uncommitted and are separately captured by a compact candidate patch/archive.

## Limited cleanup

- `demo/frontend/src/App.jsx`: compact CyberQuality brand; remove repeated
  dissertation/environment/model-verification slogans, duplicate page subtitle
  and global mode badge. Model integrity failure remains prominent. Read-only
  preview state is retained from health even with an explicit legacy fallback.
- `components/AssessmentContext.jsx`: compact shared horizontal context on all
  seven pages, explicit source/profile/time, discoverable Change evidence.
  Replay timestamp is Evidence as of; collected posture uses Collected.
  Selection remains local view state, with no monitoring or mode-transition POST.
  Completeness is not repeated next to a hero that already displays it.
- `src/styles/index.css`: restrained spacing and responsive context; preview
  indicator remains visible at narrow widths. No new libraries or layout concept.
- `utils/evidence.js` and `components/PostureWorkspace.jsx`: failed TLS-001
  display reads **Assessed target uses unencrypted HTTP** only when explicit
  retained evidence supports that statement. An HTTP URL alone is insufficient.
  Original control label HTTPS enabled remains in source evidence and detail.
  Severity HIGH, CONFIRMED, identity, membership, hazard and scoring are unchanged.
- `scripts/browser_ux_c2_acceptance.py`: reuse C2 checks with optional extension,
  candidate-only mode and a bounded assertion wait; fake health explicitly
  identifies fake normal-operation tests. No operational timeout changed.
- New `scripts/browser_final_stabilization.py`,
  `demo/frontend/scripts/stabilization_render.test.mjs`, and
  `tests/test_final_stabilization.py`: targeted presentation/API/control tests.

The original gauge, minimal Overview, seven pages, D1–D6, missing D5/D6,
conditional quality, coverage, conservative result, authorization gates,
profiles, history, metadata recovery, canonical representatives, v1 sensitivity,
single-drawer navigation, incidents, SHAP and benchmark matrices remain.
Research identity remains unchanged; CyberQuality is a product display name.

## API and feature compatibility

| Area | Verification |
|---|---|
| Snapshot/model/system | Typed saved application/product contracts; package verification; partial and unavailable states |
| Current/historical posture | Same selected snapshot supplies findings and CQI; Native/ZAP provenance and source IDs retained; historical D6 unpaired |
| Execution | Six queued/running/terminal state fixtures; owned eligibility; explicit cancel through existing route; duplicate-start rejection |
| Profiles | STANDARD default; FULL_AUTHORIZED authorization validator; restricted PASSIVE target; all three route dispatches tested with fake executor |
| Findings/dedup | Existing Branch 1/Fusion tests; root representative properties remain from one actual member; one canonical contribution |
| Behavior | Paginated observations/episodes; actual saved feature-based explanation and SHAP equality; missing telemetry is not benign proof |
| Monitoring controls | Header gate, start, duplicate rejection and stop tested with in-memory fake; browser buttons use intercepted fake responses |
| CQI | cqi-evidence-2.0 unchanged; v1 distinct; six dimensions/contributors/coverage/method/history/sensitivity reachable |
| Research | Hash-pinned OCSVM/LOF/IF values and eight-class XGBoost matrix remain; no new experiment or fitting |
| Normalization/reports | Generic capability limits/schema; final v2 MD/JSON and historical v1 report routes checked |
| Errors/privacy | Missing records, malformed contract, 503, explicit 404 legacy view, bounded pagination, sanitized domain evidence |

No API/scoring/backend implementation was changed after the C2 checkpoint.
Original model/source evidence is not rewritten for display. Frozen Behavioral
root remains `59a8c7c5d3d51632d0afe45f8cd2fe50570b7af2943d26bb313888327ea9f436`.
The final receipt verifies the 451 protected files and all three existing asset
sets (stable dist, Phase B preview and reviewed C2 preview).

## Tests and evidence

- Focused backend integration + C2: **45 passed**.
- Relevant backend/CQI/Branch 1/normalization/Behavioral/explainability: **522 passed**.
- Existing lifecycle/preflight/ownership tests: **18 passed**.
- Frontend: **102 passed**; isolated production build PASS.
- Focused frontend cleanup + C2: 26 passed after correcting a display-case test.
- `git diff --check`: PASS.
- Final actual browser: **23 check groups PASS**, zero forwarded mutations,
  zero JavaScript errors; fake start/stop/cancel requests were intercepted.
- Actual browser result, screenshots, source/build hashes and exact commands:
  see `outputs/ux/final_stabilization_20261104_06/` and its receipts.

Earlier test failures are retained/reported: the first new backend tests assumed
an obsolete explanation key and omitted a required session field from a fake;
the fake/tests were corrected to the existing schemas, without changing APIs.
A browser attempt timed out on the older Phase B preview; GET checks confirmed
that service remained healthy. A candidate evidence assertion exceeded the
five-second default; test assertions now allow 15 seconds. Another attempt was
interrupted with SIGTERM, so it is not counted as a complete acceptance.
A later browser test assumed the HTTP finding was on page one; it was corrected
to use the actual D1/FAIL filters, then restore all findings. Narrow-screen
review found and fixed a CSS specificity issue hiding the preview marker. A real 768px Posture overflow was also found: its five filter fields did not
wrap until 650px. Their existing layout now wraps below 1000px, without changing
filters or results. No successful real scan/control action is inferred from these tests.

## Runtime isolation and readiness limits

Observed main backend: PID 389143, start ticks 33616072, working directory this
repository, Python 3.10, no reload, LIVE_LAB with explicit retained journal
`runtime/behavioral_v2/ui-e01c26a593174d42bec5d45faf703576`.
Tunnel PID 392381/start ticks 33873908 was inspected, not controlled. Only
non-secret configuration fields and API-key presence were recorded.
Monitoring reports EXTERNALLY_MANAGED_UNKNOWN, not proven running or stopped.
No monitor/scanner action or ZAP API probe was executed.

Python modules already imported by the backend remain in that process. Later
imports and evidence/report reads can still use files on disk. StaticFiles also
serves disk assets. Therefore source changes, build changes and process changes
are separate deployment operations: a Git rollback alone does not roll back a
process or its data. The stable dist and original preview assets are unchanged.

The current retained journal is readable with full feature evidence (8 windows,
0 episodes) without any file hash change. The reader/config/privacy/explanation
resolver and lifecycle launcher scripts are byte-identical to pre-UX. All src/
scientific code and protected evidence namespaces are identical between pre-UX
and C2. Source/static export roundtrips were verified in a temporary directory.
This supports compatibility; it is not a full VM restore or live cutover test.

## Isolated review

```bash
cd /home/saintdomix/dissertation_model
PYTHONDONTWRITEBYTECODE=1 PRODUCT_FACTORY_ONLY=1 OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 .venv/bin/python -B scripts/run_ux_preview.py --port 18008 --assets demo/frontend/preview-final-stabilization-20261104 --retained-session runtime/behavioral_v2/ui-e01c26a593174d42bec5d45faf703576
```

Open http://127.0.0.1:18008/; Ctrl+C stops only that foreground preview.
No writable live-runtime link, extra virtual environment, large data copy or
stable dist replacement was introduced. The acceptance script uses a read-only
journal/store without constructing scanner or monitoring controllers.

Promotion and rollback require a separate operator-approved maintenance window;
see `DEPLOYMENT_AND_ROLLBACK.md`. Candidate-level tests do not establish new
real operational scan acceptance or a calibrated scientific conclusion.
