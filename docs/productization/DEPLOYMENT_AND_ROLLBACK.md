# Controlled promotion and rollback plan — DO NOT EXECUTE WITHOUT APPROVAL

Applies to this repository and its current one-process loopback deployment.
No cutover or rollback was executed during stabilization.

## Assumptions and blocking prerequisites

1. The operator separately approves the final source manifest and screenshots,
   a maintenance window, and any required effect on owned monitoring/scanning.
2. Current process ownership/configuration are re-inventoried immediately before
   cutover. The observed backend is PID389143 without reload, port8000. Never
   rely on an old PID without checking argv and start ticks.
3. Current ordinary launchers are `scripts/start_demo.sh`, `stop_demo.sh`,
   `demo_status.sh` and `scripts/run_demo.py`. All are unchanged. No new launcher
   or scanner policy is needed. The production launcher serves
   `demo/frontend/dist`; passing preview assets to it is not supported.
4. Disk currently has only about 1.4 GiB free. A full VM/research backup requires
   adequate **external/host storage**. Do not duplicate the dataset locally.
   Check actual size and space before backup; stop below 500 MiB free.
5. Secure environment configuration, accepted packages, immutable evidence,
   runtime/journals and frontend assets are available and verified. API keys
   must remain in a protected operator environment, not source or receipts.
6. Final stabilization source is intentionally uncommitted after the single
   authorized C2 checkpoint. Preserve its patch/extra-source archive and hashes;
   obtain separate approval for a final source commit if normal Git switching
   will be used. Never force a checkout over dirty source.

## Mandatory recovery material

| Layer | Required backup / verification |
|---|---|
| Source | pre-ux-20261104=a6d31a2, Phase B=fe6f4c8, C2=a92b445; final source patch/extra files and source hashes. Verify refs and preserve Git repository externally. |
| Static assets | Exact existing demo/frontend/dist including index and every asset, plus SHA256 manifest. Dist is NOT contained in pre-UX Git; Git cannot recover it. Keep candidate isolated build separately. |
| Process/config | Sanitized argv, interpreter, cwd, mode, port, retained-session path, PID/start ticks; protected environment backup held separately. Preserve original launch scripts and demo-control state for audit, not as new PID authority. |
| Runtime | Consistent journal.sqlite3 backup, any WAL/SHM requirements, session_manifest.json, checkpoint.json, summary and ownership state. Use a coordinated SQLite backup or quiesced snapshot; never blindly copy an open DB and omit WAL. |
| Evidence | Full external backup/VM snapshot of valuable untracked data/, evidence/, outputs/, runtime/posture, accepted models and checkpoints. Hashes/manifests detect damage but cannot reconstruct missing bytes. |
| Scanner/monitor | Identify owners and active jobs. Wait for completion or seek explicit authorization for cancellation/shutdown; never clear ZAP sessions or adopt an external monitor as a deployment shortcut. |

Git is a source recovery mechanism, not a VM, database, scanner-session or
loaded-process backup. A host VM snapshot may additionally preserve process
memory; its consistency and Kali worker recovery require operator planning.

## Promotion sequence (future approved task)

1. Verify candidate tests/manifests, model root and protected evidence hashes.
   Recheck no unowned active assessment/monitor will be interrupted. Rehearse
   source/build recovery into temporary storage and verify backup readability.
2. Freeze final source identity (reviewed manifest or separately authorized
   commit). Stage a small candidate static directory; never build over live dist.
   The isolated candidate assets already exist under
   `demo/frontend/preview-final-stabilization-20261104/`.
3. Obtain explicit cutover approval. Keep port8000 closed to new work during the
   maintenance interval. Use the normal owned stop script only after ownership
   and monitor consequences are approved:

   ```bash
   ./scripts/stop_demo.sh
   ```

   This script calls runtime/stop before shutting down its owned backend.
   Backend lifespan also closes its owned monitor. It must NOT be run casually
   when a monitor must remain alive. External processes are not adopted/killed.
4. Once backend is stopped, install only reviewed application source changes.
   This avoids a mix of already-loaded old modules and late imports from new
   files. Preserve current source checkpoint and dirty/untracked material first.
   Do not touch protected scientific files, data, model artifacts or snapshots.
5. With backend stopped, preserve the original dist directory, then install the
   complete candidate asset set as dist using a staged sibling directory and
   a controlled rename. Verify all manifest hashes. Do not mix index and assets
   from different builds. Keep the old directory for rollback; do not delete it.
6. Restore the approved environment (including the existing loopback ZAP origin
   and ownership declaration; key from protected operator configuration).
   Do not change ZAP/tunnel/runtime mode or start an assessment during cutover.
7. Run the existing preflight on the freed main port:

   ```bash
   .venv/bin/python -B scripts/demo_preflight.py --mode LIVE_LAB --port 8000
   ```

   Choose initial evidence mode explicitly. The following current launcher
   path starts a normal backend with the retained journal and **does not
   automatically start/adopt a monitor**:

   ```bash
   ./scripts/start_demo.sh --mode LIVE_LAB --port 8000 --retained-session runtime/behavioral_v2/ui-e01c26a593174d42bec5d45faf703576
   ```

   For research replay instead, use `--mode ACCEPTED_REPLAY --port 8000` without
   retained-session. `LIVE_LAB` without retained-session automatically starts a
   new owned monitor in the existing demo launcher: do not choose it unless
   separately authorized. Normal application controls remain explicit thereafter.
8. GET-only smoke: health, product assessment/version, model integrity, selected
   posture provenance, observations, CQI v2/v1, explanation, reports, assets and
   browser navigation. Confirm preview_read_only=false on the normal backend,
   policy cqi-evidence-2.0, original feature count83 and protected root.
   No scan/monitor POST is required for deployment verification.
9. If checks fail, use rollback below. If they pass, let the operator explicitly
   authorize later monitoring or scans. A saved journal is not a running monitor.

## Rollback to pre-UX (future approved task)

1. Preserve any new immutable assessments/journal entries since cutover. Do not
   erase them or rewind DB/checkpoint just to restore an older UI.
2. Reconfirm job/monitor ownership; get approval for shutdown effects. Stop only
   the owned candidate backend through the normal stop path. Never broad pkill.
3. Restore source to **pre-ux-20261104**, separately from assets. If a final
   reviewed source commit has been made and the tracked tree is clean, an
   ordinary non-force `git switch --detach pre-ux-20261104` may be used only
   after checking all untracked file/path collisions. Stop if Git refuses;
   do not reset, clean, force, stash indiscriminately or delete raw data.
   Otherwise recover the pre-UX source export into an isolated staging tree
   for a separately reviewed source-only install; do not overwrite this dirty
   workspace automatically. Both candidate tags and the final patch must survive.
4. Restore the exact backed-up original dist index/assets and verify hashes.
   A Git source switch alone does not restore dist. Do not rebuild pre-UX with
   different dependencies and call it the original artifact.
5. Use the same approved interpreter/configuration and retained-session path.
   Do not restore an old PID/start-ticks record as authority over a new process.
   Launch using the approved retained-session command above (or explicit replay).
   Startup creates fresh owned backend identity; no existing monitor is adopted.
6. GET-verify original assets, expected older contracts, model hash, v1/history,
   current journal integrity and no duplicate observations/incidents. Older UI
   may lack product/v2 routes; absence is expected for that version, not licence
   to fabricate a newer score or mix policy interpretations.
7. Keep new research/runtime evidence in history. Restoring damaged runtime data
   is a different recovery operation requiring a consistent external backup,
   operator approval and continuity/duplication review. It is not part of UI
   rollback. No database migration was introduced by C2/stabilization.

## What was actually tested

- Relevant APIs using saved evidence; control routes with in-memory fakes.
- PID reuse, exact owned shutdown and duplicate-start safeguards (18 existing
  lifecycle tests); no real shutdown/cutover.
- Current 8-observation journal with saved feature vectors: read-only verification
  passed, files unchanged. Reader/config/privacy/resolver/lifecycle scripts are
  byte-identical to pre-UX, and protected scientific namespaces do not differ.
- Source export from pre-UX and current stable static bytes roundtripped through
  temporary storage with exact hashes. No shared writable runtime links.
- No current untracked path conflicts with a pre-UX tracked filename at the time
  of inspection; recheck this before a future source switch.

A complete VM/database backup restore and real port8000 cutover have NOT been
tested or authorized. New external/host backup availability, final source approval,
maintenance ownership decisions and real operational acceptance remain prerequisites.
