# CyberQuality defense source checkpoint — 5 November 2026

Checkpoint tag: `cyberquality-defense-ready-20261105`.
This is the source checkpoint of the operator-accepted application, including the
stabilized C2 interface, normal operational backend and Behavioral Monitoring
controls. It does not preserve a VM, loaded processes or private runtime state.

## Verified implementation and build

At checkpoint verification the normal backend was PID 415036, loopback port 8000,
`LIVE_LAB`, `preview_read_only=false`. Its existing lifecycle controller reported
an owned running monitor. Neither process nor the ZAP tunnel was restarted,
signaled, adopted or reconfigured during checkpoint creation. Only GET requests
were used. The operator confirmed the working monitoring controls.

The active build is `demo/frontend/behavioral-controls-20261105/` (three files,
384889 bytes). It is **untracked**, not ignored by the current ignore rules, and
is explicitly excluded from this source commit. Its complete deployment hashes
are recorded in `DEFENSE_FRONTEND_SHA256.json`. GET responses from the running
backend matched those hashes. A Vite build with `write:false` reproduced all
three files byte-for-byte from the checkpoint source, without writing served
assets. Node v22.14.0, Vite 8.3.3 and the existing locked dependencies were used.

`demo/frontend/package.json`, `package-lock.json`, `vite.config.js`, `index.html`
and all source imports are tracked. No dependency installation or service restart
was performed for this checkpoint. Prior focused monitoring acceptance recorded
15 backend tests, eight frontend tests and seven isolated browser checks; fake
Start/Stop responses were used in those automated checks. Those prior receipts
remain under `/tmp/behavioral_monitor_controls/`; temporary receipts/screenshots
are not part of this tag. This task did not rerun scans, training or experiments.

The previous finalized build at
`demo/frontend/preview-final-stabilization-20261104/` and the original stable
`demo/frontend/dist/` remain separate. The latter is ignored by `demo/.gitignore`.
The original stable assets are also inside the existing verified recovery package.
The active monitoring-controls build is locally preserved at the active build
directory; an external copy of that newer build has not been independently
verified. The Windows recovery package preserves the **original** application,
not this newer compiled frontend or its latest runtime journal.

## Restart the accepted application

After a planned shutdown or reboot, from the existing laboratory repository:

```bash
cd /home/saintdomix/dissertation_model
.venv/bin/python -B scripts/start_cyberquality.py
```

An already-running owned application is rejected rather than duplicated. This
command verifies the configured asset hashes, decrypts existing startup settings
only in memory and uses the normal owned lifecycle. It selects a retained journal
without automatically starting a monitor or scan. Current monitoring must not be
interrupted just to create or inspect a Git checkpoint. The Windows URL remains
`http://127.0.0.1:18000/` through the separately managed SSH forward.

The wrapper requires these **excluded, existing** deployment prerequisites:

- The compatible `.venv` and accepted research/model inputs.
- Private `runtime/demo_control/cyberquality_startup.json`.
- Its configured retained journal and checkpoint. A restart does not automatically
  resume the currently running monitor or discover a different latest session.
- Its `frontend_manifest`, currently
  `runtime/demo_control/behavioral_controls_assets.sha256.json`.
- The existing recovery directory
  `/home/saintdomix/dissertation_checkpoints/pre_cutover_recovery_20261104T185418Z`,
  its private `RECOVERY.key` and encrypted
  `payload/original_root/startup_environment.enc`. Never commit or publish them.
- Existing original `demo/frontend/dist` assets, which the operational preflight
  still checks, and the separately configured Apache/ZAP/tunnel prerequisites.

The committed `docs/productization/DEFENSE_FRONTEND_SHA256.json` has the same flat
path-to-hash format as the active private manifest and can be used when reconstructing
deployment configuration. No current private configuration was modified here.
Restoring Git alone cannot reconstruct the private settings, runtime journals or
untracked experimental data. Preserve those through the existing recovery process.

## Rebuild without overwriting the running build

These are future reproduction instructions, **not commands run during checkpoint
creation**. Use Node v22.14.0 on the supported Linux environment. The current Node
binary is `/tmp/node-v22.14.0-linux-x64/bin/node`; that temporary installation may
need restoring after a reboot. Preserve or restore the matching toolchain.

For a fresh build environment, install dependencies with `npm ci` from
`demo/frontend` using the tracked lockfile. On the existing laboratory installation
reuse `node_modules`. Never run dependency installation or a build over active
served assets. Then, from the repository root:

```bash
rebuild_dir="$(mktemp -d /tmp/cyberquality-rebuild.XXXXXX)"
(
  cd demo/frontend
  node node_modules/vite/bin/vite.js build --outDir "$rebuild_dir"
)
python3 - "$rebuild_dir" <<'PY'
import hashlib, json, sys
from pathlib import Path
root = Path(sys.argv[1])
manifest = json.loads(Path('docs/productization/DEFENSE_FRONTEND_SHA256.json').read_text())
for name, expected in manifest.items():
    relative = Path(name).relative_to('demo/frontend/behavioral-controls-20261105')
    assert hashlib.sha256((root / relative).read_bytes()).hexdigest() == expected, relative
print('Frontend rebuild hash verification PASS')
PY
```

Use an appropriate `PATH` for the selected Node binary. Build and verify in a new
directory, then perform any promotion as a separate controlled operation. If the
hashes differ, investigate the source/toolchain/dependency mismatch; do not change
the accepted manifest merely to accept a different build.

## Recovery and scientific boundaries

Existing references remain unchanged:

- `pre-ux-20261104`: `a6d31a2633766ee285b4b80c3df361b184abc2f2`.
- `ux-phaseb-candidate-20261104`: `fe6f4c80fcc1ea05ae76c08c594c5445237b0d8b`.
- `ux-c2-candidate-20261104`: `a92b445b602adda70f7bf7ccb9b324d5be94e5fb`.
- `task3b-experiment-backup-20261104`: `f69aec973916095a3e391fe40a800a4a00615be8`.

Recovery-package checksums, 451 protected research/asset hashes and 199 historical
posture files were reverified. Frozen Behavioral v2 remains:

`59a8c7c5d3d51632d0afe45f8cd2fe50570b7af2943d26bb313888327ea9f436`.

The active monitor may continue appending legitimate observations independently;
this checkpoint does not write, restore or freeze its journal. Research evidence,
models, CQI/scanner policies and historical findings are not staged or changed.
See `OPERATIONAL_CUTOVER.md` for original-version restoration and its cold-test
limits. Older candidate/stabilization documents describe their own historical
acceptance stages, not the current running process identity.
