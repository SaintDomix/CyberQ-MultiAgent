# Dissertation demonstration runbook

## Pre-demo

1. Start the Ubuntu/Moodle VM. Kali is optional for this demo; no new attacks are
   needed. Keep the accepted replay fallback available even if Moodle is offline.
2. In the repository:

```bash
cd /home/saintdomix/dissertation_model
.venv/bin/python -B scripts/demo_preflight.py --mode LIVE_LAB
scripts/start_demo.sh --mode LIVE_LAB
scripts/demo_status.sh
```

3. Open **http://127.0.0.1:8000**. LIVE_LAB startup explicitly starts the saved,
   accepted passive monitor. No traffic generator or fitting is invoked.
4. If live prerequisites fail, use:

```bash
scripts/start_demo.sh --mode ACCEPTED_REPLAY
```

Default `scripts/start_demo.sh` also selects accepted replay. Duplicate owned
startup is refused. An occupied port belonging to another service is not killed;
use `--port 8001` or stop that service through its own terminal.

## Presentation flow

1. **Overview:** identify source/mode, accepted Behavioral v2, package verification,
   posture counts and the Cybersecurity Quality Index.
2. Explain the six dimensions and equal 1/6 baseline weights. CQI is a quality
   index, never a compromise probability. Show contributions, not causal percentages.
3. **Posture:** inspect FAIL/PARTIAL/PASS/DISMISSED. Dismissed evidence remains
   dismissed; source severity is never fabricated.
4. **Model & research:** show the 83-feature schema, saved OCSVM/XGBoost,
   uncalibrated confidence threshold and frozen UNKNOWN persistence two.
5. Show blind benign improvement: v1 93.94% novelty FPR, 6/6 alerted sessions,
   23 alert episodes; v2 3.03%, 0/6, zero episodes.
6. Show fresh controlled attempts: both detect 14/14 runs, two per class;
   reconciled window recall v1 97.06%, v2 100%. State the limited support.
7. **Live monitoring:** verify the process is actually RUNNING before calling it live.
8. Perform ordinary Moodle browsing yourself. Do not disclose credentials.
   Allow startup to reach the next UTC 10-second boundary, then browse several
   pages over 30–60 seconds. A startup partial interval is intentionally excluded.
9. Inspect observation versus incident, classifier disagreement and isolated
   UNKNOWN suppression. Do not describe ordinary browser fan-out as malicious
   merely because it is bursty.
10. Switch to **ACCEPTED EVIDENCE REPLAY**. This stops the UI-owned monitor.
    Use A Normal benign, B Known attempt, C Suppressed UNKNOWN controls. They
    select deterministic locked run IDs and reset selection, not generate traffic.
11. **Incidents:** inspect the selected known attempt, its windows, model ID,
    signed SHAP margin contributions and non-causal robust deviations.
12. **Quality → Contextual fusion:** show the matching posture/advisory rule.
    SQLI_ATTEMPT does not imply SQL injection success; association is not causal.
13. Show D6/CQI change between accepted benign and representative attempt replay.
    D1–D5 remain fixed. Multiple separated recent episodes can lower D6 further.
14. **System & evidence:** show hashes, source identity, checkpoint and journal.
    Open the final Behavioral v2 report. Historical v1 remains labelled baseline.
15. State limitations: six fresh benign sessions, two runs/class, student-role
    Moodle laboratory, no population significance, no equal-other-LMS accuracy,
    missing POST bodies, uncalibrated scores and policy-derived CQI weights.

## Operator-assisted live acceptance

With the owned demo backend running:

```bash
.venv/bin/python -B scripts/live_acceptance.py begin
# Now perform ordinary authorized browsing in your own Moodle browser.
.venv/bin/python -B scripts/live_acceptance.py finish --stop-monitor
```

The second command asks for YES attestation; it never asks for credentials.
Alternatively supply `--confirm-browsing` only after you actually browsed.
Zero closed windows is PENDING, never PASS. New incidents require review, never
automatic retuning. This whole-server operational check is not a new blind FPR
experiment; ambient traffic may exist. Versioned receipts are immutable;
`outputs/demo/live_acceptance/latest.json` is an explicitly mutable operational
pointer, not accepted research evidence. Cancel your own pending check with
`live_acceptance.py cancel`; do not overwrite research captures.

The pre-ZAP checkpoint has completed this check: the versioned receipt
`outputs/demo/live_acceptance/20261015T184313Z-df0189fb.json` records
operator-confirmed browsing, 13 new observations, zero new incidents and no
runtime error. This is operational acceptance, not another blind research test.
The operator finished with `--stop-monitor`; its journal summary records a
clean `CTRL_C` stop with integrity `OK`. A subsequent `demo_status.sh` reporting
the monitor not running describes that intentional stop, not a failed acceptance.
Start monitoring explicitly again when demonstrating LIVE_LAB. A nonzero child
exit, a journal integrity failure or an unexpected stop still requires review.

## Recovery

- **Kali unavailable:** select accepted replay; no Kali process is required.
- **Moodle unavailable / Apache unreadable:** use replay, show the warning.
  Inspect permission only: `stat -c '%A %U %G' /var/log/apache2/access.log`.
  If group is adm, an administrator may authorize, from this user's terminal,
  `sudo usermod -aG adm "$USER"`. Log out/in and check `id` and
  `test -r /var/log/apache2/access.log`. No automatic privilege change occurs.
- **No closed window:** wait through the fixed window plus 2-second grace and
  polling; browse again after the startup partial interval. Do not invent events.
- **UI unavailable:** use the API/report fallback:

```bash
curl --fail http://127.0.0.1:8000/api/health
curl --fail http://127.0.0.1:8000/api/model
curl --fail 'http://127.0.0.1:8000/api/cqi?mode=ACCEPTED_REPLAY'
less outputs/reports/behavioral_v2_final_report.md
```

- **Model integrity FAILED:** do not bypass or repair the accepted package during
  the defense. Show the preserved report/research pack and inspect the receipt.
- **Backend unexpectedly stopped:** inspect `runtime/demo_control/backend.log`,
  rerun preflight, start a fresh owned session. Previous journals stay preserved.
  Manual engine resume remains available with the existing `--resume` CLI and
  the same source/config; do not reset a continuity fault automatically.

## Stop

```bash
scripts/stop_demo.sh
scripts/demo_status.sh
```

Stop signals only the recorded PID whose argv/start identity still matches.
It tolerates already-stopped state and preserves journals/checkpoints. No pkill,
model refitting, accepted artifact rewrite or automatic Git action occurs.
