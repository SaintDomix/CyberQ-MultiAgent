# One-page defense cheat sheet

```bash
cd /home/saintdomix/dissertation_model
.venv/bin/python -B scripts/demo_preflight.py --mode LIVE_LAB
scripts/start_demo.sh --mode LIVE_LAB
scripts/demo_status.sh
# Open http://127.0.0.1:8000
scripts/stop_demo.sh
```

Fallback: `scripts/start_demo.sh --mode ACCEPTED_REPLAY`.
If port is occupied, append `--port 8001`; do not kill an unrelated service.

**Accepted model:** `behavioral-v2-59a8c7c5d3d51632d0af`.
83 features; OCSVM + XGBoost; confidence 0.8 uncalibrated;
UNKNOWN persistence two. Models are saved and immutable.

| Evidence | Model v1 | Behavioral v2 |
|---|---:|---:|
| Blind benign novelty FPR | 93.94% | 3.03% |
| Benign sessions alerted | 6/6 | 0/6 |
| Benign alert episodes | 23 | 0 |
| Fresh attempt runs detected | 14/14 | 14/14 |
| Reconciled attempt-window recall | 97.06% | 100% |

**CQI:** quality index, not probability. Six dimensions, equal 1/6 weights,
policy-derived ordinal coefficients. Explain contributors and deduplication.
Suppressed UNKNOWN is not an incident but remains scoreable under frozen CQI.

**Seven attempt labels:** BRUTE_FORCE; ENUMERATION_RECONNAISSANCE;
ADMIN_PROBING; REQUEST_BURST_DOS_LIKE; SQLI_ATTEMPT; XSS_ATTEMPT;
PATH_TRAVERSAL_ATTEMPT. Never claim successful exploitation.

**Replay buttons:** A Normal benign → B Known attempt → C Suppressed UNKNOWN.
Always say **ACCEPTED EVIDENCE REPLAY**. Reset selects original locked evidence.

**Live acceptance:** `live_acceptance.py begin` → actually browse normally for
30–60 seconds → `live_acceptance.py finish --stop-monitor` using `.venv/bin/python -B scripts/`.
Never enter passwords into the CLI/chat. Window closure includes 10 seconds plus
grace/polling; model milliseconds are not total detection latency.

**Top five limitations:** (1) six benign sessions/two runs per class;
(2) controlled student-role Moodle lab, not population sampling;
(3) other LMS accuracy unvalidated; (4) Apache lacks POST bodies and patterns
do not prove exploits; (5) uncalibrated model scores and policy-derived CQI,
with no causal or statistical-significance claim.

**Recovery:** use replay if VMs/log permission fail. `curl --fail
http://127.0.0.1:8000/api/health`; open `outputs/reports/behavioral_v2_final_report.md`.
The v1 report is historical baseline; the final v2 report is separate.
