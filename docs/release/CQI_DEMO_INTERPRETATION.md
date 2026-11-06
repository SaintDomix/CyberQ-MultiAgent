# CQI replay snapshots

`outputs/demo/cqi_snapshots.json` contains five new application projections from
actual locked evidence, using unchanged Fusion/CQI code and coefficients.
No snapshot changes accepted research outputs or model settings.

- **POSTURE_ONLY_PARTIAL:** no behavior is invented. D6 is INSUFFICIENT_EVIDENCE,
  quality null; the existing policy renormalizes five available dimensions. The
  posture timestamp is absent and remains null. This is a partial index, not a
  directly comparable full six-dimension state or assumed perfect D6.
- **NORMAL_BENIGN:** one deterministic accepted benign protocol, zero incidents.
- **KNOWN_ATTEMPT:** representative accepted SQLI_ATTEMPT protocol. Contiguous
  windows form an episode; contribution uses the maximum, not window sum.
- **UNKNOWN_OBSERVATION:** the real accepted isolated UNKNOWN remains visible,
  suppressed as an incident. The frozen raw-evidence CQI can still penalize D6.
- **ALL_ATTACK_RECENT:** the full accepted attempt replay, selected relative to
  its latest evidence time and the 300-second horizon.

Replay's clock is the observed window end, explicitly labelled; original offline
model-emission timestamps do not exist and are not invented. Live inference uses
actual saved emission evidence time. Neither depends on the current wall clock
for CQI selection.

For each reviewed scoring cluster c, D6 risk is 1 − product(1 − c), and quality
is 100 × product(1 − c). Several separated recent attempt episodes can make D6
very low even though each contiguous episode is counted once. A contribution
0.75 yields quality 25 for one episode; this coefficient is ordinal policy,
not a probability. Multiple genuine episode clusters compound the bounded index.

Overall CQI also reflects the accepted posture weaknesses: transport/header and
server-write-permission evidence can lower dimensions even when recent behavior
is benign. D1–D5 are identical in the complete benign/attack replay comparison.
Equal 1/6 weights were not tuned to improve presentation. The default full replay
is different evidence from the historical M3C two-state comparison; do not reuse
its old CQI values as current v2 application values.

UI rounds to two decimals; API/snapshot files retain full precision. A tiny
positive D6 can display 0.00 without being mathematically zero. Contributor
deductions are not additive or percentages of causality. Correlations add no
direct CQI penalty and do not upgrade VERSION_BASED posture to confirmed exploit.
