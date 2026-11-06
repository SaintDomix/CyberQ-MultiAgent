# Runtime reliability acceptance

Actual results are in `outputs/reliability/final_acceptance.json`.

The acceptance replays all fourteen locked attempt runs through temporary source
copies and all 33 blind benign saved windows through the unchanged saved-model/
incident path. It checks semantic predictions and raw scores against frozen
results (absolute score tolerance 1e-12), with no retraining or network requests.

It also stops after an initial source prefix, appends the remaining saved bytes,
resumes with the checkpoint, and confirms matching final observations, incident
IDs and an idempotent additional poll. SQLite commits and JSON projections remain
authoritative/durable under the proven M2D architecture. Clean shutdown retains
open-window state; it does not force an incomplete interval to close.

A temporary accepted-package copy is modified by one appended byte. Startup
must reject its hash before inference. The real package is reverified unchanged.
All temporary corruption/replay data is deleted by its temporary-directory
context. Missing source fails visibly. A separate operator smoke test verifies
real start/status/stop; it does not invent human browsing or a new benign FPR.

The tests also retain existing crash-before-checkpoint, byte-continuity, rotation,
truncation, duplicate-writer, privacy and incident-persistence checks. No incident
storm appears in locked benign replay. These checks establish prototype runtime
properties, not universal crash tolerance or population security performance.
