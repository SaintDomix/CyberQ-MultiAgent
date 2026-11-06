# Contextual Fusion application adapter

The existing Fusion pipeline preserves all source evidence, applies reviewed
root-condition deduplication and creates deterministic contextual correlations.
The application maps those correlations onto actual incident observation IDs.
No arbitrary text clustering, new inference score or confirmation upgrade is
introduced. Root clusters and contributions remain auditable in the Quality UI.

`FusionEvent` identifies the episode, posture finding IDs, reviewed rule,
relationship, explanation and evidence-derived time. Direct semantic matches
(SQLI/XSS/DoS advisory context) are `DIRECT_CONTEXT`; category/control associations
are `SUPPORTING_CONTEXT`. These terms describe matching context, never a direct
causal mechanism. `NO_CORRELATION` is explicit when no reviewed match exists.
`WEAK_CONTEXT` is reserved in the contract; no unsupported weak association is
manufactured to populate it.

All events have `score_effect=NONE`, `causal=false`, `exploit_confirmed=false`.
Presentation incident severity is transparently derived from the existing
behavior coefficient (>=.75 HIGH, >=.4 MEDIUM, otherwise LOW), clearly labelled
policy-derived. Context does not change that severity or add a CQI penalty.
The explanation states this and names the source rule and matching findings.

Example: an accepted SQLI_ATTEMPT episode can associate with the matching
SQL-injection advisory ADV-MSA-26-0031. The advisory retains VERSION_BASED and
the behavior retains ATTEMPT; SQL injection success is not established.

Apache evidence alone does not establish authenticated identity or role. We do
not fabricate an "authenticated anomaly" to associate with session controls.
Future contextual rules require actual canonical evidence and review, outside
this frozen-policy presentation milestone.
