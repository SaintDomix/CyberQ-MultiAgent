# Branch 1 operational integration baseline

Stable release: annotated tag `pre-zap-demo-ready-20261015`, commit
`f3fdd199a1ffa9fa3f3b3c370f2ed48967328812`, branch `m5-behavioral-v2`.
The tag was verified before editing. Starting tracked working tree was clean;
raw/derived research data and historical runs remain deliberately untracked.

Accepted Behavioral v2: `behavioral-v2-59a8c7c5d3d51632d0af`.
Canonical SHA256:
`59a8c7c5d3d51632d0afe45f8cd2fe50570b7af2943d26bb313888327ea9f436`.
All 1,320 existing protected files matched their release hashes. The working
before-inventory is `/tmp/zap_before_inventory.json`; the committed reference is
`docs/release/PRE_ZAP_INTEGRITY_RECEIPT.json`. No existing data/evidence/output
file is a destination for this integration.

Historical accepted posture: 40 records (21 FAIL, 15 PASS, 3 PARTIAL,
1 DISMISSED), SHA256
`ca798f9aab2f3be7a08001538f130c9e54a5d7b0171b92d47c2f7491a3973f3e`.
It remains a research baseline, not a newly observed operational result.

Human operational acceptance remains PASS_NO_NEW_INCIDENTS: 13 observations,
zero incidents, operator attestation and model integrity VERIFIED. Its deliberate
`finish --stop-monitor` / clean CTRL_C shutdown is not a model failure.

## Reuse and boundaries

Reuse native transport/header/cookie/CORS/endpoint-header rule callables,
frozen Fusion adapters/root rules/CQI formula, application contracts, loopback
controls, React/Vite navigation and existing polling. Add `src/posture/` for
provider policy, sanitized adapters, canonical deduplication and snapshot jobs.
Extend the application API/UI; do not replace native research code.

Intentionally untouched: `src/branch1/`, `src/branch2/`, `src/behavioral_v2/`,
`src/behavioral_runtime/`, `src/fusion/`, `src/reporting/`, all model packages,
blind benign/attack evidence, research reports and the equal 1/6 CQI policy.

Prior complete-suite receipt: 647 Python / 30 frontend. Targeted existing
application/release/runtime checks passed 63 tests during integration.

## Runtime discovery

No local `zaproxy`, `zap.sh`, Java, Docker or Podman was found. No configured
owned ZAP API/key was present. No remote Kali installation is claimed verified;
SSH is available but no remote session was opened. Status:
`ZAP_RUNTIME = UNAVAILABLE_PENDING_INSTALL`.
No package or operating-system permissions were changed.
