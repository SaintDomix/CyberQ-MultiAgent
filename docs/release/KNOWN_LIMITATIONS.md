# Known release limitations

- Six independent controlled fresh benign sessions; small support, not a
  population-level statistical-significance claim.
- Two fresh controlled runs per each of seven attempt classes; unknown/unseen
  threat-class sensitivity is not established by those known-class experiments.
- Validated in the current local Moodle laboratory, not production deployment.
- Realistic browser validation primarily uses the student role; generalization
  to every role/workload is not established. Human replication remains limited.
- Architecture is extensible through adapters; equal accuracy on other LMS
  platforms has not been demonstrated.
- Apache combined logs omit POST bodies and do not independently establish
  authenticated user/session/role context.
- SQLI/XSS/PATH are observable attempt-pattern classifications, not confirmed
  successful exploitation. REQUEST_BURST_DOS_LIKE is not proof of availability harm.
- XGBoost scores are uncalibrated. Novelty scores and robust deviations are not
  causal explanations; SHAP explains classifier raw margin, not security causality.
- CQI equal weights and ordinal coefficients are policy-derived, not empirically
  calibrated probabilities. Contextual Fusion has no direct score effect.
- Persistence controls incident escalation separately from raw-observation CQI.
  A suppressed UNKNOWN can still affect D6 under the frozen policy.
- Performance measurements are saved-evidence/in-process results on this host;
  they exclude network/browser latency and are cache/scheduler dependent.
  The recorded benchmark DB uses saved prediction payloads and is not a
  full-feature-window production storage forecast; see benchmark measurement scope.
- Prospective human browsing acceptance requires an operator attestation and
  sufficient closed windows. Start/status/stop smoke alone does not satisfy it.
  The pre-ZAP operator check has now passed with 13 new observations and zero
  new incidents; this whole-server operational result is not a new blind FPR
  estimate or evidence of population-level generalization. Its monitor was
  intentionally stopped after acceptance.
- The product is a loopback local research prototype, not an internet-facing
  multi-tenant SOC platform. Large-log scaling and distributed operation are future work.
