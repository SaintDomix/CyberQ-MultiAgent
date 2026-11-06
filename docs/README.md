# Documentation

Use the root [README](../README.md) for project scope, requirements and the
provisioned demonstration workflow.

| Topic | Starting point |
| --- | --- |
| Agents, registered tools and persistent state | [Multi-agent architecture](assignment4/ARCHITECTURE.md) |
| Message contracts | [JSON schemas](assignment4/schemas.json), [executed examples](assignment4/real-messages.json) |
| Demonstration and scenario coverage | [Demonstration](assignment4/DEMONSTRATION.md), [results](assignment4/RESULTS.md) |
| Measured tool execution | [Dated offline execution proof](assignment4/FINAL_EXECUTION_PROOF.md) |
| Isolation and preservation | [Coursework isolation](COURSEWORK_ISOLATION.md) |
| Live ownership and operations | [Operator guide](assignment4/LIVE_LAB_OPERATOR_GUIDE.md) |
| Evidence semantics and provenance | [Evidence contracts](EVIDENCE_CONTRACTS.md) |
| CQI methodology and limitations | [Mathematical model](research/CQI_MATHEMATICAL_MODEL.md), [API migration](research/CQI_V2_API_MIGRATION.md) |
| Controlled behavioral evaluation | [Benchmark protocol](research/BEHAVIORAL_MODEL_BENCHMARK.md) |
| Platform adaptation | [Normalization architecture](architecture/PLATFORM_NORMALIZATION.md) |

## Interpreting the records

The repository preserves scientific protocols and dated acceptance records from
the underlying platform. They are evidence of those particular development and
evaluation stages, not current installation instructions or authorization.
Historical commands, ports, host addresses, process IDs and BLOCKED observations
must not be treated as current workstation state. Start from the root README and
the current operator's verified prerequisites.

`acceptance/`, `branch2/`, `posture/`, `productization/`, `release/` and `fusion/`
retain implementation rationale, source contracts and experimental records used
by the research and validation tools. They are retained for auditability, rather
than presented as the coursework's quick-start path.

Offline orchestration, observed live execution and independently evaluated
detection performance are separate claims. A completed LIVE_LAB task has been
observed in the coursework environment, but the documented earlier offline runs
did not perform live operations. CQI calculation/mapping is under audit; historical
stored numbers are not endorsed here as validated research findings.

Models, datasets, raw logs, runtime state and private operational configuration
are excluded from Git. Links to those paths in historical records identify local
inputs/receipts; their absence from a public clone is intentional. The generated
examination report and presentation also remain local. The public scientific
methodology is available in `research/`.
