"""Linked validation evidence, never parent mutation or evidence fusion."""
from collections import Counter
import requests

from ..common import Document, finding
from .models import Outcome
from .redaction import redact
from .registry import Registry
from .safety import Executor, SafetyError


def run_active(ctx, parents, policy, registry=None, executor=None, runtime=None):
    registry = registry or Registry()
    runtime = runtime or (executor.runtime if executor is not None else None)
    candidates = registry.plan(parents, policy, runtime)
    if policy.active:
        policy.require_execution()
        executor = executor or Executor(policy, runtime=runtime)
        if runtime is not None and (executor.runtime.mappings != runtime.mappings or executor.runtime.sessions != runtime.sessions):
            raise SafetyError("Executor runtime context must match planner context")
        if executor.policy != policy:
            raise SafetyError("Executor policy must match orchestration policy")
    results = []
    for candidate in candidates:
        outcome = Outcome("NOT_TESTED", "NOT_TESTED", "NOT_TESTED", candidate.reason)
        start = executor.used if policy.active else 0
        if policy.active and candidate.applicability == "APPLICABLE":
            specs = registry.validators[candidate.proposed_validator].requests(candidate)
            if len(specs) > executor.remaining:
                outcome = Outcome("BUDGET_EXHAUSTED", "NOT_TESTED", "NOT_TESTED", "Insufficient remaining budget for complete bounded check")
            else:
                try:
                    responses = [executor.get(spec) for spec in specs]
                    outcome = registry.validators[candidate.proposed_validator].evaluate(candidate, responses)
                    candidate.execution_status = "EXECUTED" if specs else "CONTEXTUAL_ASSESSED"
                except (requests.RequestException, SafetyError, ValueError):
                    candidate.execution_status = "ERROR"
                    outcome = Outcome("REQUEST_ERROR", "ERROR", "NOT_TESTED", "Bounded request failed; see redacted request transcript")
        elif not policy.active and candidate.applicability == "APPLICABLE":
            candidate.execution_status = "DRY_RUN"
        candidate.confirmation_status = outcome.confirmation_status
        results.append({"candidate_id": candidate.candidate_id, "parent_finding_id": candidate.parent_finding_id,
                        "parent_evidence_id": candidate.parent_evidence_id, "validator": candidate.proposed_validator,
                        "execution_status": candidate.execution_status, **outcome.__dict__,
                        "validation_context": redact(candidate.context),
                        "validator_version": "1.1",
                        "applicability": candidate.applicability,
                        "missing_prerequisites": candidate.required_context,
                        "authentication_requirement": candidate.authentication_requirement,
                        "request_indices": list(range(start, executor.used)) if policy.active else []})
    transcript = redact(executor.transcript if policy.active else [])
    path = ctx.artifact_path("active_validation_evidence.json") if ctx.output else "active_validation_evidence.json"
    document = Document.generated(path, transcript)
    active_findings = []
    parent_map = {p.evidence_id: p for p in parents}
    for index, result in enumerate(results):
        if not result["request_indices"] and result["execution_status"] != "CONTEXTUAL_ASSESSED":
            continue
        parent = parent_map[result["parent_evidence_id"]]
        active_findings.append(finding(document, "active_validation", result["candidate_id"], parent.category,
            result["validator"], result["check_result"], result["confirmation_status"],
            parent.severity if result["confirmation_status"] == "CONFIRMED" and result["check_result"] == "FAIL" else None,
            explanation=result["reason"], evidence=redact(result), asset=redact(parent.affected_asset), index=index))
    summary = {"candidate_count": len(candidates), "validator_counts": dict(Counter(c.proposed_validator or "none" for c in candidates)),
               "applicability_counts": dict(Counter(c.applicability for c in candidates)),
               "confirmation_status_counts": dict(Counter(r["confirmation_status"] for r in results)),
               "execution_status_counts": dict(Counter(r["execution_status"] for r in results)),
               "requests_used": executor.used if policy.active else 0, "active_evidence_count": len(active_findings),
               "target": redact(policy.target), "parent_findings_preserved": True,
               "safety_controls": {"execution_enabled": policy.active, "authorization_asserted": policy.authorized,
                   "request_budget": policy.request_budget, "timeout_seconds": policy.timeout,
                   "requests_per_second": policy.requests_per_second, "max_response_bytes": policy.max_response_bytes,
                   "follow_redirects": False, "authentication": "explicit ephemeral sessions or anonymous", "scope": "exact target origin"}}
    ctx.artifacts.update({"active_validation_plan.json": redact([c.to_dict() for c in candidates]),
                          "active_validation_results.json": redact(results),
                          "active_validation_evidence.json": transcript,
                          "active_validation_findings.json": [f.to_dict() for f in active_findings]})
    return summary
