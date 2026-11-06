"""Simple ordered registry; adding validators requires no orchestration changes."""
from evidence_contracts.models import record_digest
from .models import Candidate, Decision
from .safety import SafetyError
from .validators import DEFAULT_VALIDATORS
from .runtime import RuntimeContext


class Registry:
    def __init__(self, validators=DEFAULT_VALIDATORS):
        self.validators = {v.name: v for v in validators}
        if len(self.validators) != len(validators):
            raise ValueError("Validator names must be unique")

    def plan(self, parents, policy, runtime=None):
        runtime = runtime or RuntimeContext()
        candidates = []
        for parent in parents:
            matches = [(v.name, decision) for v in self.validators.values() if (decision := v.propose(runtime.parent_for(parent, v.name))) is not None]
            if not matches:
                matches = [(None, Decision("NOT_APPLICABLE", "No registered bounded validator for this evidence"))]
            for name, decision in matches:
                identity = record_digest({"parent": parent.evidence_id, "validator": name, "context": decision.context})
                candidate = Candidate("active-" + identity, parent.finding_id, parent.evidence_id,
                    parent.to_dict()["confirmation_status"], name, decision.applicability, decision.reason,
                    list(decision.required_context), decision.authentication_requirement, dict(decision.context))
                if parent.to_dict()["confirmation_status"] == "FALSE_POSITIVE":
                    candidate.applicability, candidate.reason = "NOT_APPLICABLE", "Dismissed parent candidate; no automatic reactivation"
                if candidate.applicability == "APPLICABLE":
                    specs = self.validators[name].requests(candidate)
                    missing = [spec.session_ref for spec in specs if spec.session_ref and not runtime.session_available(spec.session_ref)]
                    roles = {"restricted_session": "restricted_role", "privileged_session": "privileged_role"}
                    for session_key, role_key in roles.items():
                        reference = candidate.context.get(session_key)
                        if reference and runtime.sessions.get(reference, {}).get("role") != candidate.context.get(role_key):
                            missing.append("session role mismatch: " + session_key)
                    if missing:
                        candidate.applicability = "MISSING_CONTEXT"
                        candidate.required_context.extend("ephemeral session: " + ref for ref in missing)
                        candidate.reason = "Authorized runtime sessions unavailable or role metadata mismatched"
                if candidate.applicability == "APPLICABLE":
                    # Validate requests without creating an executor or making any requests.
                    if not policy.target:
                        candidate.required_context.append("explicit authorized target before execution")
                    else:
                        try:
                            from dataclasses import replace
                            check_policy = replace(policy, active=True, authorized=True)
                            for spec in self.validators[name].requests(candidate):
                                check_policy.check(spec)
                        except (SafetyError, ValueError, TypeError):
                            candidate.applicability, candidate.reason = "NOT_APPLICABLE", "Request does not satisfy explicit target/safety restrictions"
                candidates.append(candidate)
        return candidates
