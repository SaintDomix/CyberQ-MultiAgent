"""Active-stage contracts link observations without modifying parent findings."""
from dataclasses import asdict, dataclass, field
from typing import Protocol


@dataclass(frozen=True)
class Decision:
    applicability: str
    reason: str
    required_context: tuple[str, ...] = ()
    authentication_requirement: str = "anonymous"
    context: dict = field(default_factory=dict)


@dataclass
class Candidate:
    candidate_id: str
    parent_finding_id: str
    parent_evidence_id: str
    parent_confirmation_status: str | None
    proposed_validator: str | None
    applicability: str
    reason: str
    required_context: list[str]
    authentication_requirement: str
    context: dict
    execution_status: str = "NOT_TESTED"
    confirmation_status: str = "NOT_TESTED"

    def to_dict(self):
        return asdict(self)


@dataclass(frozen=True)
class RequestSpec:
    url: str
    purpose: str
    method: str = "GET"
    session_ref: str | None = None
    private_parameters: tuple[str, ...] = ()


@dataclass(frozen=True)
class Outcome:
    outcome: str
    check_result: str
    confirmation_status: str
    reason: str
    characteristics: dict = field(default_factory=dict)


class Validator(Protocol):
    name: str

    def propose(self, parent) -> Decision | None:
        """None means this validator does not correspond to the evidence."""

    def requests(self, candidate: Candidate) -> list[RequestSpec]: ...

    def evaluate(self, candidate: Candidate, responses: list) -> Outcome: ...
