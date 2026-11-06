"""Versioned, strict task/message contracts. Evidence statuses are not finding statuses."""
from datetime import datetime, timezone
from typing import Literal
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

AgentId = Literal['coordinator', 'native', 'zap', 'behavioral', 'verification', 'quality']
SpecialistId = Literal['native', 'zap', 'behavioral', 'verification', 'quality']
VerificationStatus = Literal['VERIFIED', 'PARTIAL', 'CONFLICTED', 'MISSING', 'INVALID']
TERMINAL = {'COMPLETED', 'FAILED', 'TIMED_OUT', 'BLOCKED', 'LIMIT_EXCEEDED', 'INTERRUPTED'}
SPECIALISTS = ('native', 'zap', 'behavioral', 'verification', 'quality')


def now():
    return datetime.now(timezone.utc).isoformat()


class Strict(BaseModel):
    model_config = ConfigDict(extra='forbid', allow_inf_nan=False)


class TaskRequest(Strict):
    scenario: Literal['attack_replay', 'benign_replay', 'sqli_run', 'xss_run', 'traversal_run', 'bruteforce_run', 'unknown_run']
    mode: Literal['OFFLINE_EVIDENCE', 'LIVE_LAB'] = 'OFFLINE_EVIDENCE'
    zap_profile: Literal['PASSIVE_BASELINE', 'STANDARD', 'FULL_AUTHORIZED'] = 'STANDARD'
    fresh_posture: bool = True
    posture_assessment_id: str | None = Field(default=None,pattern=r'^posture-\d{8}T\d{6}Z-[0-9a-f]{12}$')
    max_steps: int = Field(default=18, ge=1, le=40)
    timeout_seconds: float = Field(default=90, ge=0.01, le=10800)
    tool_timeout_seconds: float = Field(default=30, ge=0.01, le=9000)
    max_retries: int = Field(default=1, ge=0, le=2)
    request_id: str | None = Field(default=None, pattern=r'^[a-zA-Z0-9_-]{8,64}$')

    @model_validator(mode='after')
    def live_budget(self):
        if self.mode=='LIVE_LAB':
            if not self.fresh_posture and not self.posture_assessment_id:
                raise ValueError('Explicit saved coursework posture ID required')
            full=self.zap_profile=='FULL_AUTHORIZED'
            if 'timeout_seconds' not in self.model_fields_set:self.timeout_seconds=7200 if full else 900
            if 'tool_timeout_seconds' not in self.model_fields_set:self.tool_timeout_seconds=6600 if full else 660
        return self


class EvidenceRef(Strict):
    ref_id: str
    path: str
    kind: Literal['FILE', 'SQLITE', 'MODEL_PACKAGE'] = 'FILE'
    expected_sha256: str = Field(pattern=r'^[0-9a-f]{64}$')
    read_sha256: str = Field(pattern=r'^[0-9a-f]{64}$')
    anchor: Literal['PRESERVED_INVENTORY', 'FROZEN_SOURCE_BINDING', 'COURSEWORK_TASK_SNAPSHOT'] = 'PRESERVED_INVENTORY'
    source_record_ids: list[str] = Field(default_factory=list)
    observed_at: str | None = None
    temporal_scope: Literal['HISTORICAL_SAVED_EVIDENCE', 'LIVE_MONITORING_SNAPSHOT'] = 'HISTORICAL_SAVED_EVIDENCE'

    @field_validator('observed_at')
    @classmethod
    def aware_observation(cls,value):
        if value is not None:
            parsed=datetime.fromisoformat(value.replace('Z','+00:00'))
            if parsed.tzinfo is None:raise ValueError('Explicit evidence timezone required')
        return value


class ToolArguments(Strict):
    task_id: str = Field(pattern=r'^ma-[0-9a-f]{32}$')
    agent: SpecialistId
    dependency_message_ids: list[str]
    scenario: str


class ToolResult(Strict):
    summary: dict
    data: dict = Field(default_factory=dict)
    evidence: list[EvidenceRef] = Field(default_factory=list)


class AgentResult(Strict):
    agent: SpecialistId
    summary: dict
    tools_used: list[str]
    evidence: list[EvidenceRef]


class Message(Strict):
    schema_version: Literal['cqma-message-1.0'] = 'cqma-message-1.0'
    message_id: str = Field(pattern=r'^msg-[0-9a-f]{32}$')
    task_id: str = Field(pattern=r'^ma-[0-9a-f]{32}$')
    sender: AgentId
    recipient: AgentId
    kind: Literal['DISPATCH', 'RESULT', 'FINAL', 'FAILURE']
    created_at: str
    depends_on: list[str] = Field(default_factory=list)
    payload: dict

    @field_validator('created_at')
    @classmethod
    def aware_created(cls,value):
        parsed=datetime.fromisoformat(value.replace('Z','+00:00'))
        if parsed.tzinfo is None:raise ValueError('Explicit message timezone required')
        return value


class Failure(Strict):
    code: str
    message: str
    retryable: bool = False
    agent: AgentId = 'coordinator'
    tool: str | None = None


class VerificationOutcome(Strict):
    subject: str
    status: VerificationStatus
    reasons: list[str]
    related_refs: list[str] = Field(default_factory=list)


class TaskState(Strict):
    schema_version: Literal['cqma-task-1.0'] = 'cqma-task-1.0'
    task_id: str = Field(pattern=r'^ma-[0-9a-f]{32}$')
    request: TaskRequest
    status: Literal['CREATED', 'RUNNING', 'VERIFYING', 'SCORING', 'COMPLETED', 'FAILED', 'TIMED_OUT', 'BLOCKED', 'LIMIT_EXCEEDED', 'INTERRUPTED'] = 'CREATED'
    created_at: str
    updated_at: str
    agents: dict[str, str] = Field(default_factory=lambda: {a: 'PENDING' for a in ('coordinator', *SPECIALISTS)})
    steps: int = 0
    messages: list[Message] = Field(default_factory=list)
    outputs: dict[str, AgentResult] = Field(default_factory=dict)
    tool_outputs: dict[str, ToolResult] = Field(default_factory=dict)
    branch_executions: dict = Field(default_factory=dict)
    verification: list[VerificationOutcome] = Field(default_factory=list)
    failure: Failure | None = None
    result: dict | None = None
    distribution: dict = Field(default_factory=dict)
    warnings: list[str] = Field(default_factory=list)


class TaskError(Exception):
    def __init__(self, code, message, *, retryable=False, status='FAILED'):
        super().__init__(message)
        self.code, self.safe_message, self.retryable, self.status = code, message, retryable, status
