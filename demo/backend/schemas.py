"""Stable application contracts, separate from frozen research serialization."""
from typing import Any, Generic, Literal, TypeVar
from pydantic import BaseModel, Field, model_validator

Mode = Literal['ACCEPTED_REPLAY', 'LIVE_LAB']
Replay = Literal['ATTACK_HOLDOUT', 'BENIGN_TEST']


class PostureFinding(BaseModel):
    finding_id: str
    source: str
    category: str
    dimension: str | None
    status: str
    severity: str | None
    severity_source: str = 'SOURCE_EVIDENCE'
    confirmation: str
    title: str
    description: str | None
    evidence_summary: Any
    affected_component: str | None
    remediation: Any
    provenance: dict
    created_at: str | None
    canonical_finding_id: str | None = None
    assessment_id: str | None = None
    assessment_scope: str = 'RESEARCH_BASELINE'
    source_rule_id: str | None = None
    source_finding_id: str | None = None
    source_finding_ids: list[str] = Field(default_factory=list)
    member_evidence_ids: list[str] = Field(default_factory=list)
    confidence: Any = None
    evidence_sources: list[str] = Field(default_factory=list)
    multi_source: bool = False
    dedup_rule: str | None = None
    source_severity: str | None = None
    normalized_severity: str | None = None
    source_confidence: str | None = None
    confidence_semantics: str = 'ORDINAL_SOURCE_LABEL; not probability'
    url: str | None = None
    cwe: str | None = None
    rule_reference: str | None = None
    successful_exploitation_confirmed: bool = False
    source_status_conflict: bool = False
    prerequisite_reason: str | None = None
    current_state: str | None = None
    active_validation: dict | None = None
    validation_sources: list[str] = Field(default_factory=list)
    cqi_mapping: str | None = None
    parameter: str | None = None
    method: str | None = None
    zap_details: dict | None = None


class BehaviorObservation(BaseModel):
    observation_id: str
    sequence: int
    window_start: str
    window_end: str
    reconciled_label: str
    novelty_state: str
    novelty_score: float
    xgb_label: str
    xgb_score: float
    xgb_score_semantics: str = 'UNCALIBRATED_MODEL_SCORE'
    model_disagreement: bool
    actionable: bool
    suppression_reason: str | None
    presentation_state: str
    episode_id: str | None
    model_package_id: str
    evidence: dict
    explanation: dict


class Incident(BaseModel):
    episode_id: str
    type: str
    behavior_class: str = Field(serialization_alias='class')
    status: str
    severity: str | None
    severity_source: str = 'PRESENTATION_POLICY_DERIVED'
    start_time: str
    last_seen: str
    duration: float
    observation_ids: list[str]
    observation_count: int
    known_attack: bool
    contextual_posture_links: list[str] = Field(default_factory=list)
    model_package_id: str
    evidence_summary: dict
    explanation: dict = Field(default_factory=dict)
    successful_exploitation_confirmed: bool = False


class FusionEvent(BaseModel):
    fusion_event_id: str
    behavior_episode_id: str
    related_posture_finding_ids: list[str]
    relationship_type: Literal['DIRECT_CONTEXT', 'SUPPORTING_CONTEXT', 'WEAK_CONTEXT', 'NO_CORRELATION']
    context_strength: str
    contextual_severity: str | None
    explanation: str
    created_at: str
    rule_id: str
    causal: bool = False
    exploit_confirmed: bool = False
    score_effect: str = 'NONE'


class Dimension(BaseModel):
    dimension_id: str
    name: str
    score: float | None
    risk_index: float | None
    status: str
    main_contributors: list[dict]
    finding_count: int
    active_incident_count: int
    policy_weight: float
    explanation: str


class CQI(BaseModel):
    overall: float | None
    overall_status: str
    dimensions: list[Dimension]
    contributors: list[dict]
    evidence_ids: list[str]
    deductions: list[dict]
    active_behavioral_impact: dict
    sensitivity: dict
    policy: dict
    as_of: str | None
    is_probability: bool = False


T = TypeVar('T')


class Page(BaseModel, Generic[T]):
    items: list[T]
    total: int
    offset: int
    limit: int
    mode: Mode


class State(BaseModel):
    schema_version: str = 'product-application-1.0'
    mode: Mode
    source_label: str
    model_integrity: str
    package_id: str | None
    posture_counts: dict
    observation_count: int
    incident_count: int
    cqi_available: bool
    as_of: str | None
    source_generation: str | None
    last_error: str | None
    runtime: dict
    target: dict = Field(default_factory=dict)
    posture_scope: str = 'RESEARCH_BASELINE'
    posture_assessment: dict = Field(default_factory=dict)


class EmptyAction(BaseModel):
    model_config = {'extra': 'forbid'}


class ModeAction(BaseModel):
    model_config = {'extra': 'forbid'}
    mode: Mode


class PostureAction(BaseModel):
    model_config = {'extra': 'forbid'}
    target_id: str = Field(default='moodle-local',pattern=r'^[a-zA-Z0-9_-]{1,80}$')
    mode: Literal['STANDARD','PASSIVE_BASELINE','FULL_AUTHORIZED'] = 'STANDARD'
    zap_enabled: bool = True
    target_url: str | None = Field(default=None,max_length=500)
    authorized: bool = False
    authentication_profile: Literal['NONE','FORM','HTTP','SCRIPT','EXISTING_SESSION'] = 'NONE'
    discovery_profile: Literal['SPIDER','SPIDER_CLIENT_AJAX'] = 'SPIDER_CLIENT_AJAX'
    exclude_regex: list[str] = Field(default_factory=list,max_length=12)
    api_imports: dict[str,str] = Field(default_factory=dict)

    @model_validator(mode='after')
    def explicit_profile_authorization(self):
        if self.mode=='PASSIVE_BASELINE' and self.target_id!='moodle-local':
            raise ValueError('Restricted profile requires the existing local target')
        if self.mode in ('STANDARD','FULL_AUTHORIZED') and not self.authorized:
            raise ValueError('STANDARD/FULL_AUTHORIZED requires explicit authorization')
        return self


class PassivePostureAction(PostureAction):
    # A legacy route explicitly named passive must never inherit an active default.
    mode: Literal['PASSIVE_BASELINE'] = 'PASSIVE_BASELINE'


class ModelInfo(BaseModel):
    integrity: str
    name: str
    package_id: str | None
    root_sha256: str | None = None
    feature_count: int | None = None
    schema_version: str | None = None
    schema_sha256: str | None = None
    novelty_detector: str | None = None
    novelty_threshold: float | None = None
    confidence_threshold: float | None = None
    persistence: int | None = None
    classifier: str | None = None
    adapter: dict | None = None
    runtime: dict | None = None
    confidence_semantics: str = 'UNCALIBRATED_MODEL_SCORE'
    limitations: list[str] = Field(default_factory=list)
    training_performed: bool = False
    error: str | None = None


class Evidence(BaseModel):
    evidence_id: str
    type: str
    data: dict


class ResearchComparison(BaseModel):
    candidate: dict
    model_v1: dict
    support: str


class ApplicationSnapshot(BaseModel):
    status: State
    model: ModelInfo
    posture: list[PostureFinding]
    observations: list[BehaviorObservation]
    incidents: list[Incident]
    fusion: list[FusionEvent]
    cqi: CQI | None


class Health(BaseModel):
    status: str
    model_integrity: str
    training_performed: bool
    automatic_execution: bool
    capabilities: list[Mode]
    mode: Mode = 'ACCEPTED_REPLAY'
    preview_read_only: bool = False


class RuntimeStatus(BaseModel):
    available: bool
    source: str
    process_running: bool | None
    process_state: str | None = None
    sqlite_status: str | None = None
    reader_offset: int | None = None
    safe_offset: int | None = None
    checkpoint_at: str | None = None
    session_id: str | None = None
    observations_processed: int | None = None
    incidents_created: int | None = None
    last_observation: str | None = None
    integrity_status: str | None = None
    last_error: str | None = None
    uptime_seconds: float
    freshness: str
    available_runs: list[str] = Field(default_factory=list)
    replay_source: str | None = None
    selected_run: str | None = None
    time_semantics: str | None = None
    exit_code: int | None = None
    note: str | None = None


class Evaluation(BaseModel):
    benign: ResearchComparison
    attack: ResearchComparison
    limitations: list[str]
    recomputed: bool


class Explanation(BaseModel):
    observation_id: str
    xgb_class: str
    uncalibrated_score: float
    shap: dict
    robust_deviations: list[dict]
    robust_semantics: str
    reconciliation_reason: str
    causal: bool
    version: str | None = None
    summary: str | None = None
    anomaly: dict | None = None
    classification: dict | None = None
    evidence_quality: dict | None = None
    technical: dict | None = None
    provenance: dict | None = None


class ProcessState(BaseModel):
    process_running: bool
    process_state: str
    exit_code: int | None
    session: str | None
    last_error: str | None
