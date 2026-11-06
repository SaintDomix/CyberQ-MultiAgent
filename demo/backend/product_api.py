"""Typed read-only UI contract; no scanner execution or monitor control on GET."""
from typing import Literal
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field
from .cqi_api import ScientificCQI
from .schemas import ApplicationSnapshot, Mode, Replay, Evidence
from .product_quality import product_assessment
from .posture_projection import execution_metadata, history_page


class ProductAssessment(BaseModel):
    schema_version: Literal['product-assessment-3.0']
    snapshot: ApplicationSnapshot
    scientific_cqi: ScientificCQI
    assessment: dict | None
    latest_execution: dict | None = None
    history_total: int = 0
    behavior_summary: dict = Field(default_factory=dict)
    preview_read_only: bool = False
    selection: dict
    comparison: dict
    history: list[dict]
    closure_review: dict


def router(service):
    r = APIRouter(prefix='/api/product')
    @r.get('/assessment', response_model=ProductAssessment)
    def assessment(mode: Mode | None = None, replay: Replay = 'ATTACK_HOLDOUT',
                   run_id: str | None = None, assessment_id: str | None = None):
        return product_assessment(service, mode, replay, run_id, assessment_id)
    @r.get('/history')
    def history(limit: int = Query(25, ge=1, le=100), offset: int = Query(0, ge=0)):
        return history_page(service.posture_service, offset, limit)
    @r.get('/executions/{assessment_id}')
    def execution(assessment_id: str):
        return execution_metadata(service, service.posture_service.get(assessment_id))
    @r.get('/observations')
    def observations(mode: Mode | None = None, replay: Replay = 'ATTACK_HOLDOUT', run_id: str | None = None,
                     assessment_id: str | None = None, expected_assessment_id: str | None = None, status: str | None = None,
                     limit: int = Query(25,ge=1,le=200), offset: int = Query(0,ge=0)):
        if assessment_id and (mode or service.current_mode)!='LIVE_LAB':raise ValueError('Invalid posture view')
        evidence={};snap=service.snapshot(mode,replay,run_id,assessment_id=assessment_id,evidence=evidence)
        aid=(evidence.get('assessment') or {}).get('assessment_id')
        if expected_assessment_id and aid!=expected_assessment_id:raise ValueError('Evidence selection changed; refresh required')
        rows=list(reversed(snap['observations']))
        if status:rows=[o for o in rows if o.presentation_state==status]
        return {'items':rows[offset:offset+limit],'total':len(rows),'offset':offset,'limit':limit,'assessment_id':aid}
    @r.get('/evidence/{identity}', response_model=Evidence)
    def evidence(identity: str, mode: Mode | None = None, replay: Replay = 'ATTACK_HOLDOUT',
                 run_id: str | None = None, assessment_id: str | None = None,
                 expected_assessment_id: str | None = None):
        if assessment_id and (mode or service.current_mode) != 'LIVE_LAB':
            raise ValueError('Posture selection requires LIVE_LAB')
        source = {}
        snap = service.snapshot(mode, replay, run_id, assessment_id=assessment_id, evidence=source)
        if expected_assessment_id and (source.get('assessment') or {}).get('assessment_id') != expected_assessment_id:
            raise ValueError('Evidence selection changed; refresh required')
        for kind, field, rows in (('POSTURE','finding_id',snap['posture']),
                ('OBSERVATION','observation_id',snap['observations']), ('INCIDENT','episode_id',snap['incidents']),
                ('FUSION','fusion_event_id',snap['fusion'])):
            for row in rows:
                ids = [getattr(row,field)]
                if kind == 'POSTURE':
                    ids += [row.provenance.get('evidence_id'), *row.member_evidence_ids]
                if identity in ids:
                    return {'evidence_id':identity,'type':kind,'data':row.model_dump(by_alias=True)}
        raise HTTPException(404, 'EVIDENCE_NOT_FOUND_IN_SELECTED_SNAPSHOT')
    return r
