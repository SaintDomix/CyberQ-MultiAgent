"""CQI v2 explicit migration path; v1 API and historical interpretation preserved."""
from typing import Literal
from fastapi import APIRouter
from pydantic import BaseModel

class ScientificCQI(BaseModel):
    schema_version:Literal['scientific-cqi-response-2.0']
    policy:dict
    registry:dict
    as_of:str
    platform:str
    overall:float|None
    overall_status:str
    conditional_overall:float|None
    overall_score_kind:str
    quality_bounds:dict
    coverage:dict
    dimensions:list[dict]
    contributors:list[dict]
    behavioral:dict
    warnings:list[dict]
    aggregation_alternatives:dict
    interpretation:str
    parameters_calibrated:bool
    is_probability:bool
    comparison_context:dict
    result_sha256:str

def router(service):
    from .schemas import Mode,Replay
    r=APIRouter(prefix='/api/cqi/v2')
    @r.get('',response_model=ScientificCQI)
    def current(mode:Mode|None=None,replay:Replay='ATTACK_HOLDOUT',run_id:str|None=None,as_of:str|None=None):
        return service.scientific_quality(mode,replay,run_id,as_of)
    @r.get('/policy')
    def policy():
        from cqi_v2 import Policy,registry
        return {'policy':Policy().export(),'control_registry':registry(),
            'migration':'New clients explicitly use /api/cqi/v2. Existing /api/cqi and stored history remain fusion-cqi-1.1; no historical value rewritten.'}
    return r
