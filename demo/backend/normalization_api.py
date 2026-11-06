"""Small bounded diagnostic API; no event persistence, target requests or fitting."""
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field
from typing import Literal
from platform_normalization import ingest, adapter, SCHEMA_VERSION
from platform_normalization.capabilities import CAPABILITIES
from platform_normalization.dependencies import dependency_matrix

router = APIRouter(prefix='/api/ingestion')


class InspectRequest(BaseModel):
    text: str = Field(max_length=500000)
    format: Literal['json', 'jsonl', 'csv', 'apache', 'nginx', 'access'] | None = None
    platform: Literal['generic_web', 'moodle'] = 'generic_web'
    mapping: dict = Field(default_factory=dict)


class Diagnostics(BaseModel):
    state: str
    canonical_schema_version: str
    source: dict
    detection: dict
    quality: dict
    mapping: dict
    capabilities: dict
    events_exported: bool


@router.get('/schema')
def schema():
    return {'canonical_schema_version': SCHEMA_VERSION, 'platform_adapters': ['generic_web', 'moodle'],
        'capability_denominator': list(CAPABILITIES), 'feature_dependencies': dependency_matrix(),
        'scope': 'Offline telemetry diagnostics; accepted model and scanner policies unchanged.'}


@router.post('/inspect', response_model=Diagnostics)
def inspect(body: InspectRequest):
    try:
        batch = ingest(body.text, format=body.format, mapping=body.mapping, platform=body.platform,
                       source_reference='API_MEMORY_ONLY')
        return batch.diagnostics(adapter(body.platform))
    except (ValueError, TypeError, OverflowError):
        # Do not reflect malformed input or mapping constants in error strings.
        raise HTTPException(422, detail='INVALID_SOURCE_OR_MAPPING; review declared types, UTF-8 and bounded input size.') from None
