"""Prospective bounded operational profile, sharing the existing ZAP executor."""
from dataclasses import dataclass
from pathlib import Path
import json
from .privacy import sha
from .zap_full import FullBudget

POLICY_ID='zap-standard-1.0'
ASSESSMENT_SECONDS=480
PUBLICATION_RESERVE=15
VALIDATION_RESERVE=20
MANIFEST=Path(__file__).resolve().parents[2]/'docs/posture/ZAP_STANDARD_POLICY.json'


@dataclass(frozen=True)
class StandardBudget(FullBudget):
    overall_seconds:int=300
    spider_seconds:int=25
    client_seconds:int=1
    ajax_seconds:int=1
    active_seconds:int=180
    passive_seconds:int=20
    metadata_seconds:int=20
    cleanup_seconds:int=32
    def __post_init__(self):
        super().__post_init__()
        if (self.overall_seconds>300 or self.active_seconds>180 or self.spider_seconds>25
            or self.passive_seconds>20 or self.metadata_seconds>20 or self.cleanup_seconds!=32):
            raise ValueError('STANDARD cannot expand its bounded operational budget')


def scanner_policy(installed):
    raw=MANIFEST.read_bytes();manifest=json.loads(raw)
    if manifest['policy_id']!=POLICY_ID:raise ValueError('STANDARD policy identity mismatch')
    known={r['scanner_id']:r for r in manifest['scanners']};seen={str(r['id']):r for r in installed}
    rows=[];enabled=[]
    for sid in sorted(set(known)|set(seen),key=int):
        row=dict(known.get(sid,{'scanner_id':sid,'name':seen.get(sid,{}).get('name',''),
            'standard_state':'DEEP_ONLY_UNREVIEWED','standard_rationale':'Unknown/new scanner is not enabled in STANDARD.',
            'full_authorized_state':'NOT_REVIEWED_HERE','technology_applicability':'UNKNOWN',
            'previous_observed_runtime_ms':None,'previous_request_count':None}))
        if sid not in seen:row.update(standard_state='NOT_INSTALLED',full_authorized_state='NOT_INSTALLED')
        elif row['standard_state']=='STANDARD_ENABLED':enabled.append(sid)
        rows.append(row)
    return {'id':POLICY_ID,'manifest_sha256':sha(raw),'scanner_review':rows,'enabled_ids':enabled,
        'attack_strength':'LOW','alert_threshold':'MEDIUM','discovery':manifest['discovery'],
        'telemetry_source':manifest['telemetry_source'],'telemetry_source_sha256':manifest['telemetry_source_sha256']}
