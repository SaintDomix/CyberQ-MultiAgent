"""Current-emitter identity correction; constructed evidence, no collection."""
from copy import deepcopy
import pytest
from cqi_v2.model import evaluate
from cqi_v2.identity import current_exposure_aliases,EXPOSURE_ALIASES

TIME='2026-11-06T14:16:35+00:00'

def rows(old='EXPOSURE--ENV'):
    new,title,path=EXPOSURE_ALIASES[old]
    base={'category':'Exposure','assessment_id':'fixture-current','affected_asset':'http://fixture/moodle',
        'end_utc':TIME,'evidence_source':'NATIVE_POSTURE','severity':'INFO',
        'provenance':{'assessment_id':'fixture-current'},'finding_type':title}
    current=dict(base,finding_id=new,evidence_id='fixture-current-evidence',current_state='PASS',confirmation_status='NOT_CONFIRMED',
        evidence={'observation':{'finding_id':new,'indicator':title,'status':'PASS','observed':'HTTP 404; marker=not matched'}})
    legacy=dict(base,finding_id=old,evidence_id='fixture-legacy-placeholder',current_state='NOT_AVAILABLE',confirmation_status='NOT_TESTED',
        prerequisite_reason='Legacy finding identity has no direct fresh emitter; retained',evidence={})
    controls=[{'control_id':new,'root_id':new,'dimension':'D3','platform_scope':'GENERIC_HTTP'}]
    known=[{'control_id':old,'root_id':old,'dimension':'D3','platform_scope':'GENERIC_HTTP'}]
    return [current,legacy],controls,known

@pytest.mark.parametrize('old',EXPOSURE_ALIASES)
def test_proven_alias_not_an_extra_missing_control(old):
    evidence,controls,known=rows(old);before=deepcopy(evidence)
    q=evaluate(evidence,as_of=TIME,controls=controls,known_controls=known)
    assert q['dimensions'][2]['unobserved_hazard_allowance']==0
    assert q['dimensions'][2]['applicable_control_units']==1
    assert q['dimensions'][2]['score']==100
    assert q['control_identity_corrections'][0]['legacy_control_id']==old
    assert len(q['dimensions'][2]['contributors'][0]['evidence_ids'])==2
    assert evidence==before
    assert q==evaluate(evidence*2,as_of=TIME,controls=controls,known_controls=known)
    assert q==evaluate(iter(evidence),as_of=TIME,controls=controls,known_controls=known)

def test_confirmed_failure_is_retained_and_never_suppressed():
    evidence,controls,known=rows('EXPOSURE-SERVER-STATUS')
    evidence[0].update(current_state='FAIL',severity='MEDIUM',confirmation_status='CONFIRMED')
    evidence[0]['evidence']['observation'].update(status='FAIL',observed='HTTP 200; marker=matched')
    q=evaluate(evidence,as_of=TIME,controls=controls,known_controls=known)
    assert q['dimensions'][2]['supported_hazard']==.5
    assert q['dimensions'][2]['score']==pytest.approx(100*2**(-.5))

@pytest.mark.parametrize('case',['no_assessment','wrong_title','wrong_provenance','partial','error','ambiguous_200',
    'observed_legacy_failure','other_asset','other_assessment','legacy_directory_listing','no_observation'])
def test_incomplete_or_non_equivalent_evidence_cannot_resolve_alias(case):
    evidence,controls,known=rows();current,legacy=evidence
    if case=='no_assessment':current.pop('assessment_id')
    if case=='wrong_title':current['finding_type']='A different check'
    if case=='wrong_provenance':current['provenance']['assessment_id']='another-assessment'
    if case=='partial':
        current['current_state']='PARTIAL';current['evidence']['observation']['status']='PARTIAL'
    if case=='error':current['current_state']='ERROR'
    if case=='ambiguous_200':current['evidence']['observation']['observed']='HTTP 200; marker=not matched'
    if case=='observed_legacy_failure':legacy.update(current_state='FAIL',confirmation_status='CONFIRMED')
    if case=='other_asset':legacy['affected_asset']='http://other/moodle'
    if case=='other_assessment':legacy['assessment_id']='another-assessment'
    if case=='legacy_directory_listing':current['finding_type']='Directory listing at base URL'
    if case=='no_observation':current['evidence']=None
    aliases,proof=current_exposure_aliases(evidence,{s['control_id']:s for s in controls})
    assert not aliases and not proof

def test_known_control_remains_missing_without_current_emitter():
    evidence,controls,known=rows()
    q=evaluate(evidence[1:],as_of=TIME,controls=controls,known_controls=known)
    assert 'control_identity_corrections' not in q
    assert q['dimensions'][2]['unobserved_hazard_allowance']==2
    assert q['dimensions'][2]['score'] is None

def test_old_frozen_id_without_emitter_metadata_remains_unchanged():
    evidence,controls,known=rows('EXPOSURE-SERVER-STATUS')
    evidence[0]['evidence']={};evidence[0].pop('assessment_id')
    q=evaluate(evidence,as_of=TIME,controls=controls,known_controls=known)
    assert 'control_identity_corrections' not in q
    assert q['dimensions'][2]['applicable_control_units']==2
    assert q['dimensions'][2]['unobserved_hazard_allowance']==1

def test_stale_current_evidence_never_establishes_pass():
    evidence,controls,known=rows()
    q=evaluate(evidence,as_of='2026-11-08T14:16:35+00:00',controls=controls,known_controls=known)
    assert q['dimensions'][2]['score'] is None
    assert q['dimensions'][2]['coverage']==0
    assert q['dimensions'][2]['unobserved_hazard_allowance']>=1

def test_ambiguous_current_assessments_cannot_resolve_identity():
    evidence,controls,_=rows();another=deepcopy(evidence[0]);another['assessment_id']='second'
    another['provenance']['assessment_id']='second';another['evidence_id']='second'
    assert current_exposure_aliases([evidence[0],another],{s['control_id']:s for s in controls})==({},[])
