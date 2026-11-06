"""Offline normalization acceptance; never scans targets or fits estimators."""
import asyncio
from dataclasses import asdict, replace
import hashlib
import json
from pathlib import Path
from unittest.mock import Mock, patch
import httpx
import pytest
from platform_normalization import ingest, adapter, SCHEMA_VERSION
from platform_normalization.schema import digest, CanonicalWebEvent
from platform_normalization.dependencies import dependency_matrix, behavioral_contract, REQUIRED
from platform_normalization.ingest import from_legacy, detect, MAX_BYTES, MAX_RECORDS
from platform_normalization.bridge import legacy_event, feature_rows, predict
from platform_normalization.capabilities import assess, CAPABILITIES
from platform_normalization.posture import applicability, collect_generic, GenericScopedClient, request_plan
from branch2.adapters.apache import parse_line
from behavioral_runtime.package import load, verify
from behavioral_v2.schema import FEATURES
from posture.target import AuthorizedTarget
from demo.backend.app import create_app

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / 'tests/fixtures/normalization'
FORMATS = [('apache.log','apache'),('nginx.log','nginx'),('events.json','json'),('events.jsonl','jsonl'),('events.csv','csv')]


def base(**changes):
    return {'timestamp':'2026-01-01T00:00:01Z','client_ip':'192.0.2.10','method':'GET',
            'request_uri':'/academy/catalog?item=4','status':200,'bytes':320} | changes


def batch(**changes):return ingest(json.dumps(base(**changes)),format='json')


@pytest.fixture(scope='module')
def package(): return load(ROOT/'outputs/branch2/accepted_behavioral_v2')


def test_versioned_presence_aware_canonical_schema():
    b=batch();assert b.events[0].canonical_schema_version==SCHEMA_VERSION
    assert 'query' in b.events[0].observed_fields
    with pytest.raises(ValueError):CanonicalWebEvent(status=700)
    with pytest.raises(ValueError):CanonicalWebEvent(method='get')


@pytest.mark.parametrize('name,fmt',FORMATS)
def test_equivalent_formats_normalize_without_platform_specific_code(name,fmt):
    reference=ingest((FIXTURE/'apache.log').read_bytes(),format='apache')
    b=ingest((FIXTURE/name).read_bytes(),format=fmt)
    assert b.state=='COMPLETE' and len(b.events)==3
    assert [e.analytical() for e in b.events]==[e.analytical() for e in reference.events]
    assert [r['features'] for r in feature_rows(b)]==[r['features'] for r in feature_rows(reference)]


@pytest.mark.parametrize('name,fmt',FORMATS)
def test_detection_is_deterministic_and_does_not_guess_vendor(name,fmt):
    raw=(FIXTURE/name).read_text();a=detect(raw);assert a==detect(raw)
    assert a['state']=='DETECTED'
    assert a['format']==('access' if fmt in ('apache','nginx') else fmt)


def test_common_format_support_and_absent_optional_fields():
    line=(FIXTURE/'apache.log').read_text().splitlines()[0].rsplit(' "-" "FixtureAgent/1.0"',1)[0]
    b=ingest(line,format='apache');assert b.state=='COMPLETE'
    assert b.events[0].user_agent is None and 'user_agent' in b.events[0].missing_fields
    assert behavioral_contract(b)['execution_allowed']


def test_literal_query_dash_is_not_confused_with_optional_log_sentinel():
    x=base();x.pop('request_uri');x.update(path='/academy/',query='-')
    b=ingest(json.dumps(x));assert b.events[0].query=='-'
    assert behavioral_contract(b)['execution_allowed']


def test_infrastructure_dummy_is_equivalent_and_not_a_benign_model_observation():
    x=base(client_ip='127.0.0.1',method='OPTIONS',request_uri='*',user_agent='internal dummy connection')
    b=ingest(json.dumps(x));assert b.events[0].infrastructure_dummy
    assert not behavioral_contract(b)['execution_allowed']
    with pytest.raises(ValueError):feature_rows(b)


def test_ambiguous_unknown_format_requires_mapping():
    b=ingest('arbitrary proprietary records')
    assert b.state=='MAPPING_REQUIRED' and not b.events


@pytest.mark.parametrize('field,alias', [('timestamp','event_time'),('client_ip','remote_addr'),('method','verb'),('request_uri','url'),('status','response_status'),('bytes','body_bytes_sent')])
def test_aliases_are_resolved(field,alias):
    x=base();x[alias]=x.pop(field);b=ingest(json.dumps(x));assert b.state=='COMPLETE'
    assert b.events[0].analytical()==batch().events[0].analytical()
    assert any(alias in names for names in b.mapping['resolved_fields'].values())


def test_ambiguous_aliases_require_explicit_resolution_even_if_equal():
    x=base(status_code=200);b=ingest(json.dumps(x));assert b.state=='MAPPING_REQUIRED'
    b=ingest(json.dumps(x),mapping={'status':'status'});assert b.state=='COMPLETE'


def test_nested_mapping_constants_and_query_preservation():
    x={'event':{'when':'2026-01-01T00:00:01Z','ip':'192.0.2.10','target':'/academy/catalog?item=4'},'code':'200'}
    m={'timestamp':'event.when','client_id':{'field':'event.ip'},'path':'event.target',
       'status':'code','method':{'constant':'get'},'source_platform':{'constant':'generic_web'}}
    b=ingest(json.dumps(x),mapping=m);assert b.state=='COMPLETE' and b.events[0].query=='item=4'
    assert b.mapping['sha256']==digest(m)
    assert not behavioral_contract(b)['required_missing']


@pytest.mark.parametrize('mapping',[{'unknown':'x'},{'path':{'execute':'x'}},{'status':{'field':3}},{'status':[] }])
def test_invalid_mapping_is_rejected(mapping):
    with pytest.raises(ValueError):ingest(json.dumps(base()),mapping=mapping)


def test_field_mapping_is_not_silently_ignored_for_fixed_access_log_format():
    with pytest.raises(ValueError,match='FIELD_MAPPING_REQUIRES_STRUCTURED_FORMAT'):
        ingest((FIXTURE/'apache.log').read_bytes(),format='apache',mapping={'status':{'constant':200}})


def test_missing_query_differs_from_observed_empty_query():
    x=base();x.pop('request_uri');x['path']='/academy/catalog'
    absent=ingest(json.dumps(x));empty=ingest(json.dumps(x),mapping={'query':{'constant':''}})
    assert absent.events[0].query is None and empty.events[0].query==''
    assert not behavioral_contract(absent)['execution_allowed']
    assert behavioral_contract(empty)['execution_allowed']
    with pytest.raises(ValueError):feature_rows(absent)


@pytest.mark.parametrize('key,code', [('status','STATUS_INVALID'),('bytes','BYTES_INVALID'),('timestamp','TIMESTAMP_INVALID'),('request_uri','URL_INVALID')])
def test_malformed_records_counted_without_echoing_input(key,code):
    b=ingest(json.dumps([base(),base(**{key:'DO_NOT_EXPORT_SECRET'})]),format='json')
    assert b.state=='PARTIAL' and b.quality['rejected_records']==1
    assert b.quality['errors'][0]['reason']==code
    assert 'DO_NOT_EXPORT_SECRET' not in json.dumps(b.diagnostics())
    assert not behavioral_contract(b)['execution_allowed']


def test_systemic_mismatch_and_resource_caps_fail_closed():
    b=ingest('[{"unknown":1}]',format='json');assert b.state=='FAILED'
    with pytest.raises(ValueError):ingest(b' '*(MAX_BYTES+1))
    with pytest.raises(ValueError):ingest(('{}\n')*(MAX_RECORDS+1),format='jsonl')


def test_access_log_timestamp_failure_has_a_sanitized_quality_code():
    line=(FIXTURE/'apache.log').read_text().splitlines()[0].replace('01/Jan/2026','99/Jan/2026')
    b=ingest(line,format='apache');assert b.state=='FAILED'
    assert b.quality['timestamp_failures']==1 and b.quality['errors'][0]['reason']=='TIMESTAMP_INVALID'


def test_exact_83_feature_dependency_order_and_source_trace():
    m=dependency_matrix();assert [r['feature'] for r in m['features']]==list(FEATURES)
    assert len(m['features'])==83 and 'query' in m['required_fields']
    for e in m['features']:
        assert (ROOT/e['implementation'].split(':')[0]).is_file()
        assert e['value_fields'] and e['unavailable_policy']


@pytest.mark.parametrize('missing',REQUIRED)
def test_required_telemetry_blocks_feature_and_model_execution(missing):
    b=batch();e=replace(b.events[0],**{missing:None});b.events=[e]
    fake=Mock();assert not behavioral_contract(b)['execution_allowed']
    with pytest.raises(ValueError):predict(b,fake)
    fake.predict.assert_not_called()


def test_optional_context_has_accepted_neutral_flags_without_inferred_roles():
    b=batch();r=feature_rows(b)[0]['features']
    assert behavioral_contract(b)['state']=='BEHAVIORAL_COMPATIBLE_WITH_OPTIONAL_CONTEXT_MISSING'
    assert r['role_observed_ratio']==r['session_observed_ratio']==r['identity_observed_ratio']==0
    assert b.events[0].authentication_state is None


def test_capability_denominator_prospective_and_availability_never_pass():
    a=assess(batch());assert a==assess(batch())
    assert set(a['capabilities'])==set(CAPABILITIES) and len(CAPABILITIES)==20
    assert all(v['state'] in ('AVAILABLE','PARTIAL','NOT_AVAILABLE','NOT_APPLICABLE') and v['security_verdict'] is None for v in a['capabilities'].values())
    assert a['capabilities']['platform_configuration']['state']=='NOT_APPLICABLE'
    assert a['capabilities']['role_context']['state']=='NOT_AVAILABLE'
    assert a['capabilities']['zap_standard_active']['state']=='NOT_AVAILABLE'


def test_platform_adapters_reuse_validated_semantics_without_fake_platforms():
    from behavioral_v2.platforms import MoodleBehaviorAdapter
    m=adapter('moodle');assert m.semantic_adapter().identity()==MoodleBehaviorAdapter().identity()
    assert m.semantic_adapter().map_request('/moodle/my/').category=='DASHBOARD'
    assert adapter().semantic_adapter().map_request('/moodle/my/').category=='UNKNOWN'
    with pytest.raises(ValueError):adapter('canvas')


def test_generic_semantic_unknown_is_flagged_not_invented_navigation():
    b=batch();a=adapter();f=feature_rows(b,platform=a)[0]['features']
    assert f['unknown_semantic_ratio']==1 and f['navigation_count']==0
    assert assess(b,a)['behavioral']['semantic_mapping']['unknown_records']==1
    explicit=adapter(routes={'/academy/catalog':'COURSE_VIEW'})
    assert feature_rows(b,platform=explicit)[0]['features']['course_view_request_count']==1


def test_declared_route_values_are_not_exported_in_adapter_metadata():
    a=adapter(routes={'/account/SECRET_IDENTIFIER':'PROFILE'})
    assert a.semantic_adapter().map_request('/account/SECRET_IDENTIFIER').category=='PROFILE'
    assert 'SECRET_IDENTIFIER' not in json.dumps(a.identity())


def test_moodle_legacy_roundtrip_preserves_all_existing_event_fields():
    line=(FIXTURE/'apache.log').read_text().splitlines()[0]
    old=parse_line(line,'fixture','hash',1);new=legacy_event(from_legacy(old))
    assert asdict(old)==asdict(new)


def test_cross_format_saved_model_invariance(package):
    outputs=[]
    with patch('sklearn.svm.OneClassSVM.fit',side_effect=AssertionError('No fitting')):
        for name,fmt in FORMATS:
            b=ingest((FIXTURE/name).read_bytes(),format=fmt)
            p=predict(b,package,explain=False)['predictions']
            outputs.append([{k:v for k,v in r.items() if k not in ('source_file','source_sha256','line_numbers')} for r in p])
    assert all(o==outputs[0] for o in outputs)


def test_provenance_and_safe_export_are_deterministic_and_secret_free():
    b=batch(request_uri='/academy/catalog?password=NEVER_EXPORT',user_agent='TOKEN_NEVER_EXPORT',session_id='SESSION_NEVER_EXPORT')
    c=batch(request_uri='/academy/catalog?password=NEVER_EXPORT',user_agent='TOKEN_NEVER_EXPORT',session_id='SESSION_NEVER_EXPORT')
    assert b.events[0].safe_evidence()==c.events[0].safe_evidence()
    assert b.source['sha256']==c.source['sha256']
    assert 'NEVER_EXPORT' not in json.dumps(b.events[0].safe_evidence())+json.dumps(b.diagnostics())
    assert b.events[0].query=='password=NEVER_EXPORT'  # Required lexical signal stays in memory.


def test_generic_branch1_reuses_rules_and_explicitly_gates_moodle_controls():
    target=AuthorizedTarget('http://192.0.2.20/academy/',True,scan_profile='STANDARD')
    response=Mock(status_code=200,url=target.target_url,headers={},text='ordinary public page')
    client=Mock();client.deadline=99999999;client.transcript=[]
    client.get.return_value=client.options.return_value=client.trace.return_value=response
    result=collect_generic(ROOT,'fixture',target,client_factory=lambda *a:client)
    assert result['status']=='COMPLETE' and result['provenance']['moodle_collector_run'] is False
    rows={r['finding_id']:r for r in result['findings']}
    assert rows['HDR-002']['check_result']=='FAIL'
    assert rows['AUTH-001']['check_result']=='NOT_APPLICABLE'
    assert rows['FS-001']['current_state']=='NOT_AVAILABLE'
    assert rows['FS-001']['prerequisite_reason']
    assert applicability({'finding_id':'ROLE-student-test'})=='ROLE_CONTEXT_REQUIRED'
    from posture.model import deduplicate
    from fusion.pipeline import assemble
    canonical=deduplicate(result['findings'],target.target_url)
    scored=assemble(canonical,[],'current-generic-fixture','NO_BEHAVIOR',as_of='2026-01-01T00:00:10+00:00')
    assert scored['cqi']['cqi'] is not None


def test_generic_http_stays_authorized_scoped_and_bounded():
    target=AuthorizedTarget('http://192.0.2.20/academy/',True,scan_profile='STANDARD')
    from types import SimpleNamespace
    c=GenericScopedClient(target,SimpleNamespace(max_requests=24,max_duration_seconds=60,max_response_bytes=1000000))
    assert c.allowed_url(target.target_url)
    assert not c.allowed_url('http://192.0.2.21/academy/')
    assert not c.allowed_url('http://192.0.2.20/.env')
    assert not c.allowed_url('http://192.0.2.20/academy/unreviewed')
    assert request_plan(target)['max_requests']==request_plan(target)['unique_request_variants']*4


def test_api_returns_only_diagnostics_and_respects_control_guard():
    app=create_app()
    async def run():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),base_url='http://testserver') as c:
            body={'text':json.dumps(base(request_uri='/academy/?password=PRIVATE_VALUE'))}
            forbidden=await c.post('/api/ingestion/inspect',json=body)
            good=await c.post('/api/ingestion/inspect',json=body,headers={'X-Product-Control':'1'})
            bad=await c.post('/api/ingestion/inspect',json={'text':'{}','mapping':{'bad':'PRIVATE_VALUE'}},headers={'X-Product-Control':'1'})
            return forbidden,good,bad
    f,g,b=asyncio.run(run());assert f.status_code==403 and g.status_code==200 and b.status_code==422
    assert g.json()['capabilities']['behavioral']['execution_allowed']
    assert g.json()['events_exported'] is False and 'PRIVATE_VALUE' not in g.text+b.text


def test_accepted_model_hash_and_feature_count_unchanged():
    m=verify(ROOT/'outputs/branch2/accepted_behavioral_v2')
    assert m['root_sha256']=='59a8c7c5d3d51632d0afe45f8cd2fe50570b7af2943d26bb313888327ea9f436'
    assert len(FEATURES)==83
