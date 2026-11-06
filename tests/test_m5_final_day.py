"""Final-day contracts use artificial fixtures only, never live HTTP or labels."""
import copy
from datetime import datetime,timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import numpy as np
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'src'))
from branch2.dataset import CLASSES
from branch2.events import identifier
from behavioral_v2.platforms import GenericHTTPBehaviorAdapter,MoodleBehaviorAdapter,MoodleAuditAdapter,VOCABULARY
from behavioral_v2.features31 import schema,extract,matrix,query_context
from behavioral_v2.browser_capture import (make_plan,validate_plan,safe_url,Scope,LogBoundary,capture,CaptureError,
    MoodleBrowserProtocol,TARGET,browser_environment,PROTOCOLS,MAX_BLOCKED_REQUEST_DIAGNOSTICS,verify_capture)
from behavioral_v2.study31 import train_freeze,verify_freeze,build_development,report_predictions
from behavioral_v2.model31 import load
from behavioral_v2.compat31 import observations,fuse
from test_behavioral_v2 import event,rows as old_rows,prediction


def fixture():
    adapter=GenericHTTPBehaviorAdapter({'/signin':'AUTH_LOGIN','/workspace':'DASHBOARD'})
    s=schema(adapter);rs=[]
    for part in ('TRAIN','VALIDATION'):
        ids=sorted(s['session_id'] for s in make_plan()['sessions'] if s['partition']==part)
        for label in CLASSES:
            count=16 if part=='TRAIN' and label=='BENIGN' else 8 if label=='BENIGN' else 4
            for i,r in enumerate(old_rows(part,count=count,label=label)):
                r['run_id']=ids[i%len(ids)] if label=='BENIGN' else f'UNIT-{part}-{label}-{i//2}';r['schema_sha256']=s['sha256']
                r['features']['sql_token_count']=float(CLASSES.index(label))
                r['features']['active_span']=0. if part=='TRAIN' else 1000.
                rs.append(r)
    return {'dataset_version':'UNIT_TEST_ONLY','feature_schema':s,'rows':rs,'sources':{},'capture_manifest_sha256':{},
        'capture_plan_sha256':make_plan()['sha256'],'split_manifest':{
            'train_runs':sorted({r['run_id'] for r in rs if r['partition']=='TRAIN'}),
            'validation_runs':sorted({r['run_id'] for r in rs if r['partition']=='VALIDATION'}),
            'fresh_test_reserved_ids':[s['session_id'] for s in make_plan()['sessions'] if s['partition']=='TEST']}}


def unit_development_review(root,plan):
    """Synthetic review fixture; real source replay is mocked explicitly."""
    from behavioral_v2.development_review import review_development
    entries=[s for s in plan['sessions'] if s['partition']!='TEST']
    receipts=[{'session_id':s['session_id'],'verified':True,'accepted_records':1,'foreign_records':0,
        'capture_manifest_sha256':hashlib.sha256((root/'browser_sessions'/s['session_id']/'manifest.json').read_bytes()).hexdigest()}
        for s in entries]
    path=root/'unit_collection.json';path.write_text(json.dumps({'status':'COMPLETE','plan_sha256':plan['sha256'],
        'test_files_opened':False,'test_capture_performed':False,'models_invoked':False,'verification_receipts':receipts}))
    def verified(unused,unused_plan,sid):
        return {'session_id':sid,'verified':True,'accepted_records':1,'foreign_records':0,
            'ownership_filtering_reproduced':True,'source_bytes_verified':True,'network_requests':0}
    with patch('behavioral_v2.development_review.verify_capture',side_effect=verified),patch('behavioral_v2.development_review.frozen_core_unchanged',return_value=True):
        review=review_development(root,path,[],root)
    (root/'development_review.json').write_text(json.dumps(review));return review


class AdapterTests(unittest.TestCase):
    def test_platform_independent_vocabulary(self):
        self.assertIn('CONTENT_VIEW',VOCABULARY);self.assertIn('ADMIN_ACTION',VOCABULARY)
        self.assertNotIn('THEME_RESOURCE',VOCABULARY)
    def test_moodle_routes(self):
        adapter=MoodleBehaviorAdapter()
        pairs={'/moodle/login/index.php':'AUTH_LOGIN','/moodle/login/logout.php':'AUTH_LOGOUT',
            '/moodle/my/':'DASHBOARD','/moodle/course/view.php':'COURSE_VIEW',
            '/moodle/mod/page/view.php':'CONTENT_VIEW','/moodle/user/preferences.php':'PROFILE',
            '/moodle/report/log/index.php':'ADMIN_ACTION','/moodle/lib/ajax/service.php':'AJAX_SERVICE',
            '/moodle/theme/styles.php':'STATIC_ASSET','/moodle/search/index.php':'SEARCH'}
        for p,c in pairs.items():self.assertEqual(adapter.map_request(p).category,c)
    def test_generic_contract_has_no_moodle_path_requirement(self):
        generic=GenericHTTPBehaviorAdapter({'/signin':'AUTH_LOGIN','/workspace':'DASHBOARD'})
        f=extract([event('/signin'),event('/workspace'),event('/main.css')],generic)
        self.assertEqual(f['auth_request_count'],1);self.assertEqual(f['dashboard_request_count'],1)
        self.assertEqual(f['asset_request_count'],1);self.assertEqual(len(f),83)
        row={'features':f,'schema_sha256':schema(generic)['sha256']}
        self.assertEqual(matrix([row],schema(generic)).shape,(1,83))
    def test_equivalent_semantic_mix_across_adapters(self):
        g=GenericHTTPBehaviorAdapter({'/signin':'AUTH_LOGIN','/workspace':'DASHBOARD'})
        a=extract([event('/signin'),event('/workspace'),event('/a.css')],g)
        b=extract([event('/moodle/login/index.php'),event('/moodle/my/'),event('/moodle/a.css')],MoodleBehaviorAdapter())
        for k in ('auth_request_count','navigation_count','asset_ratio','dashboard_request_count','semantic_request_rate'):
            self.assertEqual(a[k],b[k])
    def test_adapter_identity_changes_with_route_configuration(self):
        a=GenericHTTPBehaviorAdapter({'/x':'DASHBOARD'});b=GenericHTTPBehaviorAdapter({'/x':'COURSE_VIEW'})
        self.assertNotEqual(schema(a)['sha256'],schema(b)['sha256'])
    def test_schema_hash_and_order_fail_closed(self):
        d=fixture();matrix(d['rows'],d['feature_schema']);bad=copy.deepcopy(d['feature_schema']);bad['feature_order'].reverse()
        with self.assertRaises(ValueError):matrix(d['rows'],bad)
    def test_raw_query_features_retained_not_erased_as_benign(self):
        es=[event('/moodle/lib/ajax/service.php',query='args=%5B%7B%22x%22%3A1%7D%5D')]
        f=extract(es,MoodleBehaviorAdapter());q=query_context(es,MoodleBehaviorAdapter())
        self.assertGreater(f['quote_count'],0);self.assertEqual(q['AJAX_SERVICE']['valid_JSON_args_requests'],1)
    def test_audit_success_and_failure_are_distinct(self):
        a=MoodleAuditAdapter(b'unit-test-study-key-32-bytes-long')
        first=a.convert({'eventname':'\\core\\event\\user_loggedin','userid':7,'timecreated':1,'other':'password=fixture-secret'})
        second=a.convert({'eventname':'\\core\\event\\user_login_failed','userid':7,'timecreated':2})
        self.assertEqual(first['category'],'AUTH_LOGIN');self.assertEqual(first['authentication_outcome'],'SUCCEEDED')
        self.assertEqual(second['authentication_outcome'],'FAILED');self.assertEqual(first['actor_id'],second['actor_id'])
        self.assertNotIn('fixture-secret',json.dumps(first));self.assertIsNone(first['role'])
    def test_audit_hmac_domain_separation_and_key_required(self):
        with self.assertRaises(ValueError):MoodleAuditAdapter(b'')
        a=MoodleAuditAdapter(b'unit-test-study-key-32-bytes-long')
        e=a.convert({'timecreated':1,'userid':7,'courseid':7,'role':'teacher'})
        self.assertNotEqual(e['actor_id'],e['course_id']);self.assertEqual(e['role'],'teacher')


class PlanAndScopeTests(unittest.TestCase):
    def test_deterministic_reserved_12_6_6(self):
        a=make_plan();self.assertEqual(a,make_plan());validate_plan(a)
        self.assertEqual(a['split_counts'],{'TRAIN':12,'VALIDATION':6,'TEST':6})
        self.assertEqual(len({s['session_id'] for s in a['sessions']}),24)
        self.assertTrue(all(s['model_result'] is None for s in a['sessions']))
    def test_protocol_breadth_and_safe_variation(self):
        a=make_plan();self.assertEqual({s['protocol'] for s in a['sessions'] if s['partition']=='TRAIN'},set(PROTOCOLS))
        self.assertGreater(len({s['seed'] for s in a['sessions']}),20)
        self.assertTrue(all(s['max_http_requests']==2500 for s in a['sessions']))
    def test_plan_tampering_rejected(self):
        a=make_plan();a['sessions'][0]['partition']='TRAIN'
        with self.assertRaises(CaptureError):validate_plan(a)
    def test_dry_run_zero_network_and_zero_logs(self):
        spec=importlib.util.spec_from_file_location('browser_cli',ROOT/'scripts/run_m5_browser_capture.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
        with tempfile.TemporaryDirectory() as tmp:
            m.ROOT=Path(tmp);root=m.ROOT/'outputs/branch2/m5_final_day';root.mkdir(parents=True)
            (root/'predeclared_capture_plan.json').write_text(json.dumps(make_plan()))
            with patch('socket.socket',side_effect=AssertionError('Network forbidden')),patch('behavioral_v2.browser_capture.LogBoundary',side_effect=AssertionError('Log read forbidden')),patch('builtins.print'):
                self.assertEqual(m.main(['capture','--root',str(root),'--partition','TRAIN','--dry-run']),0)
    def test_unauthorized_execution_rejected_before_any_log_read(self):
        s=next(s for s in make_plan()['sessions'] if s['partition']=='TRAIN')
        with patch('behavioral_v2.browser_capture.LogBoundary',side_effect=AssertionError('No log read')):
            with self.assertRaises(CaptureError):capture(make_plan(),s['session_id'],'/unused')
    def test_test_capture_requires_freeze_even_through_api(self):
        s=next(s for s in make_plan()['sessions'] if s['partition']=='TEST')
        with self.assertRaises(CaptureError):capture(make_plan(),s['session_id'],'/unused',authorized=True)
    def test_missing_credentials_does_not_launch_or_touch_logs(self):
        s=next(s for s in make_plan()['sessions'] if s['partition']=='TRAIN')
        with patch.dict(os.environ,{},clear=True),patch('behavioral_v2.browser_capture.LogBoundary',side_effect=AssertionError('No logs')):
            with self.assertRaises(CaptureError):capture(make_plan(),s['session_id'],'/unused',authorized=True)
    def test_scope_origin_mount_and_encoded_traversal(self):
        for url in ('https://evil.test/moodle/','http://192.168.226.132:81/moodle/',TARGET+'%2e%2e/config.php',TARGET+'%252e%252e/config.php','http://u:p@192.168.226.132/moodle/','http://x:bad/'):
            self.assertFalse(safe_url(url),url)
        self.assertTrue(safe_url(TARGET+'my/'))
        self.assertTrue(safe_url(TARGET.rstrip('/')))
        self.assertFalse(safe_url('http://192.168.226.132/moodle-other/'))
    def test_budget_enforced(self):
        scope=Scope(limit=1);calls=[]
        r=SimpleNamespace(request=SimpleNamespace(url=TARGET+'my/',method='GET'),abort=lambda:calls.append('abort'),continue_=lambda:calls.append('continue'))
        scope.route(r);scope.route(r);self.assertEqual(calls,['continue','abort']);self.assertEqual(scope.error,'REQUEST_BUDGET')
    def test_off_origin_never_followed(self):
        scope=Scope();calls=[]
        scope.route(SimpleNamespace(request=SimpleNamespace(url='http://evil.test/',method='GET'),abort=lambda:calls.append('abort'),continue_=lambda:calls.append('continue')))
        self.assertEqual(calls,['abort'])
    def test_credentials_not_in_browser_environment(self):
        with patch.dict(os.environ,{'M5_STUDENT_PASSWORD':'fixture-secret','B1_ADMIN_COOKIE':'fixture-cookie'}):
            env=browser_environment({'local_library_path':'/nonexistent'})
        self.assertNotIn('fixture-secret',env.values());self.assertNotIn('fixture-cookie',env.values())


class BrowserScopeRegressionTests(unittest.TestCase):
    def routed(self,scope,url,kind='image',navigation=False,method='GET'):
        calls=[]
        request=SimpleNamespace(url=url,method=method,resource_type=kind,
            is_navigation_request=lambda:navigation)
        route=SimpleNamespace(request=request,abort=lambda:calls.append('abort'),
            continue_=lambda:calls.append('continue'))
        with patch('socket.socket',side_effect=AssertionError('No network')):
            scope.route(route)
        return calls

    def test_external_image_font_script_blocked_nonfatal(self):
        for kind in ('image','font','script'):
            with self.subTest(kind=kind):
                scope=Scope()
                self.assertEqual(self.routed(scope,'https://assets.example.invalid/file',kind),['abort'])
                self.assertIsNone(scope.error);self.assertEqual(scope.requests,0)
                self.assertEqual(scope.blocked_off_scope_requests_count,1)
                self.assertEqual(scope.audit()['blocked_off_scope_requests'][0]['resource_type'],kind)
                self.assertEqual(self.routed(scope,TARGET+'my/'),['continue'])

    def test_same_host_outside_moodle_subresources_blocked_nonfatal(self):
        scope=Scope()
        for path in ('/favicon.ico','/assets/site.css','/moodle-other/file.js'):
            self.assertEqual(self.routed(scope,'http://192.168.226.132'+path),['abort'])
        self.assertIsNone(scope.error);self.assertEqual(scope.blocked_off_scope_requests_count,3)

    def test_off_scope_navigation_fatal_including_same_host(self):
        for url in ('https://external.example.invalid/','http://192.168.226.132/other/',
            TARGET+'%2e%2e/secret'):
            with self.subTest(url=url):
                scope=Scope()
                self.assertEqual(self.routed(scope,url,'document',True),['abort'])
                self.assertEqual(scope.error,'OFF_SCOPE_NAVIGATION')
                self.assertTrue(scope.audit()['blocked_off_scope_requests'][0]['is_navigation_request'])

    def test_all_frame_navigation_fails_closed_without_frame_access(self):
        # An early navigation need not have a Request.frame; the installed
        # is_navigation_request() API also conservatively covers child frames.
        scope=Scope()
        self.routed(scope,'https://frame.example.invalid/','document',True)
        self.assertEqual(scope.error,'OFF_SCOPE_NAVIGATION')

    def test_allowed_get_post_head_continued(self):
        scope=Scope()
        for method in ('GET','POST','HEAD'):
            self.assertEqual(self.routed(scope,TARGET+'login/index.php','document',True,method),['continue'])
        self.assertIsNone(scope.error);self.assertEqual(scope.requests,3)
        self.assertEqual(scope.blocked_off_scope_requests_count,0)

    def test_unexpected_method_fatal_even_for_external_subresource(self):
        for url in (TARGET+'my/','https://assets.example.invalid/'):
            scope=Scope()
            self.assertEqual(self.routed(scope,url,method='DELETE'),['abort'])
            self.assertEqual(scope.error,'UNEXPECTED_HTTP_METHOD');self.assertEqual(scope.requests,0)

    def test_budget_unchanged_and_applies_to_blocked_resources(self):
        scope=Scope(limit=1)
        self.assertEqual(self.routed(scope,'https://assets.example.invalid/'),['abort'])
        self.assertEqual(self.routed(scope,TARGET+'my/'),['continue'])
        self.assertEqual(self.routed(scope,'https://assets.example.invalid/'),['abort'])
        self.assertEqual(scope.error,'REQUEST_BUDGET');self.assertEqual(scope.requests,1)

    def test_deadline_fatal_even_for_external_subresource(self):
        for url in (TARGET+'my/','https://assets.example.invalid/'):
            scope=Scope(deadline=10)
            with patch('behavioral_v2.browser_capture.time.monotonic',return_value=11):
                self.assertEqual(self.routed(scope,url),['abort'])
            self.assertEqual(scope.error,'SESSION_DEADLINE');self.assertEqual(scope.requests,0)

    def test_fatal_error_sticky(self):
        scope=Scope()
        self.routed(scope,'https://external.example.invalid/','document',True)
        self.assertEqual(self.routed(scope,TARGET+'my/'),['abort'])
        self.assertEqual(scope.error,'OFF_SCOPE_NAVIGATION');self.assertEqual(scope.requests,0)

    def test_diagnostics_never_export_query_fragment_userinfo_or_sensitive_path(self):
        scope=Scope()
        self.routed(scope,'https://fixture-user:fixture-password@cdn.example.invalid/private/fixture-token?token=fixture-query#fixture-fragment')
        audit=scope.audit();text=json.dumps(audit)
        for secret in ('fixture-user','fixture-password','fixture-token','fixture-query','fixture-fragment'):
            self.assertNotIn(secret,text)
        item=audit['blocked_off_scope_requests'][0]
        self.assertEqual(item['host'],'cdn.example.invalid');self.assertEqual(item['scheme'],'https')
        self.assertEqual(item['path'],'[REDACTED]');self.assertFalse(item['is_navigation_request'])
        self.assertIsNone(scope.error)

    def test_diagnostics_bounded_and_fixed_technical_path_retained(self):
        scope=Scope()
        for _ in range(MAX_BLOCKED_REQUEST_DIAGNOSTICS+7):
            self.routed(scope,'http://192.168.226.132/favicon.ico?token=secret')
        audit=scope.audit()
        self.assertEqual(audit['blocked_off_scope_requests_count'],MAX_BLOCKED_REQUEST_DIAGNOSTICS+7)
        self.assertEqual(len(audit['blocked_off_scope_requests']),MAX_BLOCKED_REQUEST_DIAGNOSTICS)
        self.assertEqual(audit['blocked_off_scope_requests_omitted_count'],7)
        self.assertEqual(audit['blocked_off_scope_requests'][0]['path'],'/favicon.ico')

    def test_missing_or_malformed_navigation_context_fails_closed(self):
        for navigation in (None,'false'):
            scope=Scope()
            self.assertEqual(self.routed(scope,'https://external.example.invalid/',navigation=navigation),['abort'])
            self.assertEqual(scope.error,'REQUEST_CONTEXT_UNAVAILABLE')

    def test_invalid_url_diagnostics_do_not_raise_or_export_raw_input(self):
        scope=Scope()
        self.routed(scope,'http://[fixture-secret')
        self.assertIsNone(scope.error)
        self.assertNotIn('fixture-secret',json.dumps(scope.audit()))

    def test_preserved_failed_acceptance_hashes_when_available(self):
        root=ROOT/'outputs/branch2/m5_final_day/browser_sessions/M5FD-20261014-001'
        if not root.exists():self.skipTest('Local acceptance evidence is not distributed')
        expected={'features.json':'37517e5f3dc66819f61f5a7bb8ace1921282415f10551d2defa5c3eb0985b570',
            'v1_features.json':'37517e5f3dc66819f61f5a7bb8ace1921282415f10551d2defa5c3eb0985b570',
            'manifest.json':'d2901801172e7030d24c96edb9f1fdfc14084d46984ca8cc023db27216928568'}
        self.assertEqual({p.name for p in root.iterdir()},set(expected))
        for name,value in expected.items():
            self.assertEqual(hashlib.sha256((root/name).read_bytes()).hexdigest(),value)

    def test_second_failed_acceptance_hashes_when_available(self):
        root=ROOT/'outputs/branch2/m5_final_day/browser_sessions/M5FD-20261014-002'
        if not root.exists():self.skipTest('Local acceptance evidence is not distributed')
        expected={'features.json':'37517e5f3dc66819f61f5a7bb8ace1921282415f10551d2defa5c3eb0985b570',
            'v1_features.json':'37517e5f3dc66819f61f5a7bb8ace1921282415f10551d2defa5c3eb0985b570',
            'manifest.json':'d10a21d2b25596aea4eeb473091ab067e8928dda96a2f1943fe7880182a7bd27'}
        self.assertEqual({p.name for p in root.iterdir()},set(expected))
        for name,value in expected.items():
            self.assertEqual(hashlib.sha256((root/name).read_bytes()).hexdigest(),value)


def log_line(agent='FixtureBrowser',actor='192.0.2.1',target='/moodle/my/'):
    return f'{actor} - - [01/Jan/2020:00:00:01 +0000] "GET {target} HTTP/1.1" 200 100 "-" "{agent}"\n'


class BoundaryTests(unittest.TestCase):
    def setUp(self):
        clock=patch('behavioral_v2.browser_capture.now',return_value='2020-01-01T00:00:01+00:00')
        clock.start();self.addCleanup(clock.stop)
    def test_exact_byte_range_excludes_earlier_log(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'access.log';path.write_text(log_line('old'))
            b=LogBoundary(path);start=path.stat().st_size
            with path.open('a') as f:f.write(log_line())
            es,p=b.close('unit','192.0.2.1','FixtureBrowser')
            self.assertEqual(len(es),1);self.assertEqual(p['offset_start'],start)
            self.assertEqual(p['slice_sha256'],hashlib.sha256(log_line().encode()).hexdigest())
    def test_foreign_actor_or_user_agent_excluded_with_provenance(self):
        for foreign in (log_line('OtherBrowser'),log_line(actor='192.0.2.2')):
            with tempfile.TemporaryDirectory() as tmp:
                path=Path(tmp)/'log';path.write_text('');b=LogBoundary(path)
                path.write_text(log_line()+foreign);es,p=b.close('unit','192.0.2.1','FixtureBrowser')
                self.assertEqual(len(es),1);self.assertEqual(p['foreign_records'],1)
                self.assertEqual(p['accepted_records'],1);self.assertTrue(p['ownership_filtering_enabled'])
    def test_malformed_records_not_silently_removed(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'log';path.write_text('');b=LogBoundary(path);path.write_text(log_line()+'malformed\n')
            es,p=b.close('unit','192.0.2.1','FixtureBrowser');self.assertFalse(es);self.assertEqual(p['malformed_records'],1)
    def test_truncation_and_partial_record_rejected(self):
        for partial in (True,False):
            with tempfile.TemporaryDirectory() as tmp:
                path=Path(tmp)/'log';path.write_text('old\n' if not partial else '');b=LogBoundary(path)
                path.write_text('x' if partial else '')
                with self.assertRaises(CaptureError):b.close('unit','192.0.2.1','FixtureBrowser')
    def test_human_marker_supported_without_secret_cookie(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'log';path.write_text('');b=LogBoundary(path);path.write_text(log_line('Chrome M5Human/H1'))
            es,p=b.close('H1','192.0.2.1','marker:M5Human/H1');self.assertEqual(len(es),1)
    def test_outside_server_time_invalidates_capture(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/'log';p.write_text('');b=LogBoundary(p)
            p.write_text(log_line().replace('00:00:01','01:00:01'));es,proof=b.close('unit','192.0.2.1','FixtureBrowser')
            self.assertEqual(es,[]);self.assertEqual(proof['outside_capture_time_records'],1)

    def test_session_marker_and_actor_are_both_required(self):
        ua='FixtureBrowser M5Capture/unit'
        foreign=(log_line('FixtureBrowser M5Capture/other'),log_line(ua,actor='192.0.2.2'),
            log_line('DifferentBrowser M5Capture/unit'),log_line(ua+'-suffix'))
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'log';path.write_text('');b=LogBoundary(path)
            path.write_text(log_line(ua)+''.join(foreign))
            events,p=b.close('unit','192.0.2.1',ua)
            self.assertEqual(len(events),1);self.assertEqual(p['accepted_records'],1)
            self.assertEqual(p['foreign_records'],4)
            self.assertEqual(p['session_marker'],'M5Capture/unit')
            self.assertEqual(p['session_marker_sha256'],identifier('M5Capture/unit'))
            self.assertEqual(p['expected_actor_id'],identifier('192.0.2.1'))

    def test_raw_and_accepted_record_ranges_hashes_preserved(self):
        ua='FixtureBrowser M5Capture/unit';old=log_line('earlier')
        owned=log_line(ua);foreign=log_line('OtherBrowser')
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'log';path.write_text(old);b=LogBoundary(path)
            with path.open('a') as f:f.write(foreign+owned+foreign)
            events,p=b.close('unit','192.0.2.1',ua);start=len(old.encode())
            expected=[]
            for line in (foreign,owned,foreign):
                raw=line.encode();expected.append({'start':start,'end':start+len(raw),'sha256':hashlib.sha256(raw).hexdigest()});start+=len(raw)
            self.assertEqual(p['source_byte_ranges'],expected)
            self.assertEqual(p['accepted_source_byte_ranges'],expected[1:2])
            self.assertEqual(p['slice_sha256'],hashlib.sha256((foreign+owned+foreign).encode()).hexdigest())
            self.assertEqual(events[0].line_number,expected[1]['start']+1)
            self.assertEqual(p['offset_end'],start)

    def test_dummy_record_excluded_even_with_matching_actor_and_marker(self):
        ua='Apache (internal dummy connection) M5Capture/unit'
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'log';path.write_text('');b=LogBoundary(path)
            path.write_text(log_line(ua,actor='127.0.0.1')+log_line(ua,actor='127.0.0.1',target='*').replace('"GET *','"OPTIONS *'))
            events,p=b.close('unit','127.0.0.1',ua)
            self.assertEqual(len(events),1);self.assertEqual(p['foreign_records'],1)
            self.assertTrue(p['dummy_filtering'])


class FakeField:
    def __init__(self,form,name,count=1):self.form=form;self.name=name;self.n=count
    @property
    def first(self):return self
    def count(self):return self.n
    def input_value(self):return self.form.values.get(self.name,'')
    def get_attribute(self,name):return 'hidden' if getattr(self.form,'formid','login')=='guestlogin' else 'password' if self.name=='password' else 'text'
    def fill(self,value):self.form.values[self.name]=value
    def click(self,**kwargs):self.form.page.clicks+=1;self.form.page.url=TARGET+'login/index.php'


class FakeForm:
    def __init__(self,page,action='index.php',tokens=1,value='fixture-token'):
        self.page=page;self.action=action;self.tokens=tokens;self.values={'logintoken':value};self.formid='login'
    def get_attribute(self,name):return {'method':'post','action':self.action,'id':self.formid}.get(name)
    def locator(self,selector):
        name='logintoken' if 'logintoken' in selector else 'username' if 'username' in selector else 'password' if 'password' in selector else 'submit'
        return FakeField(self,name,self.tokens if name=='logintoken' else 1)


class FakeList:
    def __init__(self,values):self.values=values
    @property
    def first(self):return self.values[0]
    def count(self):return len(self.values)
    def nth(self,i):return self.values[i]


class FakePage:
    def __init__(self):
        self.url=TARGET+'login/index.php';self.forms=[FakeForm(self)];self.gets=0;self.clicks=0
    def goto(self,url,**kwargs):self.gets+=1;self.url=url;return SimpleNamespace(status=200)
    def wait_for_timeout(self,*args):pass
    def wait_for_load_state(self,*args,**kwargs):pass
    def locator(self,selector):
        if selector=='form':return FakeList(self.forms)
        if selector=='#loginerrormessage,.loginerrors':return FakeList([SimpleNamespace(inner_text=lambda:'Invalid login')])
        raise AssertionError('Unexpected fixture selector')


class LoginTests(unittest.TestCase):
    def protocol(self,page):return MoodleBrowserProtocol(page,'student',42,Scope(),('fixture-user','fixture-secret'),'identity')
    def test_fresh_login_state_per_incorrect_attempt(self):
        page=FakePage();p=self.protocol(page);p.login(wrong=True);p.login(wrong=True)
        self.assertEqual(page.gets,2);self.assertEqual(page.clicks,2)
        self.assertTrue(all('fixture-secret' not in json.dumps(a) for a in p.actions))
    def test_wrong_endpoint_and_off_origin_action_rejected(self):
        for action in ('http://evil.test/login/index.php',TARGET+'other.php'):
            page=FakePage();page.forms=[FakeForm(page,action)]
            with self.assertRaises(CaptureError):self.protocol(page).login(wrong=True)
            self.assertEqual(page.clicks,0)
    def test_duplicate_qualifying_form_rejected(self):
        page=FakePage();page.forms.append(FakeForm(page))
        with self.assertRaises(CaptureError):self.protocol(page).login(wrong=True)
    def test_installed_moodle_guest_form_is_not_a_competing_credential_form(self):
        page=FakePage();guest=FakeForm(page);guest.formid='guestlogin';page.forms.append(guest)
        self.protocol(page).login(wrong=True)
        self.assertEqual(page.clicks,1)
    def test_missing_duplicate_empty_tokens_rejected(self):
        for count,value in ((0,''),(2,'token'),(1,'')):
            page=FakePage();page.forms=[FakeForm(page,tokens=count,value=value)]
            with self.assertRaises(CaptureError):self.protocol(page).login(wrong=True)
    def test_no_simple_http_fallback(self):
        source=(ROOT/'src/behavioral_v2/browser_capture.py').read_text()
        self.assertNotIn('import requests',source);self.assertNotIn('urllib.request',source)


class BrowserExecutionTests(unittest.TestCase):
    def browser(self):
        contexts=[]
        class Context:
            def __init__(self,kwargs):self.user_agent=kwargs.get('user_agent','FixtureBrowser');self.closed=False
            def new_page(self):return SimpleNamespace(evaluate=lambda code:'FixtureBrowser')
            def close(self):self.closed=True
            def route(self,*args):pass
        class Browser:
            closed=False
            def new_context(self,**kwargs):
                c=Context(kwargs);contexts.append(c);return c
            def close(self):self.closed=True
        return Browser(),contexts
    def perform(self,kind,with_features=False,verifier=None):
        plan=make_plan();session=next(s for s in plan['sessions'] if s['partition']=='TRAIN')
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);log=root/'input.log';log.write_text('');browser,contexts=self.browser()
            def run(protocol,unused):
                protocol.identity_verified=kind!='unverified'
                if kind=='blocked':
                    BrowserScopeRegressionTests().routed(protocol.scope,
                        'https://fixture-user:fixture-secret@cdn.example.invalid/fixture-token?token=fixture-secret')
                    self.assertIsNone(protocol.scope.error)
                line=log_line(contexts[-1].user_agent,target='/moodle/my/?token=fixture-secret')
                with log.open('a') as f:
                    f.write(line*(184 if kind in ('owned184','ambient188') else 1))
                    if kind=='foreign':f.write(log_line('UnrelatedBrowser'))
                    if kind=='ambient188':
                        f.write(log_line('UnrelatedBrowser',target='/moodle/admin/'))
                        f.write(log_line(contexts[-1].user_agent,actor='192.0.2.2',target='/moodle/admin/'))
                        f.write(log_line('FixtureBrowser M5Capture/another-session',target='/moodle/admin/'))
                        f.write(log_line('Apache (internal dummy connection)',actor='127.0.0.1',target='*').replace('"GET *','"OPTIONS *'))
                    if kind=='malformed':f.write('malformed\n')
                    if kind=='outside_time':f.write(line.replace('00:00:01','01:00:01'))
                    if kind=='no_owned':
                        f.seek(0);f.truncate();f.write(log_line('UnrelatedBrowser'))
                if kind=='error':raise RuntimeError('fixture-secret password and fixture-token')
                protocol.actions.append({'action':'synthetic-unit-protocol','outcome':'UNIT_TEST_ONLY'})
            env={'M5_STUDENT_USERNAME':'fixture-user','M5_STUDENT_PASSWORD':'fixture-secret','M5_STUDENT_IDENTITY_MARKER':'fixture-marker'}
            with patch.dict(os.environ,env,clear=True),patch.object(MoodleBrowserProtocol,'run',run),patch('socket.socket',side_effect=AssertionError('No HTTP')),patch('behavioral_v2.browser_capture.now',return_value='2020-01-01T00:00:01+00:00'):
                result=capture(plan,session['session_id'],root/'out/browser_sessions',authorized=True,actor='192.0.2.1',log=log,browser_factory=lambda:browser)
                if verifier is not None:verifier(root/'out',plan,session,result)
            text=''.join(p.read_text() for p in (root/'out').rglob('*.json'))
            self.assertNotIn('fixture-secret',text);self.assertNotIn('fixture-token',text)
            self.assertTrue(browser.closed);self.assertTrue(all(c.closed for c in contexts))
            if with_features:
                vectors={name:[row['features'] for row in json.loads((root/'out/browser_sessions'/session['session_id']/name).read_text())]
                    for name in ('features.json','v1_features.json')}
                return result,vectors
            return result
    def test_success_exports_features_and_hashes_not_credentials(self):
        r=self.perform('success');self.assertEqual(r['status'],'COMPLETE');self.assertGreater(r['windows'],0)
        self.assertFalse(r['model_invoked']);self.assertFalse(r['provenance']['raw_log_persisted'])
    def test_browser_error_does_not_export_exception_secrets(self):
        r=self.perform('error');self.assertEqual(r['status'],'INVALID');self.assertIsNone(r['label'])
        self.assertEqual(r['error_code'],'BOUNDED_BROWSER_OR_TRANSPORT_FAILURE')
    def test_blocked_subresource_audit_persisted_without_invalidating_or_feature_leakage(self):
        baseline,base_vectors=self.perform('success',with_features=True)
        r,vectors=self.perform('blocked',with_features=True)
        self.assertEqual(r['status'],'COMPLETE');self.assertEqual(r['windows'],baseline['windows'])
        # Provenance file paths differ between temporary captures; compare the
        # actual ML inputs, not hashes that intentionally bind those paths.
        self.assertEqual(vectors,base_vectors)
        self.assertEqual(r['blocked_off_scope_requests_count'],1)
        self.assertEqual(r['blocked_off_scope_requests'][0]['path'],'[REDACTED]')
        self.assertFalse(r['model_invoked'])
    def test_ambient_traffic_excluded_without_invalidating_owned_capture(self):
        r=self.perform('foreign');self.assertEqual(r['status'],'COMPLETE');self.assertGreater(r['windows'],0)
        self.assertEqual(r['provenance']['observed_records'],2);self.assertEqual(r['provenance']['foreign_records'],1)

    def test_184_owned_plus_4_foreign_like_records_valid_and_features_unchanged(self):
        baseline,base_vectors=self.perform('owned184',with_features=True)
        r,vectors=self.perform('ambient188',with_features=True)
        self.assertEqual(r['status'],'COMPLETE');self.assertEqual(vectors,base_vectors)
        p=r['provenance'];self.assertEqual(p['observed_records'],188)
        self.assertEqual(p['accepted_records'],184);self.assertEqual(p['foreign_records'],4)
        self.assertEqual(len(p['source_byte_ranges']),188)
        self.assertEqual(len(p['accepted_source_byte_ranges']),184)
        self.assertTrue(p['ambient_traffic_present']);self.assertTrue(p['filtering_applied'])
        self.assertEqual(p['attribution_policy'],'capture-marker-and-actor-v1')
        self.assertFalse(r['model_invoked'])

    def test_verifier_replays_owned_and_foreign_source_records(self):
        def verify(root,plan,session,result):
            checked=verify_capture(root,plan,session['session_id'])
            self.assertTrue(checked['verified']);self.assertTrue(checked['ownership_filtering_reproduced'])
            self.assertEqual(checked['source_records'],188);self.assertEqual(checked['accepted_records'],184)
            self.assertEqual(checked['foreign_records'],4);self.assertEqual(checked['network_requests'],0)
        self.perform('ambient188',verifier=verify)

    def test_authenticated_identity_retained_after_later_integrity_or_protocol_error(self):
        for kind in ('malformed','outside_time','error','no_owned'):
            with self.subTest(kind=kind):
                r=self.perform(kind);self.assertEqual(r['status'],'INVALID')
                self.assertTrue(r['authenticated_identity_verified']);self.assertEqual(r['windows'],0)
                self.assertIsNone(r['label'])

    def test_identity_is_not_inferred_without_protocol_verification(self):
        r=self.perform('unverified');self.assertEqual(r['status'],'INVALID')
        self.assertFalse(r['authenticated_identity_verified']);self.assertEqual(r['error_code'],'IDENTITY_UNVERIFIED')

    def test_malformed_and_outside_time_still_fail_closed(self):
        for kind,key in (('malformed','malformed_records'),('outside_time','outside_capture_time_records')):
            r=self.perform(kind);self.assertEqual(r['status'],'INVALID')
            self.assertEqual(r['error_code'],'CONTAMINATED_CAPTURE');self.assertEqual(r['provenance'][key],1)

    def test_only_ambient_has_no_usable_observations(self):
        r=self.perform('no_owned');self.assertEqual(r['status'],'INVALID')
        self.assertEqual(r['error_code'],'NO_USABLE_OBSERVATIONS')
        self.assertEqual(r['provenance']['accepted_records'],0)
        self.assertEqual(r['provenance']['foreign_records'],1)

    def test_verifier_rejects_changed_owned_ranges(self):
        def tamper(root,plan,session,result):
            path=root/'browser_sessions'/session['session_id']/'manifest.json'
            manifest=json.loads(path.read_text())
            manifest['provenance']['accepted_source_byte_ranges'][0]=manifest['provenance']['source_byte_ranges'][-1]
            path.write_text(json.dumps(manifest))
            with self.assertRaises(CaptureError):verify_capture(root,plan,session['session_id'])
        self.perform('ambient188',verifier=tamper)

    def test_verifier_rejects_changed_raw_record_ranges(self):
        def tamper(root,plan,session,result):
            path=root/'browser_sessions'/session['session_id']/'manifest.json'
            manifest=json.loads(path.read_text());manifest['provenance']['source_byte_ranges'][-1]['sha256']='0'*64
            path.write_text(json.dumps(manifest))
            with self.assertRaises(CaptureError):verify_capture(root,plan,session['session_id'])
        self.perform('ambient188',verifier=tamper)

    def test_verifier_rejects_posthoc_foreign_feature_inclusion(self):
        def tamper(root,plan,session,result):
            base=root/'browser_sessions'/session['session_id'];path=base/'features.json'
            rows=json.loads(path.read_text());rows[0]['features']['request_count']+=4
            path.write_text(json.dumps(rows));manifest=json.loads((base/'manifest.json').read_text())
            manifest['features_sha256']=hashlib.sha256(path.read_bytes()).hexdigest()
            (base/'manifest.json').write_text(json.dumps(manifest))
            with self.assertRaisesRegex(CaptureError,'FEATURE_REPLAY_MISMATCH'):
                verify_capture(root,plan,session['session_id'])
        self.perform('ambient188',verifier=tamper)


class ModelFreezeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp=tempfile.TemporaryDirectory();cls.root=Path(cls.temp.name);cls.data=fixture()
        plan=make_plan();(cls.root/'predeclared_capture_plan.json').write_text(json.dumps(plan))
        for s in plan['sessions']:
            if s['partition']=='TEST':continue
            base=cls.root/'browser_sessions'/s['session_id'];base.mkdir(parents=True)
            rs=[r for r in cls.data['rows'] if r['run_id']==s['session_id']]
            for name in ('features.json','v1_features.json'):(base/name).write_text(json.dumps(rs))
            digest_file=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
            m={'status':'COMPLETE','label':'BENIGN','partition':s['partition'],'protocol':s['protocol'],
                'session_id':s['session_id'],'plan_sha256':plan['sha256'],'windows':len(rs),
                'provenance':{'foreign_records':0,'malformed_records':0},
                'features_sha256':digest_file(base/'features.json'),'v1_features_sha256':digest_file(base/'v1_features.json')}
            (base/'manifest.json').write_text(json.dumps(m));cls.data['capture_manifest_sha256'][s['session_id']]=digest_file(base/'manifest.json')
        review=unit_development_review(cls.root,plan);cls.data['development_review_sha256']=review['sha256']
        cls.freeze=train_freeze(cls.data,cls.root,cls.root/'candidate_01')
        cls.package=load(cls.root/'candidate_01/v2_final_candidate')
    @classmethod
    def tearDownClass(cls):cls.temp.cleanup()
    def test_generic_adapter_package_save_load_predictions(self):
        rs=[r for r in self.data['rows'] if r['partition']=='VALIDATION']
        self.assertEqual(self.package.predict(rs),load(self.root/'candidate_01/v2_final_candidate').predict(rs))
        self.assertEqual(self.package.feature_schema['adapter']['platform_id'],'generic_http')
    def test_only_train_fit_and_benign_reference(self):
        self.assertEqual(self.package.config['train_ids'],self.data['split_manifest']['train_runs'])
        self.assertTrue(all(next(r['label'] for r in self.data['rows'] if r['run_id']==rid)=='BENIGN' for rid in self.package.config['benign_fit_ids']))
        self.assertEqual(self.package.reference['median'][2],0.) # VALIDATION sentinel=1000 absent
    def test_freeze_verifies_root_pointer_and_inference_without_fit(self):
        with patch('sklearn.ensemble.IsolationForest.fit',side_effect=AssertionError('No fit')),patch('xgboost.XGBClassifier.fit',side_effect=AssertionError('No fit')):
            frozen,p=verify_freeze(self.root/'freeze_manifest.json');ps=p.predict(self.data['rows'][:2])
        self.assertEqual(len(ps),2);self.assertFalse(frozen['test_opened'])
    def test_all_validation_candidates_preserved(self):
        d=json.loads((self.root/'candidate_01/validation_tuning.json').read_text())
        self.assertEqual(len(d['candidates']),36)
        self.assertLessEqual(d['selected']['novelty_validation']['FPR'],.05)
    def test_no_fresh_or_old_external_in_fit(self):
        for partition in ('TEST','EXTERNAL_HUMAN_TEST'):
            bad=copy.deepcopy(self.data);bad['rows'][0]['partition']=partition
            with self.assertRaises(ValueError):train_freeze(bad,self.root,self.root/('bad-'+partition))
    def test_cross_partition_run_and_reserved_id_rejected(self):
        bad=copy.deepcopy(self.data);bad['rows'][0]['run_id']=bad['split_manifest']['validation_runs'][0]
        with self.assertRaises(ValueError):train_freeze(bad,self.root,self.root/'bad-overlap')
        bad=copy.deepcopy(self.data);bad['split_manifest']['fresh_test_reserved_ids'].append(bad['rows'][0]['run_id'])
        with self.assertRaises(ValueError):train_freeze(bad,self.root,self.root/'bad-reserved')
    def test_duplicate_windows_and_mixed_labels_rejected(self):
        bad=copy.deepcopy(self.data);bad['rows'].append(copy.deepcopy(bad['rows'][0]))
        with self.assertRaises(ValueError):train_freeze(bad,self.root,self.root/'bad-duplicate')
        bad=copy.deepcopy(self.data);bad['rows'][1]['label']='SQLI_ATTEMPT'
        with self.assertRaises(ValueError):train_freeze(bad,self.root,self.root/'bad-label')
    def test_no_overwrite_or_retune_existing_study(self):
        with self.assertRaises(ValueError):train_freeze(self.data,self.root,self.root/'candidate_01')
    def test_live_observation_vs_episode_semantics_visible(self):
        ps=self.package.predict(self.data['rows'][:2])
        for p in ps:self.assertIn(p['model_observation'],('NORMAL','NOVEL_OBSERVATION','MODEL_DISAGREEMENT','KNOWN_PATTERN'))
        self.assertTrue(all(p['training_performed'] is False and p['confidence_calibrated'] is False for p in ps))
    def test_model_hash_tampering_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            import shutil
            target=Path(tmp)/'package';shutil.copytree(self.root/'candidate_01/v2_final_candidate',target)
            (target/'config.json').write_text('{}')
            with self.assertRaises(ValueError):load(target)
    def test_fresh_attack_plan_uses_existing_bounds_but_new_ids(self):
        from behavioral_v2.holdouts31 import attack_plan
        context=json.loads((ROOT/'experiments/branch2_lab_context.template.json').read_text())
        with tempfile.TemporaryDirectory() as tmp:
            out=Path(tmp)/'plan';r=attack_plan(self.root/'freeze_manifest.json',context,out)
            p=json.loads((out/'schedule.json').read_text())
            self.assertEqual(r['planned_fresh_attack_runs'],14);self.assertEqual(r['network_requests'],0)
            self.assertTrue(all(int(run['run_id'].rsplit('run',1)[-1])>=71 for run in p['runs']))
            self.assertEqual({run['label'] for run in p['runs']},set(CLASSES)-{'BENIGN'})
    def test_fresh_attack_wrapper_dry_run_never_ssh_or_network(self):
        from behavioral_v2.holdouts31 import attack_plan
        context=json.loads((ROOT/'experiments/branch2_lab_context.template.json').read_text())
        spec=importlib.util.spec_from_file_location('attack_cli',ROOT/'scripts/run_m5_fresh_attacks.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
        with tempfile.TemporaryDirectory() as tmp:
            out=Path(tmp)/'plan';attack_plan(self.root/'freeze_manifest.json',context,out)
            with patch('subprocess.run',side_effect=AssertionError('No SSH')),patch('socket.socket',side_effect=AssertionError('No HTTP')),patch('builtins.print'):
                self.assertEqual(m.main(['--plan',str(out/'schedule.json'),'--binding',str(out/'freeze_binding.json'),'--dry-run']),0)
    def test_missing_verified_browser_sessions_prevents_any_fit(self):
        bad=copy.deepcopy(self.data);bad['capture_manifest_sha256']={}
        with patch('sklearn.ensemble.IsolationForest.fit',side_effect=AssertionError('No fit')):
            with self.assertRaises(ValueError):train_freeze(bad,self.root,self.root/'bad-missing-capture')
    def test_build_does_not_open_test_sessions(self):
        plan=make_plan();calls=[];s=schema(MoodleBehaviorAdapter())
        def fake(root,entry,unused):
            calls.append(entry['partition']);row=old_rows(entry['partition'],count=1)[0]
            row.update(run_id=entry['session_id'],schema_sha256=s['sha256'])
            row['source_sha256']=hashlib.sha256(entry['session_id'].encode()).hexdigest()
            row['line_numbers']=[1]
            row['source_file']='UNIT-SOURCE'
            i=int(entry['session_id'].rsplit('-',1)[-1]);p={'source_device':1,'source_inode':2,'offset_start':i*100,'offset_end':i*100+10,'source_byte_ranges':[]}
            return [row],[],{'provenance':p}
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);(root/'predeclared_capture_plan.json').write_text(json.dumps(plan))
            for entry in plan['sessions']:
                if entry['partition']!='TEST':
                    p=root/'browser_sessions'/entry['session_id'];p.mkdir(parents=True);(p/'manifest.json').write_text('{}')
            review={'sha256':'UNIT-REVIEW','included_browser_sessions':[s for s in plan['sessions'] if s['partition']!='TEST'],'excluded_browser_sessions':[]}
            with patch('behavioral_v2.study31.load_browser_session',side_effect=fake),patch('behavioral_v2.study31.require_development_review',return_value=review):
                d=build_development(root,{'rows':[]},{'train_runs':[],'validation_runs':[],'test_runs':[]},root)
        self.assertNotIn('TEST',calls);self.assertFalse(d['split_manifest']['fresh_test_files_opened'])


class CompatibilityTests(unittest.TestCase):
    def row(self,decision='BENIGN'):
        from branch2.reconciliation import reconcile
        anomalous=decision!='BENIGN';label='SQLI_ATTEMPT' if anomalous else 'BENIGN'
        return {'record_id':'unit-live-1','sequence':1,'emitted_at_utc':'2020-01-01T00:00:10+00:00',
            'window_start':'2020-01-01T00:00:00+00:00','window_end':'2020-01-01T00:00:10+00:00',
            'source_byte_ranges':[{'start':0,'end':10,'sha256':'a'*64}],'source_sha256':'b'*64,
            'session_id':'unit-session','run_id':'unit-run','client_id':'unit-client','user_agent_id':'unit-agent',
            'source_file':'unit-source','model_id':'model','schema_sha256':'schema','training_performed':False,
            'novelty_anomalous':anomalous,'novelty_model':'OCSVM','xgb_label':label,'xgb_confidence':.9,
            'confidence_calibrated':False,'reconciliation':reconcile(anomalous,label,.9,.8),
            'robust_deviations':[],'shap_explanation':{'status':'UNAVAILABLE','top_features':[],'causal':False}}
    def test_requires_real_emission_and_provenance(self):
        r=self.row();r.pop('emitted_at_utc')
        with self.assertRaises(ValueError):observations([r],'model','schema')
    def test_input_unmodified_and_actual_novelty_identity_retained(self):
        r=self.row('SQLI_ATTEMPT');before=copy.deepcopy(r);n=observations([r],'model','schema')[0]
        self.assertEqual(r,before);self.assertIn('OCSVM',n['semantic_scope'])
    def test_existing_cqi_formula_d6_response_without_posture_change(self):
        posture=[{'finding_id':'UNIT-INFO','evidence_id':'unit-posture','category':'Authentication & Session',
            'finding_type':'unit','check_result':'PASS','confirmation_status':'CONFIRMED','severity':'INFO'}]
        baseline=fuse(posture,[self.row()],'model','schema')['fusion']
        attack=fuse(posture,[self.row('SQLI_ATTEMPT')],'model','schema')['fusion']
        self.assertLess(attack['cqi']['cqi'],baseline['cqi']['cqi'])
        self.assertFalse(attack['cqi']['is_probability'])
        self.assertTrue(all(c['score_effect']=='NONE' and c['causal'] is False for c in attack['correlations']))


if __name__=='__main__':unittest.main()
