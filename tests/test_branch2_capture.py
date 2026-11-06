"""Capture tests use fake clocks, transports and log appends only; no network."""
import copy
from datetime import datetime,timedelta,timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import MagicMock,patch
from urllib.parse import urlsplit
import requests
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'src'))
from branch2.capture.planning import schedule,COUNTS,sha,TARGET,WORKER
from branch2.capture.safety import validate_schedule,validate_run,validate_result
from branch2.capture.traffic import execute,Transport,ephemeral_inputs
from branch2.capture.server import CaptureServer
from branch2.capture.verification import verify
from branch2.capture.importing import import_capture
from branch2.capture.orchestration import capture,RemoteAgent
from branch2.dataset import build

CONTEXT=json.loads((ROOT/'experiments/branch2_lab_context.template.json').read_text())


class Clock:
    def __init__(self):self.seconds=0;self.base=datetime(2026,10,6,10,tzinfo=timezone.utc)
    def monotonic(self):return self.seconds
    def utc(self):return self.base+timedelta(seconds=self.seconds)
    def sleep(self,n):self.seconds+=n


class Response:
    def __init__(self,status=200,body='',headers=None):self.status_code=status;self.body=body.encode();self.headers=headers or {}
    def __enter__(self):return self
    def __exit__(self,*a):pass
    def iter_content(self,size):yield self.body


class Session:
    def __init__(self,handler=None):self.headers={};self.cookies=requests.cookies.RequestsCookieJar();self.calls=[];self.handler=handler
    def request(self,method,url,**kw):
        self.calls.append((method,url,kw))
        return self.handler(self,method,url,kw) if self.handler else Response()
    def close(self):pass


def selected(label='SQLI_ATTEMPT'):
    counts=dict.fromkeys(COUNTS,0);counts[label]=1
    return schedule(CONTEXT,counts=counts)


class CaptureTests(unittest.TestCase):
    def setUp(self):
        self.network=patch('socket.socket',side_effect=AssertionError('No network'));self.network.start();self.addCleanup(self.network.stop)

    def test_full_schedule_counts_unique_ids_and_seeded_variation(self):
        p=schedule(CONTEXT);validate_schedule(p)
        self.assertEqual(p,schedule(CONTEXT));self.assertNotEqual(p,schedule(CONTEXT,43))
        self.assertEqual(len(p['runs']),68);self.assertEqual(p['requested_counts'],COUNTS)
        self.assertEqual(len({r['run_id'] for r in p['runs']}),68)
        for label in COUNTS:
            runs=[r for r in p['runs'] if r['label']==label]
            self.assertEqual(len(runs),COUNTS[label]);self.assertEqual(len({sha(r['steps']) for r in runs}),len(runs))
        self.assertEqual(p['estimated_duration_seconds'],3264)
        self.assertEqual(p['estimated_requests'],1363)
        self.assertFalse(any(r['scenario_id']=='BN03' for r in p['runs']))

    def test_partial_counts_explicit_and_target_preserved(self):
        p=selected();self.assertTrue(p['target_reduced']);self.assertEqual(p['target_additional_counts'],COUNTS)
        with self.assertRaises(ValueError):schedule(CONTEXT,counts={'BENIGN':1})
        next_plan=schedule(CONTEXT,run_offset=20)
        self.assertFalse({r['run_id'] for r in next_plan['runs']}&{r['run_id'] for r in schedule(CONTEXT)['runs']})

    def test_dry_run_zero_http_ssh_no_log_changes(self):
        spec=importlib.util.spec_from_file_location('capture_cli',ROOT/'scripts/run_branch2_capture.py');cli=importlib.util.module_from_spec(spec);spec.loader.exec_module(cli)
        with patch('requests.Session',side_effect=AssertionError('No HTTP')),patch('subprocess.run',side_effect=AssertionError('No SSH')),patch.object(sys,'argv',['capture','run','--dry-run']),patch('builtins.print') as output:
            self.assertEqual(cli.main(),0)
        self.assertEqual(len(json.loads(output.call_args.args[0])['runs']),68)

    def test_authorization_gate_before_requests_or_agent(self):
        p=selected();run=p['runs'][0];agent=MagicMock()
        with self.assertRaises(ValueError):capture(p,agent,False)
        agent.call.assert_not_called()
        with self.assertRaises(ValueError):execute(run,CONTEXT,False,worker_check=False)
        with self.assertRaises(ValueError):Transport(run,CONTEXT,False)

    def test_class_bounds_inert_xss_traversal_and_nonextractive_sql(self):
        p=schedule(CONTEXT)
        for run in p['runs']:
            validate_run(run,CONTEXT)
            self.assertLessEqual(run['maximum_request_count'],40)
            self.assertEqual(run['parameter_profile']['concurrency'],1)
            if run['label']=='REQUEST_BURST_DOS_LIKE':self.assertLessEqual(run['parameter_profile']['burst_rate'],2)
        for label,replace_text in [('SQLI_ATTEMPT','DROP TABLE users;'),('XSS_ATTEMPT','<script>alert(1)</script>'),('PATH_TRAVERSAL_ATTEMPT','../../etc/passwd')]:
            run=copy.deepcopy(selected(label)['runs'][0]);run['steps'][0]['url']=TARGET+'?b2_lab_q='+replace_text
            with self.subTest(label=label),self.assertRaises(ValueError):validate_run(run,CONTEXT)
        burst=selected('REQUEST_BURST_DOS_LIKE')['runs'][0];burst['parameter_profile']['burst_rate']=3
        with self.assertRaises(ValueError):validate_run(burst,CONTEXT)

    def test_scope_mutation_and_context_secrets_prohibited(self):
        run=copy.deepcopy(selected()['runs'][0])
        for url in ('http://outside.invalid/','http://192.168.226.132/moodle/delete.php',TARGET+'?sesskey=secret'):
            run['steps'][0]['url']=url
            with self.assertRaises(ValueError):validate_run(run,CONTEXT)
        context=copy.deepcopy(CONTEXT);context['password']='never-save'
        with self.assertRaises(ValueError):validate_schedule(schedule(context))

    def test_bounded_mock_http_variation_and_rate_enforced(self):
        for label in ('SQLI_ATTEMPT','XSS_ATTEMPT','PATH_TRAVERSAL_ATTEMPT','REQUEST_BURST_DOS_LIKE'):
            run=selected(label)['runs'][0];clock=Clock();session=Session()
            result=execute(run,CONTEXT,True,session=session,clock=clock.monotonic,sleep=clock.sleep,worker_check=False)
            self.assertEqual(result['status'],'COMPLETE');self.assertEqual(result['actual_request_count'],run['planned_request_count'])
            times=[r['elapsed_seconds'] for r in result['requests']]
            self.assertTrue(all(b-a>=.49999 for a,b in zip(times,times[1:])))
            self.assertTrue(all(not c[2]['allow_redirects'] and c[2]['timeout']==5 for c in session.calls))

    def test_fictitious_login_secret_not_exported_no_retry(self):
        run=selected('BRUTE_FORCE')['runs'][0];clock=Clock()
        session=Session(lambda s,m,u,k:Response(body='<form method="post" action="/moodle/login/index.php"><input name="logintoken" value="token-secret"></form>'))
        with patch.dict(os.environ,{'B2_FICTITIOUS_PASSWORD':'password-secret'}):
            result=execute(run,CONTEXT,True,session=session,clock=clock.monotonic,sleep=clock.sleep,worker_check=False)
        self.assertEqual(result['status'],'COMPLETE')
        exported=json.dumps(result)
        self.assertNotIn('password-secret',exported);self.assertNotIn('token-secret',exported)
        self.assertEqual(sum(c[0]=='POST' for c in session.calls),len(run['steps']))
        self.assertTrue(all(c[2]['data']['username'].startswith('b2lab-fictitious-') for c in session.calls if c[0]=='POST'))

    def test_login_failure_and_server_errors_stop(self):
        run=selected('BRUTE_FORCE')['runs'][0];clock=Clock();session=Session(lambda *a:Response(403))
        with patch.dict(os.environ,{'B2_FICTITIOUS_PASSWORD':'pw'}):
            r=execute(run,CONTEXT,True,session=session,clock=clock.monotonic,sleep=clock.sleep,worker_check=False)
        self.assertEqual(r['status'],'FAILED');self.assertEqual(len(session.calls),1)
        run=selected()['runs'][0];session=Session(lambda *a:Response(503))
        r=execute(run,CONTEXT,True,session=session,clock=clock.monotonic,sleep=clock.sleep,worker_check=False)
        self.assertEqual(r['status'],'FAILED');self.assertEqual(len(session.calls),1)

    def test_admin_ephemeral_identity_testsession_redirect(self):
        run=next(r for r in schedule(CONTEXT)['runs'] if r['auth_role']);clock=Clock()
        def handler(session,method,url,options):
            if method=='POST':
                session.cookies.set('MoodleSession','cookie-secret',domain='192.168.226.132',path='/moodle/')
                for c in session.cookies:c.domain_specified=False
                return Response(302,headers={'Location':TARGET+'login/index.php?testsession=2'})
            if '?testsession=' in url:return Response(302,headers={'Location':TARGET+'my/'})
            if url==TARGET+'login/index.php':return Response(body='<form method="post" action="/moodle/login/index.php"><input name="logintoken" value="token-secret"></form>')
            return Response(body=CONTEXT['identity_markers']['administrator'])
        session=Session(handler)
        with patch.dict(os.environ,{'B2_ADMIN_USERNAME':'admin-secret','B2_ADMIN_PASSWORD':'password-secret'}):
            result=execute(run,CONTEXT,True,session=session,clock=clock.monotonic,sleep=clock.sleep,worker_check=False)
        self.assertEqual(result['status'],'COMPLETE')
        for secret in ('admin-secret','password-secret','cookie-secret','token-secret'):self.assertNotIn(secret,json.dumps(result))
        self.assertFalse(session.cookies)

    def test_worker_result_rejects_literal_credentials(self):
        run=selected()['runs'][0]
        result={'run_id':run['run_id'],'label':run['label'],'actor_ip':WORKER,'status':'FAILED','actual_request_count':0,'requests':[],'password':'bad'}
        with self.assertRaises(ValueError):validate_result(result,run,CONTEXT)

    def test_hidden_input_ephemeral_cleanup_and_missing_input_preflight(self):
        p=schedule(CONTEXT);agent=MagicMock()
        with patch.dict(os.environ,{},clear=True),patch('getpass.getpass',side_effect=['fictitious-private','admin-private','admin-password-private']):
            with ephemeral_inputs(p,True):
                self.assertEqual(os.environ['B2_ADMIN_PASSWORD'],'admin-password-private')
                self.assertNotIn('admin-password-private',json.dumps(p))
            self.assertNotIn('B2_ADMIN_PASSWORD',os.environ)
            self.assertNotIn('B2_FICTITIOUS_PASSWORD',os.environ)
            with self.assertRaises(ValueError):capture(p,agent,True)
        agent.call.assert_not_called()

    def test_global_capture_lock_abort_and_rotation_preserve_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            log=Path(directory)/'access';log.write_bytes(b'');clock=Clock();p=selected();rid=p['runs'][0]['run_id']
            first=CaptureServer(Path(directory)/'one',log,clock.utc,clock.sleep)
            second=CaptureServer(Path(directory)/'two',log,clock.utc,clock.sleep)
            counts=dict.fromkeys(COUNTS,0);counts['SQLI_ATTEMPT']=1
            different=schedule(CONTEXT,counts=counts,run_offset=20);otherid=different['runs'][0]['run_id']
            first.initialize(p);second.initialize(different);first.begin(rid)
            with self.assertRaisesRegex(ValueError,'Overlapping'):second.begin(otherid)
            log.rename(Path(directory)/'rotated');log.write_bytes(b'')
            unknown={'run_id':rid,'label':p['runs'][0]['label'],'actor_ip':WORKER,'status':'FAILED','actual_request_count':None,'requests':[],'error':'WORKER_ABORTED'}
            with self.assertRaisesRegex(ValueError,'rotation'):first.finish(rid,unknown)
            self.assertTrue((first.root/rid/'begin.json').exists())
            first.abort(rid)
            self.assertTrue((first.root/rid/'abort.json').exists())
            self.assertFalse(verify(first.root)['verified'])
            second.begin(otherid);second.abort(otherid)

    def test_missing_runs_plan_hash_and_unknown_worker_accounting(self):
        p=selected();run=p['runs'][0]
        unknown={'run_id':run['run_id'],'label':run['label'],'actor_ip':WORKER,'status':'FAILED','actual_request_count':None,'requests':[],'error':'WORKER_ABORTED'}
        validate_result(unknown,run,CONTEXT)
        bad=copy.deepcopy(p);bad['seed']=43
        with self.assertRaisesRegex(ValueError,'hash'):validate_schedule(bad)
        with tempfile.TemporaryDirectory() as directory:
            log=Path(directory)/'log';log.touch();clock=Clock();server=CaptureServer(Path(directory)/'root',log,clock.utc,clock.sleep)
            server.initialize(p)
            self.assertFalse(verify(server.root)['verified'])

    def test_identical_capture_and_early_time_compression_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root,log,server,p=self.capture_fixture(directory)
            rd=root/p['runs'][0]['run_id'];m=json.loads((rd/'manifest.json').read_text())
            raw=(rd/'access.log').read_bytes().replace(b'10:00:03',b'10:00:03')
            # Keep requests and hashes valid while all actual events occupy one second.
            import re
            raw=re.sub(rb'10:00:\d\d',b'10:00:03',raw)
            (rd/'access.log').write_bytes(raw);m['access_sha256']=hashlib.sha256(raw).hexdigest()
            (rd/'manifest.json').write_text(json.dumps(m));(rd/'manifest.sha256').write_text(hashlib.sha256((rd/'manifest.json').read_bytes()).hexdigest())
            report=verify(root);self.assertFalse(report['verified'])
            self.assertTrue(any('temporal windows' in str(e) for e in report['errors']))

    def test_real_historical_files_unchanged_by_plan_and_fixture_capture(self):
        paths=list((ROOT/'data/raw').glob('*'))+[ROOT/'experiments/experiment_metadata.csv',ROOT/'experiments/branch2_v2_labels.json']
        before={str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in paths if p.is_file()}
        schedule(CONTEXT)
        with tempfile.TemporaryDirectory() as directory:self.capture_fixture(directory)
        self.assertEqual(before,{str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in paths if p.is_file()})

    def capture_fixture(self,directory,plan=None):
        directory=Path(directory);plan=plan or selected()
        log=directory/'apache.log';log.write_bytes(b'192.0.2.9 - - [06/Oct/2026:09:59:00 +0000] "GET / HTTP/1.1" 200 10 "-" "earlier unrelated"\n')
        clock=Clock();root=directory/'capture'
        server=CaptureServer(root,log,clock.utc,clock.sleep);server.initialize(plan)
        for run in plan['runs']:
            start=server.begin(run['run_id']);seconds=clock.seconds
            requests_rows=[]
            lines=[]
            for i,step in enumerate(run['steps'],1):
                when=clock.base+timedelta(seconds=seconds+step['at_seconds']);parts=urlsplit(step['url'])
                target=parts.path+('?' +parts.query if parts.query else '')
                # Apache escapes raw quotes when applicable.
                target=target.replace('"','\\"')
                lines.append(f'{WORKER} - - [{when.strftime("%d/%b/%Y:%H:%M:%S %z")}] "GET {target} HTTP/1.1" 200 10 "-" "{run["user_agent"]}"\n')
                requests_rows.append({'request_index':i,'method':'GET','url':step['url'],'elapsed_seconds':step['at_seconds'],'status':200,'response_bytes_observed':10})
            with log.open('ab') as f:f.write(''.join(lines).encode())
            clock.sleep(run['duration_seconds'])
            result={'run_id':run['run_id'],'label':run['label'],'actor_ip':WORKER,'status':'COMPLETE','requests':requests_rows,'actual_request_count':len(requests_rows)}
            server.finish(run['run_id'],result);clock.sleep(2)
        return root,log,server,plan

    def test_exact_offset_slice_timestamps_hashes_and_verification(self):
        with tempfile.TemporaryDirectory() as directory:
            root,log,server,plan=self.capture_fixture(directory)
            report=verify(root);self.assertTrue(report['verified'],report)
            self.assertEqual(report['verified_runs'],1);self.assertGreaterEqual(report['runs'][0]['windows'],2)
            slice_file=next(root.glob('*/access.log'))
            self.assertNotIn(b'earlier unrelated',slice_file.read_bytes())
            self.assertIn(b'earlier unrelated',log.read_bytes())
            self.assertEqual(report['runs'][0]['source_sha256'],hashlib.sha256(slice_file.read_bytes()).hexdigest())

    def test_hash_malformed_foreign_traffic_and_incomplete_rejected(self):
        for mode in ('hash','malformed','foreign','missing','manifest'):
            with self.subTest(mode=mode),tempfile.TemporaryDirectory() as directory:
                root,log,server,plan=self.capture_fixture(directory);run_dir=root/plan['runs'][0]['run_id']
                path=run_dir/'access.log'
                if mode=='hash':path.write_bytes(path.read_bytes()+b'extra')
                elif mode in {'malformed','foreign'}:
                    raw=path.read_bytes();raw=b'malformed\n' if mode=='malformed' else raw.replace(WORKER.encode(),b'192.0.2.9')
                    path.write_bytes(raw)
                    m=json.loads((run_dir/'manifest.json').read_text());m['access_sha256']=hashlib.sha256(raw).hexdigest();m['offset_end']=m['offset_start']+len(raw)
                    (run_dir/'manifest.json').write_text(json.dumps(m));(run_dir/'manifest.sha256').write_text(hashlib.sha256((run_dir/'manifest.json').read_bytes()).hexdigest())
                elif mode=='missing':path.unlink()
                else:(run_dir/'manifest.json').write_text('{}')
                self.assertFalse(verify(root)['verified'])

    def test_rotation_partial_record_and_overlapping_capture_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root,log,server,plan=self.capture_fixture(directory)
            with self.assertRaises(ValueError):server.begin(plan['runs'][0]['run_id'])
        with tempfile.TemporaryDirectory() as directory:
            log=Path(directory)/'access';log.write_bytes(b'');clock=Clock()
            server=CaptureServer(Path(directory)/'root',log,clock.utc,clock.sleep);server.initialize(selected())
            log.write_bytes(b'partial')
            with self.assertRaisesRegex(ValueError,'incomplete'):server.begin(selected()['runs'][0]['run_id'])

    def test_import_compatible_builder_and_historical_preservation(self):
        with tempfile.TemporaryDirectory() as directory:
            project=Path(directory);(project/'data/raw').mkdir(parents=True);(project/'experiments').mkdir();(project/'evidence/branch2_captures').mkdir(parents=True)
            metadata=project/'experiments/experiment_metadata.csv';metadata.write_text('scenario_id,label,run,start_utc,end_utc,duration_seconds,access_file,error_file\n')
            labels=project/'experiments/branch2_v2_labels.json';labels.write_text('{"scenarios":{},"source_references":[]}')
            before=metadata.read_bytes(),labels.read_bytes()
            container=project/'evidence/branch2_captures/fixture';container.mkdir()
            root,_,_,_=self.capture_fixture(container)
            result=import_capture(project,root,'fixture',allow_partial=True)
            data=build(project,Path(result['metadata']),Path(result['labels']))
            self.assertEqual(data['qa']['run_count'],1);self.assertGreaterEqual(len(data['rows']),2)
            self.assertEqual(data['rows'][0]['label'],'SQLI_ATTEMPT')
            self.assertEqual(before,(metadata.read_bytes(),labels.read_bytes()))
            with self.assertRaises(ValueError):import_capture(project,root,'fixture2',allow_partial=True)

    def test_coordinator_does_not_train_and_stop_on_failure(self):
        p=selected();agent=MagicMock();agent.root='evidence/branch2_captures/test'
        worker=MagicMock(return_value={'status':'FAILED'})
        with self.assertRaises(ValueError):capture(p,agent,True,worker=worker,sleep=MagicMock())
        self.assertEqual([c.args[0] for c in agent.call.call_args_list],['init','begin','finish'])
        with self.assertRaises(ValueError):RemoteAgent('user@other.invalid','/tmp','anything')

    def test_ssh_environment_excludes_ephemeral_secret_inputs(self):
        agent=RemoteAgent('saintdomix@192.168.226.132','/home/saintdomix/dissertation_model','evidence/branch2_captures/test')
        reply=MagicMock(returncode=0,stdout='{}')
        with patch.dict(os.environ,{'B2_ADMIN_PASSWORD':'secret','B2_FICTITIOUS_PASSWORD':'secret2'}),patch('subprocess.run',return_value=reply) as command:
            agent.call('begin',{'run_id':'SQ01-run01'})
        self.assertNotIn('B2_ADMIN_PASSWORD',command.call_args.kwargs['env'])
        self.assertNotIn('B2_FICTITIOUS_PASSWORD',command.call_args.kwargs['env'])

    def test_apache_extended_format_rejected_before_capture_and_ssh_failure_redacted(self):
        with tempfile.TemporaryDirectory() as directory:
            log=Path(directory)/'log';log.write_bytes(b'not combined with Cookie: private\n')
            server=CaptureServer(Path(directory)/'capture',log)
            with self.assertRaisesRegex(ValueError,'combined-only'):server.initialize(selected())
            self.assertFalse(server.root.exists())
        agent=RemoteAgent('saintdomix@192.168.226.132','/home/saintdomix/dissertation_model','evidence/branch2_captures/test')
        import subprocess
        with patch('subprocess.run',side_effect=subprocess.TimeoutExpired('private-command',20)),self.assertRaisesRegex(ValueError,'transport failed') as error:
            agent.call('begin',{'run_id':'SQ01-run01'})
        self.assertNotIn('private-command',str(error.exception))

    def test_duplicate_capture_content_rejected(self):
        counts=dict.fromkeys(COUNTS,0);counts['SQLI_ATTEMPT']=2
        plan=schedule(CONTEXT,counts=counts)
        with tempfile.TemporaryDirectory() as directory:
            root,_,_,_=self.capture_fixture(directory,plan)
            first=root/plan['runs'][0]['run_id'];second=root/plan['runs'][1]['run_id']
            raw=(first/'access.log').read_bytes();(second/'access.log').write_bytes(raw)
            m=json.loads((second/'manifest.json').read_text());m['access_sha256']=hashlib.sha256(raw).hexdigest();m['offset_end']=m['offset_start']+len(raw)
            (second/'manifest.json').write_text(json.dumps(m));(second/'manifest.sha256').write_text(hashlib.sha256((second/'manifest.json').read_bytes()).hexdigest())
            result=verify(root);self.assertFalse(result['verified'])
            self.assertTrue(any('Duplicate capture' in str(e) for e in result['errors']))


if __name__=='__main__':unittest.main()
