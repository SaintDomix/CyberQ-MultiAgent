"""Regression for laboratory failed-login PRG; mocked HTTP and clocks only."""
import copy
import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
import requests
from test_branch2_capture import ROOT,CONTEXT,Clock,Response,Session
from branch2.capture.planning import schedule,COUNTS,TARGET
from branch2.capture.safety import validate_schedule,validate_result
from branch2.capture.traffic import execute,Transport
from branch2.capture.server import CaptureServer
from branch2.capture.verification import verify


class BruteForceRedirectTests(unittest.TestCase):
    def setUp(self):
        blocker=patch('socket.socket',side_effect=AssertionError('No network'))
        blocker.start();self.addCleanup(blocker.stop)
        self.run=schedule(CONTEXT,only_run_id='S01-run06')['runs'][0]

    def execute(self,handler):
        clock=Clock();session=Session(handler)
        with patch.dict(os.environ,{'B2_FICTITIOUS_PASSWORD':'private-password'}):
            result=execute(self.run,CONTEXT,True,session=session,clock=clock.monotonic,sleep=clock.sleep,worker_check=False)
        return result,session

    def test_real_200_303_sequence_fresh_state_and_no_secret_export(self):
        for location in (TARGET+'login/index.php', '/moodle/login/index.php?loginredirect=1', 'index.php?loginredirect=0'):
            tokens=[]
            def handler(session,method,url,options):
                if method=='GET':
                    self.assertFalse(session.cookies)
                    token='private-token-'+str(len(tokens));tokens.append(token)
                    session.cookies.set('MoodleSession','private-cookie')
                    return Response(body=f'<form method="post" action="/moodle/login/index.php"><input name="logintoken" value="{token}"></form>')
                self.assertEqual(options['data']['logintoken'],tokens[-1])
                self.assertTrue(session.cookies)
                return Response(303,headers={'Location':location,'Set-Cookie':'private-cookie'})
            with self.subTest(location=location):
                result,session=self.execute(handler)
                self.assertEqual(result['status'],'COMPLETE')
                self.assertEqual(result['actual_request_count'],12)
                self.assertEqual(len(tokens),6);self.assertEqual(len(set(tokens)),6)
                self.assertEqual([c[0] for c in session.calls],['GET','POST']*6)
                self.assertEqual([r['status'] for r in result['requests']],[200,303]*6)
                self.assertTrue(all(not c[2]['allow_redirects'] for c in session.calls))
                self.assertFalse(session.cookies)
                validate_result(result,self.run,CONTEXT)
                exported=json.dumps(result)
                for secret in ('private-password','private-token','private-cookie','Location','Set-Cookie'):
                    self.assertNotIn(secret,exported)

    def test_off_origin_and_non_login_or_malformed_redirects_fail_closed(self):
        locations=['http://outside.invalid/login/index.php','//outside.invalid/moodle/login/index.php',
                   TARGET+'my/',TARGET+'login/index.php?testsession=2',
                   TARGET+'login/index.php?loginredirect=1&token=private-token',
                   TARGET+'login/index.php?loginredirect=1&junk',TARGET+'login/index.php#fragment',
                   TARGET+'login/index.php?loginredirect=2','',None,42,'\n'+TARGET+'login/index.php']
        for location in locations:
            def handler(s,m,u,k):
                return Response(body='<form method="post" action="/moodle/login/index.php"><input name="logintoken" value="private-token"></form>') if m=='GET' else Response(303,headers={'Location':location})
            with self.subTest(location=location):
                result,session=self.execute(handler)
                self.assertEqual(result['status'],'FAILED');self.assertEqual(result['actual_request_count'],2)
                self.assertFalse(session.cookies)
                self.assertNotIn('private-token',json.dumps(result))

    def test_missing_duplicate_or_malformed_login_state_fails_before_post(self):
        for body in ('<html>No login state</html>','<input name="logintoken">',
                     '<input name="logintoken" value="">','<input name="logintoken" value="   ">',
                     '<input name="logintoken" value="private-token"',
                     '<input name="logintoken" value="a"><input name="logintoken" value="b">'):
            with self.subTest(body=body):
                result,session=self.execute(lambda *a:Response(body=body))
                self.assertEqual(result['status'],'FAILED');self.assertEqual(result['actual_request_count'],1)
                self.assertFalse(session.cookies)

    def test_unexpected_post_status_and_transport_failure_stop_without_retry(self):
        for status in (301,307,308,403,429,503):
            with self.subTest(status=status):
                result,_=self.execute(lambda s,m,u,k:Response(body='<form method="post" action="/moodle/login/index.php"><input name="logintoken" value="x"></form>') if m=='GET' else Response(status,headers={'Location':TARGET+'login/index.php'}))
                self.assertEqual(result['status'],'FAILED');self.assertEqual(result['actual_request_count'],2)
        def broken(s,m,u,k):raise requests.ConnectionError('private-cookie private-password')
        result,_=self.execute(broken)
        self.assertEqual(result['status'],'FAILED');self.assertEqual(result['actual_request_count'],1)
        self.assertNotIn('private-',json.dumps(result))

    def test_request_budget_unchanged_and_exhaustion_still_rejected(self):
        self.assertEqual(self.run['planned_request_count'],12)
        self.assertEqual(self.run['minimum_request_count'],12)
        self.assertEqual(self.run['maximum_request_count'],12)
        clock=Clock();session=Session();transport=Transport(self.run,CONTEXT,True,session,clock.monotonic,clock.sleep)
        transport.used=12
        with self.assertRaises(ValueError):transport.request('GET',TARGET+'login/index.php')
        self.assertFalse(session.calls)

    def test_single_selection_preserves_seeded_profile_and_full_defaults(self):
        full=schedule(CONTEXT);original=next(r for r in full['runs'] if r['run_id']=='S01-run06')
        plan=schedule(CONTEXT,only_run_id='S01-run06');validate_schedule(plan)
        expected=copy.deepcopy(original);expected['planned_start_offset_seconds']=0;expected['planned_end_offset_seconds']=44
        self.assertEqual(plan['runs'],[expected]);self.assertEqual(plan,schedule(CONTEXT,only_run_id='S01-run06'))
        self.assertTrue(plan['target_reduced']);self.assertEqual(plan['requested_counts']['BRUTE_FORCE'],1)
        self.assertEqual(plan['target_additional_counts'],COUNTS)
        self.assertEqual(plan['estimated_requests'],12);self.assertEqual(plan['estimated_duration_seconds'],48)
        self.assertEqual(len(full['runs']),68);self.assertEqual(full['estimated_requests'],1363)
        offset=schedule(CONTEXT,run_offset=20,only_run_id='S01-run26');validate_schedule(offset)
        self.assertEqual(offset['runs'][0]['run_id'],'S01-run26')
        with self.assertRaises(ValueError):schedule(CONTEXT,only_run_id='S01-run99')

    def test_selected_cli_dry_run_is_zero_network_and_authorization_required(self):
        spec=importlib.util.spec_from_file_location('capture_regression_cli',ROOT/'scripts/run_branch2_capture.py')
        cli=importlib.util.module_from_spec(spec);spec.loader.exec_module(cli)
        args=['capture','run','--only-run-id','S01-run06']
        with patch('requests.Session',side_effect=AssertionError('No HTTP')),patch('subprocess.run',side_effect=AssertionError('No SSH')),patch('builtins.print') as output:
            with patch.object(sys,'argv',args+['--dry-run']):self.assertEqual(cli.main(),0)
            plan=json.loads(output.call_args.args[0]);self.assertEqual([r['run_id'] for r in plan['runs']],['S01-run06'])
            with patch.object(sys,'argv',args):self.assertEqual(cli.main(),1)
            with patch.object(sys,'argv',['capture','run','--only-run-id','bad','--dry-run']):self.assertEqual(cli.main(),1)

    def test_single_run_capture_verification_accepts_mocked_303_protocol(self):
        plan=schedule(CONTEXT,only_run_id='S01-run06');clock=Clock()
        with tempfile.TemporaryDirectory() as directory:
            log=Path(directory)/'access.log';log.touch()
            server=CaptureServer(Path(directory)/'capture',log,clock.utc,clock.sleep)
            server.initialize(plan);server.begin(self.run['run_id'])
            def handler(session,method,url,options):
                status=200 if method=='GET' else 303
                with log.open('a') as output:
                    output.write(f'192.168.226.129 - - [{clock.utc().strftime("%d/%b/%Y:%H:%M:%S %z")}] "{method} /moodle/login/index.php HTTP/1.1" {status} 10 "-" "{self.run["user_agent"]}"\n')
                return Response(body='<form method="post" action="/moodle/login/index.php"><input name="logintoken" value="private-token"></form>') if method=='GET' else Response(303,headers={'Location':TARGET+'login/index.php?loginredirect=1'})
            with patch.dict(os.environ,{'B2_FICTITIOUS_PASSWORD':'private-password'}):
                result=execute(self.run,CONTEXT,True,session=Session(handler),clock=clock.monotonic,sleep=clock.sleep,worker_check=False)
            server.finish(self.run['run_id'],result)
            report=verify(server.root)
            self.assertTrue(report['verified'],report);self.assertEqual(report['verified_runs'],1)
            self.assertEqual(report['class_counts']['BRUTE_FORCE'],1)
            for path in server.root.rglob('*'):
                if path.is_file() and 'generator_source' not in path.parts:
                    self.assertNotIn('private-password',path.read_text());self.assertNotIn('private-token',path.read_text())


if __name__=='__main__':unittest.main()
