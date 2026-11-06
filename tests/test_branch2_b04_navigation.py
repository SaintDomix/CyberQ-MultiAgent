"""B04 normal administrator navigation; fake HTTP/logs, strict contamination QA."""
import copy
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from urllib.parse import urlsplit
from test_branch2_capture import ROOT,CONTEXT,Clock,Response,Session
from branch2.capture.planning import schedule,TARGET,COUNTS
from branch2.capture.safety import check_url,validate_run,validate_schedule
from branch2.capture.traffic import execute
from branch2.capture.server import CaptureServer
from branch2.capture.verification import verify


class B04NavigationTests(unittest.TestCase):
    def setUp(self):
        blocker=patch('socket.socket',side_effect=AssertionError('No network'))
        blocker.start();self.addCleanup(blocker.stop)

    def test_b04_only_existing_read_only_authenticated_navigation(self):
        approved={TARGET,TARGET+'my/',TARGET+'course/index.php'}
        self.assertEqual(set(CONTEXT['admin_navigation']),approved)
        self.assertIn(TARGET+'course/index.php',CONTEXT['benign_resource'])
        for offset in (0,40,60):
            plan=schedule(CONTEXT,run_offset=offset);validate_schedule(plan)
            runs=[r for r in plan['runs'] if r['scenario_id']=='B04']
            self.assertEqual(len(runs),3)
            for run in runs:
                self.assertEqual(run['label'],'BENIGN');self.assertEqual(run['auth_role'],'administrator')
                self.assertEqual(run['variant'],'admin_navigation');validate_run(run,CONTEXT)
                self.assertEqual({s['url'] for s in run['steps']},approved)
                for step in run['steps']:
                    self.assertEqual(step['operation'],'get');check_url(step['url'],CONTEXT)

    def test_determinism_counts_timing_and_unrelated_profiles_preserved(self):
        old=copy.deepcopy(CONTEXT)
        old['admin_navigation']=[TARGET,TARGET+'my/',TARGET+'report/security/index.php']
        for offset,requests in ((0,1363),(40,1369)):
            plan=schedule(CONTEXT,run_offset=offset);previous=schedule(old,run_offset=offset)
            self.assertEqual(plan,schedule(CONTEXT,run_offset=offset))
            self.assertEqual(plan['requested_counts'],COUNTS);self.assertEqual(len(plan['runs']),68)
            self.assertEqual(plan['estimated_requests'],requests)
            self.assertEqual(plan['estimated_duration_seconds'],previous['estimated_duration_seconds'])
            for run,before in zip(plan['runs'],previous['runs']):
                self.assertEqual(run['run_id'],before['run_id'])
                if run['scenario_id']!='B04':self.assertEqual(run,before);continue
                for key in ('seed','minimum_request_count','maximum_request_count','planned_request_count','parameter_profile'):
                    self.assertEqual(run[key],before[key])
                self.assertEqual([s['at_seconds'] for s in run['steps']],[s['at_seconds'] for s in before['steps']])

    def fixture(self,directory,foreign=False):
        plan=schedule(CONTEXT,run_offset=60,only_run_id='B04-run63')
        run=plan['runs'][0];clock=Clock();log=Path(directory)/'apache.log';log.touch()
        server=CaptureServer(Path(directory)/'capture',log,clock.utc,clock.sleep)
        server.initialize(plan);server.begin(run['run_id'])
        def handler(session,method,url,options):
            if method=='POST':
                session.cookies.set('MoodleSession','fixture-cookie',domain='192.168.226.132',path='/moodle/')
                for cookie in session.cookies:cookie.domain_specified=False
                response=Response(303,headers={'Location':TARGET+'login/index.php?testsession=2'})
            elif '?testsession=' in url:response=Response(303,headers={'Location':TARGET+'my/'})
            elif url==TARGET+'login/index.php':response=Response(body='<form method="post" action="/moodle/login/index.php"><input name="logintoken" value="fixture-token"></form>')
            else:response=Response(body=CONTEXT['identity_markers']['administrator'])
            parts=urlsplit(url);path=parts.path+('?' +parts.query if parts.query else '')
            stamp=clock.utc().strftime('%d/%b/%Y:%H:%M:%S %z')
            with log.open('a') as output:
                output.write(f'192.168.226.129 - - [{stamp}] "{method} {path} HTTP/1.1" {response.status_code} 10 "-" "{run["user_agent"]}"\n')
                if foreign and url==TARGET+'course/index.php':
                    output.write(f'192.168.226.132 - - [{stamp}] "HEAD /moodle/vendor/ HTTP/1.1" 404 196 "-" "MoodleBot/4.5"\n')
            return response
        with patch.dict(os.environ,{'B2_ADMIN_USERNAME':'fixture-admin','B2_ADMIN_PASSWORD':'fixture-password'}):
            result=execute(run,CONTEXT,True,session=Session(handler),clock=clock.monotonic,sleep=clock.sleep,worker_check=False)
        self.assertEqual(result['status'],'COMPLETE')
        server.finish(run['run_id'],result)
        return server.root,run

    def test_b04_authenticated_navigation_passes_existing_capture_verification(self):
        with tempfile.TemporaryDirectory() as directory:
            root,run=self.fixture(directory)
            report=verify(root);self.assertTrue(report['verified'],report)
            self.assertEqual(report['class_counts']['BENIGN'],1)
            manifest=json.loads((root/run['run_id']/'manifest.json').read_text())
            result=manifest['worker_result']
            self.assertEqual(result['actual_request_count'],len(run['steps'])+5)
            self.assertNotIn('fixture-password',json.dumps(result));self.assertNotIn('fixture-cookie',json.dumps(result))

    def test_moodlebot_foreign_traffic_rejected_and_retained_without_filtering(self):
        with tempfile.TemporaryDirectory() as directory:
            root,run=self.fixture(directory,foreign=True)
            before={str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in root.rglob('*') if p.is_file()}
            report=verify(root)
            self.assertFalse(report['verified']);self.assertEqual(report['verified_runs'],0)
            self.assertTrue(any('contamination' in str(e) for e in report['errors']))
            self.assertIn('MoodleBot/4.5',(root/run['run_id']/'access.log').read_text())
            self.assertEqual(before,{str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in root.rglob('*') if p.is_file()})


if __name__=='__main__':unittest.main()
