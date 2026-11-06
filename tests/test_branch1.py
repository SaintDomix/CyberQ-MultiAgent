"""Branch 1 regression tests use saved evidence and synthetic response fixtures only."""
import ast
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from evidence_contracts import SecurityFinding, ConfirmationStatus, CheckResult
from evidence_contracts.baseline import normalize_baseline
from branch1 import Context, DEFAULT_MODULES, run
from branch1.common import Document, json_bytes
from branch1 import internal, intelligence, roles
from branch1.reporting import write_report, validate_output


def internal_document(payload=None):
    if payload is None:
        payload = json.loads((ROOT/"evidence/baseline/branch1/internal_evidence_v2.json").read_text())
    return Document.generated("fixture/internal.json", payload)


def by_id(findings):
    return {f.finding_id: f for f in findings}


class ReplayTests(unittest.TestCase):
    def test_all_modules_and_canonical_identical_replay(self):
        with patch("socket.socket", side_effect=AssertionError("Network forbidden")):
            records, counts, assignments = run(Context(ROOT))
            repeat, _, _ = run(Context(ROOT))
        expected = normalize_baseline(ROOT)
        self.assertEqual([f.to_dict() for f in records], [f.to_dict() for f in expected])
        self.assertEqual([f.to_dict() for f in records], [f.to_dict() for f in repeat])
        self.assertEqual(counts, {"external": 23, "intelligence": 12, "internal": 4, "roles": 1})
        self.assertEqual(len(assignments), 40)
        for record in records:
            self.assertEqual(SecurityFinding.from_json(record.to_json()), record)

    def test_confirmations_preserved(self):
        records, _, _ = run(Context(ROOT))
        self.assertEqual(sum(f.confirmation_status == ConfirmationStatus.VERSION_BASED for f in records), 11)
        dismissed = [f for f in records if f.confirmation_status == ConfirmationStatus.FALSE_POSITIVE]
        self.assertEqual(len(dismissed), 1)
        self.assertEqual(dismissed[0].check_result, CheckResult.DISMISSED)
        fs = by_id(records)["FS-001"]
        self.assertEqual(fs.confirmation_status, ConfirmationStatus.CONFIRMED)
        self.assertEqual(fs.check_result, CheckResult.FAIL)

    def test_offline_report_idempotence_and_no_source_mutation(self):
        files = [p for root in [ROOT/"legacy", ROOT/"evidence/baseline", ROOT/"outputs/security_scan_local"] for p in root.rglob('*') if p.is_file()]
        before = {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in files}
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory)
            # Baseline input comes from ROOT; reporting is isolated in the temporary project.
            records, counts, assignments = run(Context(ROOT))
            ctx = Context(project, output=project/"outputs/branch1")
            first = write_report(ctx, records, counts, assignments)
            artifacts = {p.name:p.read_bytes() for p in ctx.output.iterdir()}
            self.assertEqual(first, write_report(ctx, records, counts, assignments))
            self.assertEqual(artifacts, {p.name:p.read_bytes() for p in ctx.output.iterdir()})
            self.assertEqual(first["source_counts"], {"external_mvp":23,"deep_v2":16,"role_review_v3":1})
            self.assertEqual(first["check_result_counts"], {"FAIL":21,"PASS":15,"PARTIAL":3,"DISMISSED":1})
        self.assertEqual(before, {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in files})

    def test_registry_accepts_additional_canonical_module(self):
        modules = dict(DEFAULT_MODULES)
        modules["future"] = lambda ctx: []
        _, counts, _ = run(Context(ROOT), modules)
        self.assertEqual(counts["future"], 0)
        with self.assertRaises(TypeError):
            run(Context(ROOT), {"invalid": lambda ctx: [{}]})

    def test_production_has_no_legacy_runtime_dependency(self):
        for path in (ROOT/"src/branch1").rglob('*.py'):
            tree = ast.parse(path.read_text())
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    self.assertTrue(all(not a.name.startswith('legacy') for a in node.names))
                if isinstance(node, ast.ImportFrom):
                    self.assertFalse((node.module or '').startswith('legacy'))
            self.assertNotIn('sys.path', path.read_text())
        self.assertEqual((ROOT/"src/branch1/advisories.json").read_bytes(),
                         (ROOT/"legacy/branch1/moodle_deep_v2_role_pack/advisories_v2.json").read_bytes())

    def test_live_cli_rejects_missing_authorization_before_collection(self):
        result = subprocess.run([sys.executable, '-B', str(ROOT/'scripts/run_branch1.py'),
                                 '--mode','live-passive','--target','http://127.0.0.1/moodle/'],
                                capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('requires --authorized', result.stderr)

    def test_live_orchestration_with_fixture_collector_and_real_saved_inputs(self):
        from branch1.common import finding
        with tempfile.TemporaryDirectory() as directory:
            project=Path(directory)
            ctx=Context(project,mode='live-passive',target='http://fixture/moodle/',
                        output=project/'outputs/live',internal_document=internal_document(),
                        advisory_document=Document.load(ROOT/'src/branch1/advisories.json'),
                        role_documents=[Document.load(ROOT/'evidence/baseline/branch1/role_access_review_v3.json')])
            document=Document.generated('fixture/http.json',{'status':200})
            external_record=finding(document,'external','FIXTURE','Transport Security','Fixture observation',
                                    'PASS','CONFIRMED','INFO',observed=200)
            with patch('branch1.external.assess',return_value=([external_record],{'status':200})), patch('socket.socket',side_effect=AssertionError('No network')):
                records,counts,assignments=run(ctx)
                summary=write_report(ctx,records,counts,assignments)
            self.assertEqual(set(counts),{'external','internal','intelligence','roles'})
            self.assertTrue(all(count > 0 for count in counts.values()))
            self.assertEqual(summary['mode'],'live-passive')
            self.assertEqual(len(json.loads((ctx.output/'findings.json').read_text())),len(records))
            self.assertTrue((ctx.output/'external_evidence.json').exists())


class InternalTests(unittest.TestCase):
    def test_direct_configuration_and_missing_values(self):
        records = by_id(internal.assess(internal_document(), webserver_uid=33))
        self.assertEqual(records['FS-001'].confirmation_status, ConfirmationStatus.CONFIRMED)
        self.assertEqual(records['FS-001'].check_result, CheckResult.FAIL)
        missing = internal.assess(internal_document({}))
        self.assertTrue(all(f.check_result == CheckResult.NOT_TESTED for f in missing))
        self.assertTrue(all(f.severity is None for f in missing))
        mismatched = by_id(internal.assess(internal_document(),webserver_uid=999))
        self.assertEqual(mismatched['FS-001'].confirmation_status,ConfirmationStatus.NOT_TESTED)

    def test_debugdisplay_not_debug_level_and_cli_runtime_caveat(self):
        ev = {'settings':{'debug':32767,'debugdisplay':False},'runtime':{'sapi':'cli','display_errors':'1'}}
        records = by_id(internal.assess(internal_document(ev)))
        self.assertEqual(records['CFG-001'].check_result, CheckResult.PASS)
        self.assertEqual(records['PHP-001'].check_result, CheckResult.PARTIAL)
        self.assertIn('not proof of web-SAPI', records['PHP-001'].explanation)
        ev['settings']['debugdisplay'] = True
        self.assertEqual(by_id(internal.assess(internal_document(ev)))['CFG-001'].check_result, CheckResult.FAIL)

    def test_secure_cookie_https_http_and_unknown(self):
        ev = {'settings':{'wwwroot':'https://fixture/moodle/','cookiesecure':False}}
        self.assertEqual(by_id(internal.assess(internal_document(ev)))['SESSION-INT-001'].check_result, CheckResult.FAIL)
        ev['settings']['wwwroot']='http://fixture/moodle/'
        record = by_id(internal.assess(internal_document(ev)))['SESSION-INT-001']
        self.assertEqual(record.check_result, CheckResult.NOT_APPLICABLE)
        self.assertEqual(record.confirmation_status, ConfirmationStatus.NOT_APPLICABLE)
        ev['settings']['wwwroot']='https://fixture/moodle/'
        ev['settings']['cookiesecure']=None
        self.assertEqual(by_id(internal.assess(internal_document(ev)))['SESSION-INT-001'].check_result, CheckResult.NOT_TESTED)

    def test_httponly_explicit_false_and_unknown(self):
        ev={'settings':{'cookiehttponly':False}}
        record=by_id(internal.assess(internal_document(ev)))['SESSION-INT-002']
        self.assertEqual(record.check_result, CheckResult.FAIL)
        self.assertEqual(record.confirmation_status, ConfirmationStatus.CONFIRMED)
        ev['settings']['cookiehttponly']=None
        self.assertEqual(by_id(internal.assess(internal_document(ev)))['SESSION-INT-002'].confirmation_status,ConfirmationStatus.NOT_TESTED)

    def test_provenance_hashes(self):
        document = internal_document()
        for record in internal.assess(document):
            self.assertEqual(record.provenance.source_sha256, hashlib.sha256(json_bytes(document.payload)).hexdigest())
            self.assertEqual(record.provenance.source_file,document.path)
            self.assertEqual(record.provenance.record_sha256, hashlib.sha256(__import__('evidence_contracts.models',fromlist=['canonical_json']).canonical_json(record.raw_record).encode()).hexdigest())
            self.assertEqual(record.raw_record['check_result'],record.check_result)
            self.assertEqual(record.raw_record['confirmation_status'],record.confirmation_status)
            self.assertEqual(record.raw_record['severity'],record.severity)


class IntelligenceTests(unittest.TestCase):
    def catalog(self):
        return Document.load(ROOT/'src/branch1/advisories.json', ROOT)

    def test_disabled_enabled_webservice_context_and_version_semantics(self):
        document=internal_document()
        document.payload['settings']['enablewebservices']=False
        disabled=by_id(intelligence.assess(document,self.catalog()))['ADV-MSA-26-0031']
        self.assertEqual(disabled.confirmation_status,ConfirmationStatus.VERSION_BASED)
        self.assertIn('disabled',disabled.evidence['context'])
        document.payload['settings']['enablewebservices']=True
        enabled=by_id(intelligence.assess(document,self.catalog()))['ADV-MSA-26-0031']
        self.assertIn('enabled',enabled.evidence['context'])
        self.assertEqual(enabled.confirmation_status,ConfirmationStatus.VERSION_BASED)
        self.assertEqual(enabled.evidence['catalog_sha256'],self.catalog().sha256)

    def test_no_implicit_current_release_or_missing_core_claim(self):
        records=by_id(intelligence.assess(internal_document(),self.catalog()))
        self.assertNotIn('PATCH-001',records)
        record=intelligence.assess(internal_document({}),self.catalog())[0]
        self.assertEqual(record.confirmation_status,ConfirmationStatus.NOT_TESTED)
        self.assertIsNone(record.severity)

    def test_affected_range_and_explicit_patch_baseline(self):
        document=internal_document(); document.payload['core']['version']=2024100714
        records=by_id(intelligence.assess(document,self.catalog(),2024100714))
        self.assertEqual(set(records),{'CORE-001','PATCH-001'})
        self.assertEqual(records['PATCH-001'].confirmation_status,ConfirmationStatus.VERSION_BASED)


class RoleTests(unittest.TestCase):
    def inputs(self):
        return [roles.load_csv(ROOT/f'evidence/baseline/branch1/role_v3_{role}/role_{role}_v3.csv',ROOT)
                for role in ['anonymous','student','admin']]

    def test_historical_cross_role_content_dismisses_student_admin(self):
        records,payload=roles.compare(self.inputs(),'outputs/test/roles.json')
        record=next(r for r in records if r.finding_id=='ROLE-student-admin_home')
        self.assertEqual(record.check_result,CheckResult.DISMISSED)
        self.assertEqual(record.confirmation_status,ConfirmationStatus.FALSE_POSITIVE)
        self.assertEqual(record.observed_value['status'],'200')
        self.assertEqual(record.provenance.source_sha256,hashlib.sha256(json_bytes(payload)).hexdigest())

    def test_missing_comparators_never_becomes_false_positive_or_vulnerability(self):
        inputs=self.inputs()[1:2]
        records,_=roles.compare(inputs,'outputs/test/roles.json')
        record=next(r for r in records if r.finding_id=='ROLE-student-admin_home')
        self.assertEqual(record.confirmation_status,ConfirmationStatus.NOT_TESTED)

    def test_privileged_links_produce_review_not_confirmation(self):
        inputs=self.inputs()
        row=next(r for r in inputs[1]['rows'] if r['endpoint']=='admin_home')
        row['privileged_links']='["http://fixture/admin/user.php"]'
        records,_=roles.compare(inputs,'outputs/test/roles.json')
        record=next(r for r in records if r.finding_id=='ROLE-student-admin_home')
        self.assertEqual(record.confirmation_status,ConfirmationStatus.NOT_CONFIRMED)


class ExternalTests(unittest.TestCase):
    def response(self,url='http://fixture/moodle/',text='<html><title>Moodle</title></html>',status=200,headers=None):
        import requests
        response=requests.Response();response.url=url;response.status_code=status
        response._content=text.encode();response.headers.update(headers or {})
        return response

    def test_access_200_not_proof_and_permission_content(self):
        from branch1.external_rules.moodle_rules import MoodleRules
        class Fixture:
            def get(client,url): return self.response(url)
        rules=MoodleRules(Fixture(),'http://fixture/moodle/')
        raw=rules._access_finding('ACCESS-X','admin/','Admin')
        self.assertEqual(raw.status,'PARTIAL');self.assertEqual(raw.confidence,'HEURISTIC')
        with patch.object(rules.c,'get',return_value=self.response(text='You do not have permission')):
            self.assertEqual(rules._access_finding('ACCESS-X','admin/','Admin').status,'PASS')
        with patch.object(rules.c,'get',return_value=self.response(status=404)):
            self.assertEqual(rules._access_finding('ACCESS-X','admin/','Admin').status,'NOT_APPLICABLE')

    def test_cookie_per_cookie_and_html_form_component_parsing(self):
        from branch1.external_rules.cookies import cookie_findings
        from branch1.external_rules.html import Document as HTML
        import re
        response=self.response(headers={'Set-Cookie':'MoodleSession=fixture; Path=/moodle; HttpOnly; SameSite=Lax'})
        records=by_id(cookie_findings(response))
        self.assertEqual(records['COOKIE-002'].status,'PASS')
        html=HTML('<FORM method="POST"><input name="logintoken"></FORM><img src="/theme/image.php/boost/core/1/a"><a href="signup.php">Sign up</a>')
        self.assertIsNotNone(html.find('form',attrs={'method':re.compile('post',re.I)}))
        self.assertIsNotNone(html.find('input',attrs={'name':'logintoken'}))
        self.assertEqual(html.find_all(src=True)[0].get('src'),'/theme/image.php/boost/core/1/a')

    def test_bounded_client_rejects_scope_before_request(self):
        from branch1.client import Client
        import requests
        client=Client('http://fixture/moodle/')
        with patch.object(client.session,'request',side_effect=AssertionError('No network')):
            for url in ['http://other/moodle/','http://fixture:9999/','http://u:p@fixture/']:
                with self.assertRaises(requests.RequestException): client.get(url)
            with self.assertRaises(requests.RequestException):client.request('POST','http://fixture/')

    def test_redirect_rejected_without_second_request_and_request_budget(self):
        from branch1.client import Client
        import requests
        client=Client('http://fixture/moodle/',max_requests=1)
        response=self.response(headers={'Location':'http://other/'},status=302)
        response._content_consumed=True
        with patch.object(client.session,'request',return_value=response) as request:
            with self.assertRaises(requests.RequestException):client.get('http://fixture/moodle/')
            self.assertEqual(request.call_count,1)
            with self.assertRaises(requests.RequestException):client.get('http://fixture/second/')
            self.assertEqual(request.call_count,1)

    def test_external_collection_failure_not_confirmed(self):
        from branch1.external import assess
        import requests
        class Fixture:
            transcript=[]
            def get(client,url):raise requests.RequestException('fixture timeout')
        records,payload=assess('http://fixture/moodle/','outputs/test/external.json',client=Fixture())
        self.assertEqual(len(records),1)
        self.assertEqual(records[0].check_result,CheckResult.ERROR)
        self.assertEqual(records[0].confirmation_status,ConfirmationStatus.NOT_TESTED)
        self.assertEqual(payload['errors'],['fixture timeout'])

    def test_external_fixture_pipeline_and_provenance(self):
        from branch1.external import assess
        class Fixture:
            transcript=[]
            def get(client,url,**kwargs):
                text='<html><title>Moodle</title><form method="post"><input name="logintoken"></form><a href="forgot_password.php">Reset</a></html>'
                return self.response(url,text)
            def options(client,url,**kwargs):return self.response(url,status=200)
            def trace(client,url,**kwargs):return self.response(url,status=405)
        with patch('socket.socket',side_effect=AssertionError('No network')):
            records,payload=assess('http://fixture/moodle/','outputs/test/external.json',client=Fixture())
        self.assertGreater(len(records),30)
        self.assertTrue(all(isinstance(f,SecurityFinding) for f in records))
        self.assertEqual(payload['errors'],[])
        self.assertEqual(records[0].provenance.source_sha256,hashlib.sha256(json_bytes(payload)).hexdigest())
        artifacts=[f for f in records if f.finding_id.startswith('DISC-00') and f.finding_id[-1] in '456789']
        self.assertTrue(all(f.check_result==CheckResult.PASS for f in artifacts))

    def test_header_matrix_errors_not_pass(self):
        from branch1.external_rules.generic_rules import GenericRules
        record=GenericRules(None,'http://fixture/').endpoint_header_finding([{'status':'ERROR'}])
        self.assertEqual(record.status,'ERROR');self.assertEqual(record.confidence,'NOT_TESTED')


if __name__=='__main__':
    unittest.main()
