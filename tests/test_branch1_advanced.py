"""Advanced active validation uses fixture HTTP only, with network creation barred."""
import copy
import json
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from branch1 import Context, run
from branch1.active import Registry, SafetyPolicy, run_active
from branch1.active.advanced import SQLInjection, UnsafeReflection, AccountEnumeration, AccessControl, SessionControl, SSRFContext
from branch1.active.runtime import RuntimeContext
from branch1.active.models import RequestSpec
from branch1.active.safety import SafetyError
from evidence_contracts import SecurityFinding
from test_branch1_active import parent, response, executor, TARGET


class AdvancedTests(unittest.TestCase):
    def setUp(self):
        self.network = patch('socket.socket', side_effect=AssertionError('Network forbidden'))
        self.network.start()
        self.addCleanup(self.network.stop)
        self.env = patch.dict(os.environ, {'B1_LOW': 'MoodleSession=low-secret', 'B1_HIGH': 'MoodleSession=high-secret', 'B1_OLD': 'MoodleSession=old-secret'})
        self.env.start()
        self.addCleanup(self.env.stop)
        self.runtime = RuntimeContext(sessions={'low': {'role': 'student', 'cookie_env': 'B1_LOW'}, 'high': {'role': 'administrator', 'cookie_env': 'B1_HIGH'}, 'old': {'role': 'student', 'cookie_env': 'B1_OLD'}})

    def candidate(self, validator, ctx=None, confirmation='VERSION_BASED', runtime=None):
        p = parent(validator.name, 'Fixture', evidence={'active_context': dict(ctx or {}, validator=validator.name)}, confirmation=confirmation)
        return Registry((validator,)).plan([p], SafetyPolicy(TARGET), runtime or self.runtime)[0]

    def input(self, **extra):
        return dict(url=TARGET+'search.php', parameter='q', read_only=True, **extra)

    def test_sql_reproducible_database_error_is_likely(self):
        v=SQLInjection(); c=self.candidate(v,self.input(baseline_value='1'))
        result=v.evaluate(c,[response(body='normal'),response(500,'SQLSTATE[42000]'),response(body='normal'),response(500,'SQLSTATE[42000]')])
        self.assertEqual(result.confirmation_status,'LIKELY')
        self.assertEqual(len(v.requests(c)),4)
        for spec in v.requests(c):
            self.assertNotIn('UNION',spec.url); self.assertNotIn('SLEEP',spec.url)
            SafetyPolicy(TARGET,True,True).check(spec)

    def test_sql_ordinary_app_error_not_sqli(self):
        v=SQLInjection(); c=self.candidate(v,self.input(baseline_value='1'))
        result=v.evaluate(c,[response(body='ok'),response(500,'Application error'),response(body='ok'),response(500,'Application error')])
        self.assertEqual(result.confirmation_status,'NOT_CONFIRMED')

    def test_sql_unstable_error_is_weak(self):
        v=SQLInjection(); c=self.candidate(v,self.input(baseline_value='1'))
        r=v.evaluate(c,[response(body='ok'),response(500,'SQLSTATE[42000]'),response(body='changed'),response(500,'SQLSTATE[42000]')])
        self.assertEqual(r.outcome,'WEAK_DIFFERENTIAL')

    def test_sql_version_only_not_tested(self):
        p=parent('SQL injection','Vulnerability Intelligence',confirmation='VERSION_BASED')
        ex,session,_=executor([])
        ctx=Context(ROOT); run_active(ctx,[p],ex.policy,executor=ex)
        session.get.assert_not_called()
        self.assertEqual(p.to_dict()['confirmation_status'],'VERSION_BASED')
        self.assertEqual(ctx.artifacts['active_validation_results.json'][0]['confirmation_status'],'NOT_TESTED')

    def test_sql_missing_parameter_and_endpoint(self):
        v=SQLInjection()
        for ctx in ({}, {'url':TARGET,'read_only':True}, {'parameter':'q','read_only':True}):
            self.assertEqual(self.candidate(v,ctx).applicability,'MISSING_CONTEXT')

    def test_sql_rejects_extraction_baseline(self):
        self.assertEqual(self.candidate(SQLInjection(),self.input(baseline_value='1; DROP TABLE x')).applicability,'MISSING_CONTEXT')

    def reflection(self, transform, headers=None):
        v=UnsafeReflection(); c=self.candidate(v,self.input()); marker=v.marker(c)
        replies=[response(body='baseline'),response(body=transform(marker),headers=headers),response(body=transform(marker),headers=headers)]
        return v.evaluate(c,replies)

    def test_xss_no_reflection(self):
        self.assertEqual(self.reflection(lambda m:'ordinary page').outcome,'NO_REFLECTION')

    def test_xss_encoded(self):
        import html
        self.assertEqual(self.reflection(html.escape,{'Content-Type':'text/html'}).outcome,'ENCODED_REFLECTION')

    def test_xss_raw_not_confirmed_exploit(self):
        r=self.reflection(lambda m:m,{'Content-Type':'text/plain'})
        self.assertEqual(r.outcome,'RAW_REFLECTION'); self.assertEqual(r.confirmation_status,'CONTEXTUAL')

    def test_xss_attribute_and_script_context(self):
        for transform in (lambda m:'<input value="'+m+'">',lambda m:'<script>var s="'+m+'";</script>'):
            r=self.reflection(transform,{'Content-Type':'text/html'})
            self.assertEqual(r.outcome,'POTENTIALLY_UNSAFE_CONTEXT'); self.assertEqual(r.confirmation_status,'LIKELY')

    def test_xss_ambiguous_encoding(self):
        self.assertEqual(self.reflection(lambda m:m.replace('<','&lt;').replace('>','&gt;')).outcome,'INCONCLUSIVE')

    def test_xss_no_mutation_payload(self):
        v=UnsafeReflection(); c=self.candidate(v,self.input())
        for spec in v.requests(c):
            self.assertEqual(spec.method,'GET'); self.assertNotIn('alert',spec.url); self.assertNotIn('%3Cscript',spec.url)
        self.assertEqual(self.candidate(v,dict(url=TARGET+'edit.php',parameter='q',read_only=True)).applicability,'NOT_APPLICABLE')

    def enumeration(self):
        v=AccountEnumeration(); return v,self.candidate(v,self.input(test_identifiers=['known-fixture','absent-fixture'],lookup_only=True))

    def test_enumeration_identical_and_echo_ignored(self):
        v,c=self.enumeration()
        replies=[response(body='Account '+name) for name in c.context['test_identifiers']*2]
        self.assertEqual(v.evaluate(c,replies).outcome,'NO_ACCOUNT_DISTINCTION')

    def test_enumeration_reproducible(self):
        v,c=self.enumeration()
        r=v.evaluate(c,[response(body='Known account'),response(body='Unknown account')]*2)
        self.assertEqual(r.outcome,'REPRODUCIBLE_ACCOUNT_DISTINCTION'); self.assertEqual(r.confirmation_status,'CONFIRMED')

    def test_enumeration_ambiguous(self):
        v,c=self.enumeration()
        self.assertEqual(v.evaluate(c,[response(body=x) for x in ['a','b','c','d']]).confirmation_status,'NOT_CONFIRMED')

    def test_enumeration_bound_and_secret_identity_redaction(self):
        v,c=self.enumeration(); p=parent('Account enumeration','Authentication',evidence={'active_context':c.context})
        ex,session,_=executor([],3); ctx=Context(ROOT)
        run_active(ctx,[p],ex.policy,registry=Registry((v,)),executor=ex)
        session.get.assert_not_called()
        self.assertEqual(ctx.artifacts['active_validation_results.json'][0]['outcome'],'BUDGET_EXHAUSTED')
        ex,session,_=executor([response(body='known'),response(body='absent')]*2,4)
        ctx=Context(ROOT); run_active(ctx,[p],ex.policy,registry=Registry((v,)),executor=ex)
        self.assertEqual(session.get.call_count,4)
        export=json.dumps(ctx.artifacts)
        self.assertNotIn('known-fixture',export); self.assertNotIn('absent-fixture',export)

    def test_enumeration_refuses_recovery_side_effect_context(self):
        self.assertEqual(self.candidate(AccountEnumeration(),self.input(test_identifiers=['a','b'],lookup_only=False)).applicability,'MISSING_CONTEXT')

    def access(self):
        v=AccessControl()
        return v,self.candidate(v,dict(url=TARGET+'admin/index.php',read_only=True,expected_denied=True,restricted_session='low',privileged_session='high',restricted_role='student',privileged_role='administrator',identity_markers={'restricted':'identity-student','privileged':'identity-admin'},privileged_markers=['restricted-report-content']))

    def test_access_generic_200_inconclusive(self):
        v,c=self.access()
        self.assertEqual(v.evaluate(c,[response(body='Home')]*4).confirmation_status,'NOT_CONFIRMED')

    def test_access_privileged_content_stronger(self):
        v,c=self.access()
        low=response(body='identity-student restricted-report-content'); high=response(body='identity-admin restricted-report-content')
        self.assertEqual(v.evaluate(c,[low,high,low,high]).confirmation_status,'LIKELY')

    def test_access_privileged_links_only_not_proof(self):
        v,c=self.access()
        low=response(body='identity-student <a href="x">restricted-report-content</a>'); high=response(body='identity-admin restricted-report-content')
        self.assertEqual(v.evaluate(c,[low,high,low,high]).confirmation_status,'NOT_CONFIRMED')

    def test_access_denial_redirect(self):
        v,c=self.access()
        for low in (response(403),response(302,headers={'Location':'/login/index.php'})):
            self.assertEqual(v.evaluate(c,[low,response(),low,response()]).outcome,'ROLE_DENIED')

    def test_access_dismissed_never_reactivated(self):
        v,c=self.access(); p=parent('Access control','Access Control',evidence={'active_context':c.context},confirmation='FALSE_POSITIVE')
        self.assertEqual(Registry((v,)).plan([p],SafetyPolicy(TARGET),self.runtime)[0].applicability,'NOT_APPLICABLE')
        self.assertEqual(p.to_dict()['confirmation_status'],'FALSE_POSITIVE')

    def test_access_role_mismatch_or_missing_cookie(self):
        v,c=self.access(); ctx=dict(c.context,restricted_role='teacher')
        self.assertEqual(self.candidate(v,ctx).applicability,'MISSING_CONTEXT')
        with patch.dict(os.environ,{'B1_LOW':''}): self.assertEqual(self.candidate(v,c.context).applicability,'MISSING_CONTEXT')

    def test_runtime_cookie_only_sent_scoped_and_not_exported(self):
        v,c=self.access(); p=parent('Access control','Access Control',evidence={'active_context':c.context})
        ex,session,_=executor([response(body='identity-student'),response(body='identity-admin')]*2)
        ex.runtime=self.runtime
        ctx=Context(ROOT); original=copy.deepcopy(p.to_dict())
        run_active(ctx,[p],ex.policy,registry=Registry((v,)),executor=ex,runtime=self.runtime)
        self.assertEqual(session.get.call_args_list[0].kwargs['headers'],{'Cookie':'MoodleSession=low-secret'})
        self.assertEqual(session.get.call_args_list[1].kwargs['headers'],{'Cookie':'MoodleSession=high-secret'})
        self.assertNotIn('low-secret',json.dumps(ctx.artifacts)); self.assertNotIn('high-secret',json.dumps(ctx.artifacts))
        self.assertEqual(original,p.to_dict())
        for item in ctx.artifacts['active_validation_findings.json']:
            linked=SecurityFinding.from_dict(item); self.assertEqual(linked.evidence['parent_evidence_id'],p.evidence_id)

    def session(self, **extra):
        v=SessionControl(); return v,self.candidate(v,dict(url=TARGET,cookie_name='MoodleSession',read_only=True,**extra))

    def test_session_effective_attributes_and_transport(self):
        v,c=self.session()
        for attributes,expected in [('Secure; HttpOnly; SameSite=Lax','PASS'),('HttpOnly; SameSite=None','FAIL'),('Secure; SameSite=Strict','FAIL')]:
            r=response(headers={'Set-Cookie':'MoodleSession=fixture-secret; '+attributes},url='https://127.0.0.1/moodle/')
            result=v.evaluate(c,[r,r]); self.assertEqual(result.check_result,expected); self.assertEqual(result.confirmation_status,'CONFIRMED')
            self.assertNotIn('fixture-secret',json.dumps(result.__dict__))
        r=response(headers={'Set-Cookie':'MoodleSession=x; Secure; HttpOnly; SameSite=Lax'})
        self.assertEqual(v.evaluate(c,[r,r]).check_result,'FAIL')

    def test_session_configuration_effective_mismatch(self):
        v,c=self.session(configured_attributes={'secure':True,'httponly':True})
        r=response(headers={'Set-Cookie':'MoodleSession=x; SameSite=Lax'})
        self.assertTrue(v.evaluate(c,[r,r]).characteristics['configuration_mismatch'])

    def test_session_missing_auth_not_tested(self):
        v,c=self.session(require_authenticated=True)
        self.assertEqual(c.applicability,'MISSING_CONTEXT')
        v,c=self.session(require_authenticated=True,session_ref='low',authenticated_marker='identity-student')
        self.assertEqual(v.evaluate(c,[response(),response()]).confirmation_status,'NOT_TESTED')

    def test_session_missing_cookie_not_tested(self):
        v,c=self.session(); self.assertEqual(v.evaluate(c,[response(),response()]).confirmation_status,'NOT_TESTED')

    def test_session_inconsistent_attributes(self):
        v,c=self.session()
        self.assertEqual(v.evaluate(c,[response(headers={'Set-Cookie':'MoodleSession=x; Secure'}),response(headers={'Set-Cookie':'MoodleSession=x'})]).confirmation_status,'NOT_CONFIRMED')

    def test_session_prior_invalidated_session_probe_is_read_only(self):
        v,c=self.session(require_authenticated=True,session_ref='low',authenticated_marker='identity-student',invalidated_session='old',expected_invalidated=True)
        r=response(body='identity-student',headers={'Set-Cookie':'MoodleSession=x; Secure; HttpOnly; SameSite=Lax'})
        result=v.evaluate(c,[r,r,response(403),response(403)])
        self.assertEqual(result.characteristics['prior_session_observation'],'PREVIOUS_SESSION_DENIED')
        self.assertEqual(result.characteristics['rotation'],'NOT_TESTED')
        self.assertEqual(len(v.requests(c)),4)
        for spec in v.requests(c): SafetyPolicy(TARGET,True,True).check(spec)

    def test_ssrf_unavailable_feature(self):
        v=SSRFContext(); c=self.candidate(v,dict(feature_enabled=False,url_fetch_available=False,feature_evidence='fixture feature inventory'))
        self.assertEqual(v.evaluate(c,[]).confirmation_status,'NOT_APPLICABLE'); self.assertEqual(v.requests(c),[])

    def test_ssrf_exposed_context_no_requests(self):
        v=SSRFContext(); c=self.candidate(v,dict(feature_enabled=True,url_fetch_available=True,feature_evidence='fixture feature inventory',fetch_url='http://169.254.169.254/'))
        self.assertEqual(v.evaluate(c,[]).confirmation_status,'CONTEXTUAL'); self.assertEqual(v.requests(c),[])

    def test_ssrf_context_linked_without_http(self):
        v=SSRFContext(); p=parent('SSRF','Intelligence',evidence={'active_context':dict(feature_enabled=True,url_fetch_available=True,feature_evidence='fixture inventory')},confirmation='VERSION_BASED')
        ex,session,_=executor([]); ctx=Context(ROOT)
        run_active(ctx,[p],ex.policy,registry=Registry((v,)),executor=ex)
        session.get.assert_not_called()
        self.assertEqual(ctx.artifacts['active_validation_results.json'][0]['execution_status'],'CONTEXTUAL_ASSESSED')
        self.assertEqual(len(ctx.artifacts['active_validation_findings.json']),1)
        self.assertEqual(p.to_dict()['confirmation_status'],'VERSION_BASED')

    def test_ssrf_missing_feature_evidence(self):
        self.assertEqual(self.candidate(SSRFContext(),{}).applicability,'MISSING_CONTEXT')

    def test_runtime_mapping_parent_unchanged_and_planning_no_client(self):
        p=parent('Unclassified input','Fixture'); original=copy.deepcopy(p.to_dict())
        runtime=RuntimeContext(mappings={p.evidence_id:{'sql_injection':self.input(baseline_value='1')}})
        with patch('requests.Session',side_effect=AssertionError('No HTTP client in planning')):
            candidates=Registry().plan([p],SafetyPolicy(TARGET),runtime)
        self.assertEqual(candidates[0].proposed_validator,'sql_injection'); self.assertEqual(candidates[0].applicability,'APPLICABLE')
        self.assertEqual(original,p.to_dict())

    def test_runtime_rejects_literal_credentials_and_header_injection(self):
        for key in ('cookie','password','authorization'):
            with self.assertRaises(ValueError): RuntimeContext(mappings={'parent':{'access_control':{key:'secret'}}})
        with patch.dict(os.environ,{'B1_LOW':'MoodleSession=x\r\nInjected: true'}):
            with self.assertRaises(ValueError): self.runtime.cookie('low')

    def test_advanced_origin_gate_applies_before_execution(self):
        c=self.candidate(SQLInjection(),dict(url='http://other.invalid/search',parameter='q',read_only=True,baseline_value='1'))
        self.assertEqual(c.applicability,'NOT_APPLICABLE')

    def test_results_include_applicability_and_rationale(self):
        p=parent('SQL injection','Intelligence',confirmation='VERSION_BASED');ctx=Context(ROOT)
        run_active(ctx,[p],SafetyPolicy())
        result=ctx.artifacts['active_validation_results.json'][0]
        for key in ('parent_finding_id','parent_evidence_id','validator','applicability','missing_prerequisites','execution_status','confirmation_status','reason','validation_context','request_indices'):
            self.assertIn(key,result)

    def test_enumeration_identity_in_redirect_is_ignored(self):
        v,c=self.enumeration()
        replies=[response(302,headers={'Location':'/lookup?who='+name}) for name in c.context['test_identifiers']*2]
        self.assertEqual(v.evaluate(c,replies).outcome,'NO_ACCOUNT_DISTINCTION')

    def test_account_email_parameter_is_allowed_and_redacted(self):
        v=AccountEnumeration(); c=self.candidate(v,dict(url=TARGET+'lookup.php',parameter='email',read_only=True,lookup_only=True,test_identifiers=['known@example.invalid','absent@example.invalid']))
        self.assertEqual(c.applicability,'APPLICABLE')
        for spec in v.requests(c): SafetyPolicy(TARGET,True,True).check(spec)

    def test_advanced_executed_evidence_links_and_bounds(self):
        sql=SQLInjection(); xss=UnsafeReflection(); session=SessionControl()
        fixtures=[(sql,self.input(baseline_value='1'),[response(body='ok'),response(500,'SQLSTATE[42000]')]*2,4),
                  (xss,self.input(),None,3),
                  (session,dict(url=TARGET,cookie_name='MoodleSession',read_only=True),[response(headers={'Set-Cookie':'MoodleSession=secret-cookie; HttpOnly; SameSite=Lax'})]*2,2)]
        for v,context,replies,count in fixtures:
            p=parent(v.name,'Fixture',evidence={'active_context':dict(context,validator=v.name)})
            if replies is None:
                c=Registry((v,)).plan([p],SafetyPolicy(TARGET))[0]
                marker=v.marker(c)
                replies=[response(body='baseline')]+[response(body='<input value="'+marker+'">',headers={'Content-Type':'text/html'})]*2
            ex,client,_=executor(replies)
            ctx=Context(ROOT); original=copy.deepcopy(p.to_dict())
            run_active(ctx,[p],ex.policy,registry=Registry((v,)),executor=ex)
            self.assertEqual(client.get.call_count,count)
            linked=SecurityFinding.from_dict(ctx.artifacts['active_validation_findings.json'][0])
            self.assertEqual(linked.evidence['parent_finding_id'],p.finding_id)
            self.assertEqual(linked.evidence['parent_evidence_id'],p.evidence_id)
            self.assertEqual(linked.evidence['applicability'],'APPLICABLE')
            self.assertEqual(len(linked.evidence['request_indices']),count)
            self.assertEqual(original,p.to_dict())
            self.assertNotIn('secret-cookie',json.dumps(ctx.artifacts))

    def test_xss_unstable_context_inconclusive(self):
        v=UnsafeReflection(); c=self.candidate(v,self.input()); marker=v.marker(c)
        result=v.evaluate(c,[response(),response(body=marker),response(body='absent')])
        self.assertEqual(result.outcome,'INCONCLUSIVE')

    def test_session_pass_has_no_inherited_weakness_severity(self):
        v=SessionControl(); p=parent('session','Fixture',evidence={'active_context':dict(url='https://127.0.0.1/moodle/',cookie_name='MoodleSession',read_only=True)})
        ex,client,_=executor([response(headers={'Set-Cookie':'MoodleSession=x; Secure; HttpOnly; SameSite=Lax'})]*2)
        # This fixture uses an HTTPS policy and response URL, with no real TLS request.
        from dataclasses import replace
        ex.policy=replace(ex.policy,target='https://127.0.0.1/moodle/')
        ctx=Context(ROOT); run_active(ctx,[p],ex.policy,registry=Registry((v,)),executor=ex)
        self.assertIsNone(ctx.artifacts['active_validation_findings.json'][0]['severity'])

    def test_ssrf_context_requires_execution_authorization(self):
        v=SSRFContext(); p=parent('SSRF','Fixture',evidence={'active_context':dict(feature_enabled=True,url_fetch_available=True,feature_evidence='fixture inventory')})
        with patch('requests.Session',side_effect=AssertionError('No client')):
            ctx=Context(ROOT); run_active(ctx,[p],SafetyPolicy(),registry=Registry((v,)))
        self.assertEqual(ctx.artifacts['active_validation_results.json'][0]['confirmation_status'],'NOT_TESTED')
        self.assertEqual(ctx.artifacts['active_validation_findings.json'],[])

    def test_runtime_from_environment_no_files(self):
        payload={'mappings':{'parent':{'sql_injection':self.input(baseline_value='1')}},'sessions':{'low':{'role':'student','cookie_env':'B1_LOW'}}}
        with patch.dict(os.environ,{'B1_CONTEXT':json.dumps(payload)}):
            runtime=RuntimeContext.from_env('B1_CONTEXT')
        self.assertEqual(runtime.sessions['low']['role'],'student')
        with patch.dict(os.environ,{'B1_CONTEXT':'{"password":"secret"}'}):
            with self.assertRaises(ValueError): RuntimeContext.from_env('B1_CONTEXT')

    def test_access_ambiguous_identity_not_verified(self):
        v,c=self.access(); r=response(body='identity-student identity-admin restricted-report-content')
        self.assertEqual(v.evaluate(c,[r]*4).confirmation_status,'NOT_CONFIRMED')

    def test_xss_html_comment_is_ambiguous(self):
        self.assertEqual(self.reflection(lambda m:'<!-- <script>'+m+' -->',{'Content-Type':'text/html'}).confirmation_status,'NOT_CONFIRMED')

    def test_session_prior_identity_remains_likely(self):
        v,c=self.session(require_authenticated=True,session_ref='low',authenticated_marker='identity-student',invalidated_session='old',expected_invalidated=True)
        r=response(body='identity-student',headers={'Set-Cookie':'MoodleSession=x; Secure; HttpOnly; SameSite=Lax'})
        result=v.evaluate(c,[r]*4)
        self.assertEqual(result.confirmation_status,'LIKELY')
        self.assertEqual(result.check_result,'FAIL')

    def test_runtime_missing_env_is_explicit_error(self):
        with patch.dict(os.environ,{},clear=True):
            with self.assertRaises(ValueError): RuntimeContext.from_env('B1_MISSING_CONTEXT')

    def cookie_parent(self, suffix, **context):
        from branch1.common import Document, finding
        return finding(Document.generated('cookie-fixture.json', {}), 'fixture',
                       'COOKIE-MoodleSession-' + suffix, 'Authentication & Session',
                       'MoodleSession ' + {'SECURE': 'Secure flag', 'HTTPONLY': 'HttpOnly flag', 'SAMESITE': 'SameSite attribute'}[suffix],
                       'PARTIAL', 'NOT_CONFIRMED', 'LOW', evidence={'active_context':
                       dict(url=TARGET+'login/index.php', cookie_name='MoodleSession', read_only=True, **context)})

    def kali_cookie(self):
        return response(headers={'Set-Cookie': 'MoodleSession=fixture-secret; HttpOnly; SameSite=Lax'}, url=TARGET+'login/index.php')

    def test_kali_cookie_independent_parent_outcomes_and_attributes(self):
        v=SessionControl()
        expected={'SECURE':('FAIL','CONFIRMED'), 'HTTPONLY':('PASS','NOT_CONFIRMED'), 'SAMESITE':('PASS','NOT_CONFIRMED')}
        attrs={'secure':False,'httponly':True,'samesite':'lax','transport':'http'}
        for suffix,status in expected.items():
            p=self.cookie_parent(suffix); original=copy.deepcopy(p.to_dict())
            c=Registry((v,)).plan([p],SafetyPolicy(TARGET))[0]
            r=self.kali_cookie(); result=v.evaluate(c,[r,r])
            self.assertEqual((result.check_result,result.confirmation_status),status)
            self.assertEqual(result.characteristics['effective_attributes'],attrs)
            self.assertEqual(result.characteristics['effective_attribute_observations'],[attrs,attrs])
            self.assertIsNone(result.characteristics['configuration_mismatch'])
            self.assertEqual(original,p.to_dict())
            self.assertNotIn('fixture-secret',json.dumps(result.__dict__))

    def test_kali_cookie_linked_results_preserve_all_parents(self):
        parents=[self.cookie_parent(suffix) for suffix in ('SECURE','HTTPONLY','SAMESITE')]
        original=copy.deepcopy([p.to_dict() for p in parents])
        ex,client,_=executor([self.kali_cookie() for _ in range(6)])
        ctx=Context(ROOT)
        run_active(ctx,parents,ex.policy,registry=Registry((SessionControl(),)),executor=ex)
        results=ctx.artifacts['active_validation_results.json']
        self.assertEqual([(r['check_result'],r['confirmation_status']) for r in results],
                         [('FAIL','CONFIRMED'),('PASS','NOT_CONFIRMED'),('PASS','NOT_CONFIRMED')])
        linked=[SecurityFinding.from_dict(r) for r in ctx.artifacts['active_validation_findings.json']]
        for p,record in zip(parents,linked):
            self.assertEqual(record.evidence['parent_finding_id'],p.finding_id)
            self.assertEqual(record.evidence['parent_evidence_id'],p.evidence_id)
            self.assertEqual(record.evidence['characteristics']['effective_attributes'],
                             {'secure':False,'httponly':True,'samesite':'lax','transport':'http'})
        self.assertEqual(original,[p.to_dict() for p in parents])
        self.assertEqual(client.get.call_count,6)

    def test_samesite_lax_only_fails_explicit_stronger_policy(self):
        v=SessionControl(); p=self.cookie_parent('SAMESITE',samesite_policy=['strict'])
        c=Registry((v,)).plan([p],SafetyPolicy(TARGET))[0]
        r=self.kali_cookie(); result=v.evaluate(c,[r,r])
        self.assertEqual((result.check_result,result.confirmation_status),('FAIL','CONFIRMED'))
        self.assertEqual(result.characteristics['samesite_policy'],['strict'])

    def test_specific_cookie_weaknesses_confirm_only_their_parent(self):
        v=SessionControl()
        for suffix,cookie in [('HTTPONLY','MoodleSession=x; Secure; SameSite=Lax'),('SAMESITE','MoodleSession=x; Secure; HttpOnly')]:
            c=Registry((v,)).plan([self.cookie_parent(suffix)],SafetyPolicy(TARGET))[0]
            r=response(headers={'Set-Cookie':cookie})
            self.assertEqual(v.evaluate(c,[r,r]).confirmation_status,'CONFIRMED')

    def test_conflicting_context_cannot_override_parent_predicate(self):
        for predicate in ('secure','all_attributes','unknown'):
            p=self.cookie_parent('HTTPONLY',session_predicate=predicate)
            c=Registry((SessionControl(),)).plan([p],SafetyPolicy(TARGET))[0]
            self.assertEqual(c.applicability,'MISSING_CONTEXT')

    def test_configuration_reference_or_empty_unparsed_expectation_is_unknown(self):
        v=SessionControl()
        for ctx in ({}, {'configuration_reference':'evidence/internal.json#/settings'},
                    {'configured_attributes':{}}, {'configured_attributes':{'secure':None}},
                    {'configured_attributes':{'secure':'unparsed'}}, {'configured_attributes':{'unrelated':True}}):
            c=Registry((v,)).plan([self.cookie_parent('SECURE',**ctx)],SafetyPolicy(TARGET))[0]
            r=self.kali_cookie(); details=v.evaluate(c,[r,r]).characteristics
            self.assertIsNone(details['configuration_mismatch'])
            self.assertEqual(details['configuration_assessment'],'NOT_ASSESSED')

    def test_explicit_configured_secure_expectation_is_parsed_and_compared(self):
        v=SessionControl()
        for key,value in [('secure',True),('secure','1'),('cookiesecure','1')]:
            c=Registry((v,)).plan([self.cookie_parent('SECURE',configured_attributes={key:value})],SafetyPolicy(TARGET))[0]
            r=self.kali_cookie(); details=v.evaluate(c,[r,r]).characteristics
            self.assertTrue(details['configuration_mismatch'])
            self.assertEqual(details['configured_expectations']['secure'],True)
            self.assertTrue(details['configuration_comparisons']['secure'])

    def test_configuration_for_other_attribute_does_not_contaminate_parent(self):
        v=SessionControl(); p=self.cookie_parent('HTTPONLY',configured_attributes={'secure':True})
        c=Registry((v,)).plan([p],SafetyPolicy(TARGET))[0]
        r=self.kali_cookie(); result=v.evaluate(c,[r,r])
        self.assertEqual((result.check_result,result.confirmation_status),('PASS','NOT_CONFIRMED'))
        self.assertIsNone(result.characteristics['configuration_mismatch'])
        self.assertTrue(result.characteristics['configuration_comparisons']['secure'])

    def test_matching_relevant_configuration_is_assessed_false(self):
        v=SessionControl()
        for suffix,ctx in [('HTTPONLY',{'cookiehttponly':'1'}),('SAMESITE',{'cookiesamesite':'Lax'}),('SECURE',{'cookiesecure':'0'})]:
            c=Registry((v,)).plan([self.cookie_parent(suffix,configured_settings=ctx)],SafetyPolicy(TARGET))[0]
            r=self.kali_cookie(); details=v.evaluate(c,[r,r]).characteristics
            self.assertIs(details['configuration_mismatch'],False)
            self.assertEqual(details['configuration_assessment'],'ASSESSED')

    def test_internal_config_observation_supplies_expectation_without_parent_mutation(self):
        from dataclasses import replace
        v=SessionControl(); p=replace(self.cookie_parent('SECURE'),observed_value={'cookiesecure':'1','wwwroot':TARGET})
        original=copy.deepcopy(p.to_dict())
        c=Registry((v,)).plan([p],SafetyPolicy(TARGET))[0]
        r=self.kali_cookie(); self.assertTrue(v.evaluate(c,[r,r]).characteristics['configuration_mismatch'])
        self.assertEqual(original,p.to_dict())

    def test_prior_session_observation_does_not_override_httponly_parent(self):
        v=SessionControl(); p=self.cookie_parent('HTTPONLY',require_authenticated=True,session_ref='low',authenticated_marker='identity-student',invalidated_session='old',expected_invalidated=True)
        c=Registry((v,)).plan([p],SafetyPolicy(TARGET),self.runtime)[0]
        r=response(body='identity-student',headers={'Set-Cookie':'MoodleSession=x; HttpOnly; SameSite=Lax'})
        result=v.evaluate(c,[r]*4)
        self.assertEqual((result.check_result,result.confirmation_status),('PASS','NOT_CONFIRMED'))
        self.assertEqual(result.characteristics['prior_session_observation'],'PREVIOUS_SESSION_STILL_AUTHENTICATED')


if __name__ == '__main__': unittest.main()
