"""Source-shaped Moodle form fixtures; no HTTP and no real tokens/credentials."""
import json
import os
import unittest
from unittest.mock import patch
from test_branch2_capture import CONTEXT,Clock,Response,Session
from branch2.capture.planning import schedule,TARGET
from branch2.capture.traffic import Form,execute


def login(token='fixture-private-token',action='/moodle/login/index.php',extra=''):
    return (f'<form id="login" class="login-form" method="post" action="{action}">'
            f'<input type="hidden" name="logintoken" value="{token}">'
            '<input type="text" name="username"><input type="password" name="password">'
            f'{extra}</form>')

GUEST=('<form id="guestlogin" method="post" action="/moodle/login/index.php">'
       '<input type="hidden" name="logintoken" value="fixture-guest-token">'
       '<input type="hidden" name="username" value="guest">'
       '<input type="hidden" name="password" value="guest"></form>')


class LoginFormTests(unittest.TestCase):
    def setUp(self):
        blocker=patch('socket.socket',side_effect=AssertionError('No network'))
        blocker.start();self.addCleanup(blocker.stop)

    def parse(self,body):
        form=Form();form.feed(body);form.close();return form

    def test_real_page_like_credential_and_guest_forms_select_credentials(self):
        for body in (login()+GUEST,GUEST+login()):
            with self.subTest(order=body.startswith('<form id="login"')):
                form=self.parse(body)
                self.assertEqual(form.token,'fixture-private-token');self.assertEqual(form.token_count,1)
                form.clear_tokens();self.assertIsNone(form.token)
                self.assertTrue(all(f['token'] is None for f in form._forms))

    def test_unrelated_outside_token_ignored_in_both_orders(self):
        other='<input name="logintoken" value="fixture-outside-token">'
        for body in (other+login(),login()+other):
            self.assertEqual(self.parse(body).token,'fixture-private-token')

    def test_unrelated_form_token_ignored(self):
        other='<form action="/moodle/search/index.php" method="get"><input name="logintoken" value="fixture-other-token"></form>'
        self.assertEqual(self.parse(other+login()).token,'fixture-private-token')

    def test_two_qualifying_post_forms_rejected_even_identical_tokens(self):
        self.assertIsNone(self.parse(login()+login()).token)

    def test_off_origin_action_rejected(self):
        for action in ('http://outside.invalid/moodle/login/index.php','//outside.invalid/moodle/login/index.php','https://192.168.226.132/moodle/login/index.php'):
            self.assertIsNone(self.parse(login(action=action)).token)

    def test_wrong_endpoint_query_fragment_or_method_rejected(self):
        for action in (TARGET+'my/',TARGET+'login/index.php?testsession=2',TARGET+'login/index.php#x'):
            self.assertIsNone(self.parse(login(action=action)).token)
        self.assertIsNone(self.parse(login().replace('method="post"','method="get"')).token)

    def test_missing_token_rejected(self):
        self.assertIsNone(self.parse('<form method="post" action="/moodle/login/index.php"></form>').token)
        self.assertIsNone(self.parse('<input name="logintoken" value="fixture-private-token">').token)

    def test_duplicate_tokens_in_selected_form_rejected(self):
        form=self.parse(login(extra='<input name="logintoken" value="fixture-extra-token">'))
        self.assertEqual(form.token_count,2);self.assertIsNone(form.token)

    def test_empty_missing_or_disabled_token_rejected(self):
        for body in (login(token=''),login(token='   '),login().replace('value="fixture-private-token"',''),login().replace('name="logintoken"','disabled name="logintoken"')):
            self.assertIsNone(self.parse(body).token)

    def test_relative_and_absolute_authorized_actions_accepted(self):
        for action in ('/moodle/login/index.php','index.php',TARGET+'login/index.php'):
            self.assertEqual(self.parse(login(action=action)).token,'fixture-private-token')

    def test_incomplete_nested_base_and_external_association_fail_closed(self):
        for body in (login().replace('</form>',''), '<form>'+login()+'</form>',
                     '<base href="http://outside.invalid/">'+login(),
                     login().replace('name="logintoken"','form="other" name="logintoken"'),
                     login()+'<input form="login" name="logintoken" value="fixture-other-token">'):
            self.assertIsNone(self.parse(body).token)

    def test_guest_id_with_interactive_credentials_does_not_hide_competing_form(self):
        self.assertIsNone(self.parse(login()+login().replace('id="login"','id="guestlogin"')).token)
        self.assertIsNone(self.parse(GUEST).token)

    def test_real_like_form_303_fresh_state_and_no_secrets_in_result(self):
        run=schedule(CONTEXT,only_run_id='S01-run06')['runs'][0];clock=Clock();tokens=[]
        def handler(session,method,url,options):
            if method=='GET':
                self.assertFalse(session.cookies)
                token=f'fixture-private-token-{len(tokens)}';tokens.append(token)
                session.cookies.set('MoodleSession','fixture-private-cookie')
                return Response(body=GUEST+login(token))
            self.assertEqual(options['data']['logintoken'],tokens[-1])
            return Response(303,headers={'Location':TARGET+'login/index.php?loginredirect=1'})
        session=Session(handler)
        with patch.dict(os.environ,{'B2_FICTITIOUS_PASSWORD':'fixture-private-password'}):
            result=execute(run,CONTEXT,True,session=session,clock=clock.monotonic,sleep=clock.sleep,worker_check=False)
        self.assertEqual(result['status'],'COMPLETE');self.assertEqual(result['actual_request_count'],12)
        self.assertEqual(len(set(tokens)),6);self.assertFalse(session.cookies)
        self.assertTrue(all(not call[2]['allow_redirects'] for call in session.calls))
        self.assertNotIn('fixture-',json.dumps(result))

    def test_ambiguous_form_fails_before_post_without_secret_error(self):
        run=schedule(CONTEXT,only_run_id='S01-run06')['runs'][0];clock=Clock()
        session=Session(lambda *a:Response(body=login()+login()))
        with patch.dict(os.environ,{'B2_FICTITIOUS_PASSWORD':'fixture-private-password'}):
            result=execute(run,CONTEXT,True,session=session,clock=clock.monotonic,sleep=clock.sleep,worker_check=False)
        self.assertEqual(result['status'],'FAILED');self.assertEqual(result['actual_request_count'],1)
        self.assertNotIn('fixture-',json.dumps(result));self.assertFalse(session.cookies)

    def test_admin_uses_same_form_selection(self):
        run=next(r for r in schedule(CONTEXT)['runs'] if r['auth_role']);clock=Clock()
        def handler(session,method,url,options):
            if method=='POST':
                self.assertEqual(options['data']['logintoken'],'fixture-private-token')
                session.cookies.set('MoodleSession','fixture-private-cookie',domain='192.168.226.132',path='/moodle/')
                for cookie in session.cookies:cookie.domain_specified=False
                return Response(302,headers={'Location':TARGET+'my/'})
            if url==TARGET+'login/index.php':return Response(body=login()+GUEST)
            return Response(body=CONTEXT['identity_markers']['administrator'])
        session=Session(handler)
        with patch.dict(os.environ,{'B2_ADMIN_USERNAME':'fixture-admin','B2_ADMIN_PASSWORD':'fixture-private-password'}):
            result=execute(run,CONTEXT,True,session=session,clock=clock.monotonic,sleep=clock.sleep,worker_check=False)
        self.assertEqual(result['status'],'COMPLETE');self.assertFalse(session.cookies)
        self.assertNotIn('fixture-',json.dumps(result))


if __name__=='__main__':unittest.main()
