#!/usr/bin/env python3
"""Read-only browser acceptance of the isolated UX candidate, never lab controls."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
from urllib.parse import urlsplit
from urllib.request import urlopen

ROOT=Path(__file__).resolve().parents[1]

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',default='outputs/ux/phaseb_20261104_01')
    parser.add_argument('--port',type=int,default=18004)
    args=parser.parse_args()
    if args.port==8000:parser.error('Never use the production port')
    out=ROOT/args.output
    if out.exists():parser.error('Use a new evidence directory; no previous receipt overwritten')
    if os.statvfs(ROOT).f_bavail*os.statvfs(ROOT).f_frsize<500*1024**2:parser.error('Insufficient disk')
    out.mkdir(parents=True)
    env=dict(os.environ,PYTHONDONTWRITEBYTECODE='1',PRODUCT_FACTORY_ONLY='1',OPENBLAS_NUM_THREADS='1',OMP_NUM_THREADS='1')
    result={'status':'INCOMPLETE','checks':[],'screenshots':[],'write_requests':[],'foreign_requests':[],'javascript_errors':[],
            'production_restarted':False,'monitor_controller_created':False,'scans_executed':False}
    base=f'http://127.0.0.1:{args.port}'
    process=None
    def passed(name):result['checks'].append(name);print('PASS '+name,flush=True)
    def get(path):
        with urlopen(base+path,timeout=20) as r:return json.load(r)
    try:
        process=subprocess.Popen([str(ROOT/'.venv/bin/python'),'-B',str(ROOT/'scripts/run_ux_preview.py'),'--port',str(args.port),
            '--retained-session','runtime/behavioral_v2/ui-e01c26a593174d42bec5d45faf703576'],cwd=ROOT,env=env,
            stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        deadline=time.monotonic()+45
        while True:
            if process.poll() is not None:raise RuntimeError('Isolated preview exited before readiness')
            try:
                if get('/api/health')['preview_read_only']:break
            except OSError:pass
            if time.monotonic()>deadline:raise TimeoutError('Preview startup deadline')
            time.sleep(.25)
        passed('isolated_read_only_backend')
        from playwright.sync_api import sync_playwright,expect
        browser_env=dict(env,LD_LIBRARY_PATH=str(ROOT/'.tools/chromium-runtime/extracted/usr/lib/x86_64-linux-gnu'))
        with sync_playwright() as p:
            browser=p.chromium.launch(headless=True,executable_path=str(ROOT/'.tools/ms-playwright/chromium_headless_shell-1248/chrome-headless-shell-linux64/chrome-headless-shell'),env=browser_env)
            try:
                page=browser.new_page(viewport={'width':1600,'height':1000})
                page.set_default_timeout(15000)
                def scope(route):
                    request=route.request;url=urlsplit(request.url)
                    if request.method not in ('GET','HEAD','OPTIONS'):
                        result['write_requests'].append({'method':request.method,'path':url.path});route.abort()
                    elif url.hostname!='127.0.0.1' or url.port not in (args.port,8000):
                        result['foreign_requests'].append(url.origin if hasattr(url,'origin') else url.netloc);route.abort()
                    else:route.continue_()
                page.route('**/*',scope)
                page.on('pageerror',lambda e:result['javascript_errors'].append(str(e)))
                def shot(name):
                    page.evaluate('window.scrollTo(0,0)')
                    page.screenshot(path=str(out/(name+'.png')),full_page=page.get_by_role('dialog').count()==0)
                    result['screenshots'].append(name+'.png')
                def nav(name):page.get_by_role('navigation',name='Main navigation').get_by_role('button',name=name,exact=True).click()
                # Only GET and static rendering against the stable service.
                page.goto('http://127.0.0.1:8000/');page.locator('.gauge').wait_for();shot('before_overview_stable')
                passed('stable_before_screenshot_GET_only')
                page.goto(base);page.locator('.quality-hero').wait_for();shot('after_overview_current')
                expect(page.get_by_text('READ-ONLY UX PREVIEW · saved evidence · operational controls disabled')).to_be_visible()
                passed('current_context_conditional_coverage_conservative')
                nav('Security posture');page.get_by_role('button',name='Inspect finding').first.wait_for()
                before=page.locator('.finding-summary').first.inner_text()
                page.get_by_role('button',name='Next',exact=True).click()
                expect(page.locator('.pagination')).to_contain_text('26–')
                expect(page.locator('.finding-summary').first).not_to_have_text(before)
                page.get_by_label('Finding status',exact=True).select_option('FAIL')
                expect(page.locator('.pagination')).to_contain_text('of 41 findings')
                expect(page.locator('.finding-summary .badge')).to_have_text(['FAIL']*25)
                page.get_by_label('Finding status',exact=True).select_option('UNMAPPED')
                expect(page.locator('.pagination')).to_contain_text('of 23 findings')
                expect(page.get_by_text('Not mapped to CQI · finding retained',exact=True)).to_have_count(23)
                page.get_by_label('Finding status',exact=True).select_option('FAIL')
                expect(page.locator('.pagination')).to_contain_text('of 41 findings')
                assert page.get_by_label('Finding category',exact=True).locator('option').count()>2
                shot('after_posture_current')
                trigger=page.get_by_role('button',name='Inspect finding').first
                trigger.click();dialog=page.get_by_role('dialog');dialog.wait_for()
                expect(dialog).to_contain_text('Source remediation')
                page.keyboard.press('Shift+Tab');assert dialog.evaluate('(el)=>el.contains(document.activeElement)')
                page.keyboard.press('Escape');expect(dialog).to_have_count(0);expect(trigger).to_be_focused()
                passed('posture_server_pagination_filter_drawer_focus_escape')
                page.get_by_label('Evidence view',exact=True).select_option('ACCEPTED_REPLAY')
                page.get_by_label('Evaluation set',exact=True).select_option('BENIGN_TEST')
                nav('Overview');expect(page.locator('.coverage-reading')).to_contain_text('51.75%')
                shot('after_overview_benign')
                assert page.locator('.dimension-card').count()==6
                page.get_by_role('button',name='Inspect D5',exact=True).click()
                expect(page.get_by_role('dialog')).to_contain_text('Reliability-adjusted coverage');page.keyboard.press('Escape')
                nav('Behavioral monitoring');expect(page.locator('.pagination')).to_contain_text('of 33 observations')
                page.get_by_role('button',name='Next',exact=True).click();expect(page.locator('.pagination')).to_contain_text('26–33')
                page.get_by_label('Observation status',exact=True).select_option('BENIGN')
                expect(page.locator('.pagination')).to_contain_text('of 32 observations')
                page.get_by_role('button',name='Explain',exact=True).first.click()
                expect(page.get_by_role('dialog')).to_contain_text('WHY DOES THIS WINDOW APPEAR NORMAL?')
                page.get_by_role('tab',name='Important factors',exact=True).click()
                expect(page.get_by_role('dialog')).to_contain_text('Benign TRAIN median');shot('after_explanation_benign')
                page.get_by_role('dialog').get_by_text('Technical details',exact=True).click()
                expect(page.get_by_role('dialog')).to_contain_text('XGBoost attribution')
                expect(page.get_by_role('dialog')).to_contain_text('Raw feature values')
                page.keyboard.press('Escape')
                passed('benign_observation_full_pagination_numeric_factors_SHAP')
                page.get_by_label('Evaluation set',exact=True).select_option('ATTACK_HOLDOUT')
                nav('Incidents');page.get_by_role('button',name='Inspect episode',exact=True).first.click()
                expect(page.get_by_role('dialog')).to_contain_text('Why this episode exists')
                page.get_by_role('button',name='Model explanation',exact=True).first.click()
                expect(page.get_by_role('dialog')).to_have_count(1)
                page.get_by_role('button',name='Back to previous detail').click()
                expect(page.get_by_role('dialog')).to_contain_text('Why this episode exists');page.keyboard.press('Escape')
                shot('after_incidents')
                passed('episode_observation_back_navigation_single_dialog')
                nav('Model & research');expect(page.locator('.benchmark-bars')).to_contain_text('65/68')
                expect(page.locator('.benchmark-bars')).to_contain_text('41/68')
                expect(page.locator('.benchmark-bars')).to_contain_text('3/68')
                shot('after_research_novelty')
                page.get_by_role('tab',name='Classification',exact=True).click()
                expect(page.locator('.research-measures')).to_contain_text('99/101')
                assert page.locator('.confusion-matrix tbody tr').count()==8
                shot('after_research_classification')
                page.get_by_label('Classification evaluation scope',exact=True).select_option('attack_only')
                expect(page.locator('.research-measures')).to_contain_text('66/68')
                page.get_by_role('tab',name='Classification',exact=True).focus();page.keyboard.press('ArrowRight')
                expect(page.get_by_role('tab',name='Accepted v1/v2 evidence',exact=True)).to_have_attribute('aria-selected','true')
                expect(page.get_by_text('93.94%',exact=True)).to_be_visible()
                passed('verified_novelty_matrix_classifier_and_history_keyboard_tabs')
                nav('Cybersecurity quality');page.get_by_role('tab',name='Mathematical method',exact=True).click()
                assert page.get_by_role('link',name='Open full mathematical specification').get_attribute('href')=='/api/research/cqi-method'
                page.get_by_role('tab',name='Contributors & coverage',exact=True).click();shot('after_quality_coverage')
                page.get_by_role('tab',name='Contextual fusion',exact=True).click()
                expect(page.get_by_text('NO DIRECT CQI EFFECT',exact=True)).to_be_visible()
                passed('CQI_dimensions_coverage_method_and_fusion_preserved')
                nav('System & evidence');page.get_by_role('button',name='Inspect accepted generic example',exact=True).click()
                expect(page.get_by_text('ACCEPTED GENERIC FIXTURE · not newly supplied telemetry',exact=True)).to_be_visible()
                expect(page.get_by_text('Compatibility does not establish equal accuracy on another LMS.',exact=False)).to_be_visible()
                page.get_by_text('Full canonical schema and feature dependencies',exact=True).click()
                page.get_by_role('button',name='Load dependency specification',exact=True).click()
                expect(page.locator('details').filter(has=page.get_by_role('button',name='Load dependency specification',exact=True)).locator('pre')).to_contain_text('feature')
                page.get_by_text('Full canonical schema and feature dependencies',exact=True).click()
                page.get_by_text('Authorized laboratory controls',exact=True).click()
                expect(page.get_by_role('button',name='Start monitoring',exact=True)).to_be_disabled()
                shot('after_system_generic')
                passed('generic_capability_limitations_read_only_controls')
                page.get_by_label('Evidence view',exact=True).select_option('LIVE_LAB')
                nav('Behavioral monitoring');page.get_by_role('button',name='Explain',exact=True).first.wait_for()
                page.get_by_role('button',name='Explain',exact=True).first.click()
                expect(page.get_by_role('dialog')).to_contain_text('WHY ')
                page.get_by_role('button',name='Inspect sanitized provenance',exact=True).click()
                expect(page.get_by_role('dialog')).to_contain_text('PROVENANCE / SANITIZED');page.keyboard.press('Escape');page.keyboard.press('Escape')
                passed('actual_retained_LIVE_journal_explanation_and_bound_provenance')
                # Browser-only fixture: a valid saved vector under a synthetic
                # page-local ID proves polling does not close a later-page row.
                fixture=get('/api/product/observations?mode=LIVE_LAB&limit=1')
                fixture['items'][0]['observation_id']='browser-fixture-outside-first-200'
                page.route('**/api/product/observations?**',lambda r:r.fulfill(status=200,json=fixture))
                nav('Overview');nav('Behavioral monitoring')
                page.get_by_role('button',name='Explain',exact=True).first.click()
                with page.expect_response(lambda r:'/api/product/assessment?' in r.url):
                    expect(page.get_by_role('dialog')).to_be_visible()
                expect(page.get_by_role('dialog')).to_be_visible()
                page.keyboard.press('Escape');page.unroute('**/api/product/observations?**')
                passed('later_page_observation_survives_poll_BROWSER_FIXTURE_ONLY')
                snapshot=get('/api/product/assessment?mode=LIVE_LAB');aid=snapshot['history'][0]['assessment_id']
                page.get_by_label('Posture snapshot',exact=True).select_option(aid)
                nav('Overview');expect(page.get_by_text('D6 is unavailable for this historical posture. Current incidents are not substituted.',exact=True)).to_be_visible()
                nav('Cybersecurity quality');page.get_by_role('tab',name='History & comparison',exact=True).click();shot('after_history_unpaired')
                nav('Overview')
                for width in (1280,768):
                    page.set_viewport_size({'width':width,'height':900})
                    assert page.evaluate('document.documentElement.scrollWidth <= innerWidth + 1')
                    shot('after_overview_'+str(width))
                passed('historical_D6_unpaired_and_responsive_1280_768')
                # Explicit failures are browser fixtures, never reported as live API evidence.
                page.route('**/api/product/assessment?**',lambda r:r.fulfill(status=503,json={'error':'SOURCE_UNAVAILABLE','message':'TEST FIXTURE: source unavailable'}))
                page.reload();expect(page.get_by_role('alert')).to_contain_text('TEST FIXTURE: source unavailable')
                assert page.get_by_text('LEGACY POLICY VIEW',exact=False).count()==0
                passed('503_browser_fixture_does_not_fall_back_to_v1')
                page.unroute('**/api/product/assessment?**')
                page.route('**/api/product/assessment?**',lambda r:r.fulfill(status=404,json={'detail':'TEST FIXTURE: projection missing'}))
                page.reload();expect(page.get_by_text('LEGACY POLICY VIEW',exact=False)).to_be_visible()
                passed('404_browser_fixture_is_explicitly_labelled_legacy')
                assert not result['write_requests'],result['write_requests']
                assert not result['foreign_requests'],result['foreign_requests']
                assert not result['javascript_errors'],result['javascript_errors']
                passed('zero_browser_writes_foreign_requests_or_JS_errors')
            finally:browser.close()
        result['status']='PASS'
    except Exception as e:
        result['status']='FAIL';result['failure']=str(e);raise
    finally:
        if process and process.poll() is None:
            process.terminate()
            try:process.wait(timeout=10)
            except subprocess.TimeoutExpired:process.kill();process.wait(timeout=5)
        result['preview_process_stopped']=process is not None and process.poll() is not None
        result['files_sha256']={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in out.glob('*.png')}
        (out/'browser_receipt.json').write_text(json.dumps(result,indent=2)+'\n')

if __name__=='__main__':main()
