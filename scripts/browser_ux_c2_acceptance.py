#!/usr/bin/env python3
"""C2 read-only visual acceptance. Operational interactions use browser-only fixtures."""
import argparse,hashlib,json,os,subprocess,time
from copy import deepcopy
from pathlib import Path
from urllib.parse import urlsplit
from urllib.request import urlopen
ROOT=Path(__file__).resolve().parents[1]

def main(extra_checks=None):
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--port',type=int,default=18006)
    p.add_argument('--output',default='outputs/ux/c2_20261104_01')
    p.add_argument('--assets',default='demo/frontend/preview-ux-c2-20261104')
    p.add_argument('--skip-before',action='store_true',help='Validate candidate without contacting the operator Phase B preview')
    a=p.parse_args()
    if a.port in (8000,18004):p.error('Preserve stable and operator Phase B preview ports')
    out=ROOT/a.output
    if out.exists():p.error('Use a new receipt directory')
    if os.statvfs(ROOT).f_bavail*os.statvfs(ROOT).f_frsize<500*1024**2:p.error('Low disk')
    out.mkdir(parents=True)
    env=dict(os.environ,PYTHONDONTWRITEBYTECODE='1',PRODUCT_FACTORY_ONLY='1',OPENBLAS_NUM_THREADS='1',OMP_NUM_THREADS='1')
    result={'status':'INCOMPLETE','checks':[],'screenshots':[],'blocked_mutations':[], 'fixture_mutations':[],
        'forwarded_mutations':0,'foreign_requests':[],'javascript_errors':[],
        'scans_executed':False,'monitor_controller_created':False,'production_restarted':False}
    base=f'http://127.0.0.1:{a.port}';process=None
    def passed(name):result['checks'].append(name);print('PASS '+name,flush=True)
    def get(path):
        with urlopen(base+path,timeout=25) as r:return json.load(r)
    try:
        process=subprocess.Popen([str(ROOT/'.venv/bin/python'),'-B',str(ROOT/'scripts/run_ux_preview.py'),'--port',str(a.port),'--assets',a.assets,
          '--retained-session','runtime/behavioral_v2/ui-e01c26a593174d42bec5d45faf703576'],cwd=ROOT,env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        deadline=time.monotonic()+45
        while True:
            if process.poll() is not None:raise RuntimeError('Preview exited')
            try:
                if get('/api/health')['preview_read_only']:break
            except OSError:pass
            if time.monotonic()>deadline:raise TimeoutError('Preview readiness')
            time.sleep(.25)
        passed('isolated_read_only_preview')
        from playwright.sync_api import sync_playwright,expect
        expect.set_options(timeout=15000)
        with sync_playwright() as pw:
            browser=pw.chromium.launch(headless=True,executable_path=str(ROOT/'.tools/ms-playwright/chromium_headless_shell-1248/chrome-headless-shell-linux64/chrome-headless-shell'),
                env=dict(env,LD_LIBRARY_PATH=str(ROOT/'.tools/chromium-runtime/extracted/usr/lib/x86_64-linux-gnu')))
            try:
                page=browser.new_page(viewport={'width':1600,'height':1000});page.set_default_timeout(15000)
                def scope(route):
                    req=route.request;url=urlsplit(req.url)
                    if req.method not in ('GET','HEAD','OPTIONS'):
                        result['blocked_mutations'].append({'method':req.method,'path':url.path});route.abort()
                    elif url.hostname!='127.0.0.1' or url.port not in (a.port,18004):
                        result['foreign_requests'].append(url.netloc);route.abort()
                    else:route.continue_()
                page.route('**/*',scope)
                page.on('pageerror',lambda e:result['javascript_errors'].append(str(e)))
                def shot(name):
                    page.evaluate('window.scrollTo(0,0)');page.screenshot(path=str(out/(name+'.png')),full_page=page.get_by_role('dialog').count()==0);result['screenshots'].append(name+'.png')
                def nav(name):page.get_by_role('navigation',name='Main navigation').get_by_role('button',name=name,exact=True).click()
                def change():
                    d=page.locator('.context-change')
                    if d.count() and d.get_attribute('open') is None:d.locator('summary').first.click()
                if not a.skip_before:
                    page.goto('http://127.0.0.1:18004/');page.locator('.quality-hero').wait_for();shot('before_phaseb_overview_1600')
                    passed('Phase_B_before_screenshot_GET_only')
                page.goto(base);page.locator('.minimal-quality-hero').wait_for()
                expect(page.locator('.context-change')).not_to_have_attribute('open','')
                for width in (1600,1280,768):
                    page.set_viewport_size({'width':width,'height':1000})
                    assert page.evaluate('document.documentElement.scrollWidth <= innerWidth + 1')
                    expect(page.locator('.overview-dimension-details')).not_to_have_attribute('open','')
                    shot('after_overview_'+str(width))
                passed('minimal_Overview_1600_1280_768_no_horizontal_overflow')
                page.set_viewport_size({'width':1600,'height':1000})
                page.get_by_text('Dimensions and evidence completeness',exact=True).click()
                expect(page.locator('.dimension-card')).to_have_count(6)
                page.get_by_role('button',name='Inspect D5',exact=True).click();expect(page.get_by_role('dialog')).to_contain_text('Coverage');page.keyboard.press('Escape')
                page.get_by_text('Dimensions and evidence completeness',exact=True).click()
                page.locator('.concern-title').first.click();expect(page.get_by_role('dialog')).to_contain_text('Source');page.keyboard.press('Escape')
                passed('all_six_dimensions_and_actual_posture_evidence_drilldown')
                change();expect(page.get_by_label('Evidence view')).to_be_visible();page.get_by_label('Evidence view').select_option('ACCEPTED_REPLAY');change()
                page.get_by_label('Evaluation set').select_option('BENIGN_TEST');expect(page.locator('.coverage-reading')).to_contain_text('51.75%')
                page.get_by_role('button',name='Reset to all accepted runs',exact=True).click();expect(page.get_by_label('Evaluation set')).to_have_value('ATTACK_HOLDOUT');expect(page.get_by_label('Run / session')).to_have_value('')
                passed('context_disclosure_saved_selection_replay_reset_view_only')
                nav('Incidents');attack=get('/api/product/assessment?mode=ACCEPTED_REPLAY&replay=ATTACK_HOLDOUT')['snapshot']
                index=next(i for i,e in enumerate(attack['incidents']) if e['contextual_posture_links'])
                episode=attack['incidents'][index];trigger=page.get_by_role('button',name='Inspect episode',exact=True).nth(index);trigger.click()
                key=episode['contextual_posture_links'][0];context=page.get_by_role('dialog').get_by_role('button',name=key,exact=True);context.click()
                expect(page.get_by_role('dialog')).to_have_count(1);expect(page.get_by_role('button',name='Back to previous detail')).to_be_visible()
                page.get_by_role('button',name='Back to previous detail').click();expect(page.get_by_role('dialog')).to_contain_text('Contextual posture');expect(page.get_by_role('dialog').get_by_role('button',name=key,exact=True)).to_be_focused()
                page.keyboard.press('Escape');expect(page.get_by_role('dialog')).to_have_count(0);expect(trigger).to_be_focused()
                passed('contextual_posture_single_drawer_back_focus_Escape')
                trigger.click();page.get_by_role('button',name='Model explanation',exact=True).first.click();expect(page.get_by_role('dialog')).to_have_count(1)
                page.get_by_role('button',name='Back to previous detail').click();expect(page.get_by_role('dialog')).to_contain_text('Why this episode exists');page.keyboard.press('Escape');shot('incidents')
                passed('episode_observation_back_preserved')
                nav('Behavioral monitoring');page.get_by_role('button',name='Explain',exact=True).first.click();expect(page.get_by_role('dialog')).to_contain_text('WHY ')
                page.get_by_role('tab',name='Important factors',exact=True).click();expect(page.get_by_role('dialog')).to_contain_text('Benign TRAIN median')
                page.get_by_text('Technical details',exact=True).click();expect(page.get_by_role('dialog')).to_contain_text('XGBoost attribution');expect(page.get_by_role('dialog')).to_contain_text('Raw feature values');shot('behavioral_explanation');page.keyboard.press('Escape')
                passed('actual_numeric_factors_SHAP_and_features_preserved')
                nav('Cybersecurity quality');page.get_by_role('tab',name='Legacy CQI v1',exact=True).click();expect(page.get_by_text('Legacy CQI · fusion-cqi-1.1',exact=True)).to_be_visible()
                expect(page.get_by_text('Contributors and root-condition grouping',exact=True)).to_be_visible()
                page.get_by_role('tab',name='Sensitivity & policy',exact=True).click();expect(page.get_by_text('Weight sensitivity',exact=True)).to_be_visible();shot('legacy_v1_sensitivity')
                page.get_by_role('tab',name='Assessment & dimensions',exact=True).click();expect(page.locator('.dimension-card')).to_have_count(6)
                page.get_by_role('tab',name='Contributors & coverage',exact=True).click();expect(page.get_by_text('Representative member, not aggregate severity',exact=True).first).to_be_visible();shot('quality_root_members')
                page.get_by_role('tab',name='Mathematical method',exact=True).click();expect(page.get_by_role('link',name='Open full mathematical specification')).to_have_attribute('href','/api/research/cqi-method')
                passed('full_legacy_dimensions_contributors_sensitivity_and_v2_separate')
                nav('Model & research');expect(page.locator('.benchmark-bars')).to_contain_text('65/68');expect(page.locator('.benchmark-bars')).to_contain_text('41/68');expect(page.locator('.benchmark-bars')).to_contain_text('3/68')
                page.get_by_role('tab',name='Classification',exact=True).click();expect(page.locator('.research-measures')).to_contain_text('99/101');expect(page.locator('.confusion-matrix tbody tr')).to_have_count(8);shot('research_classification')
                passed('accepted_benchmark_and_eight_class_matrix_preserved')
                nav('System & evidence');page.get_by_role('button',name='Inspect accepted generic example',exact=True).click();expect(page.get_by_text('ACCEPTED GENERIC FIXTURE · not newly supplied telemetry',exact=True)).to_be_visible();shot('system_generic')
                passed('normalization_capability_limitations_preserved')
                page.get_by_label('Evidence view').select_option('LIVE_LAB');nav('Security posture');page.get_by_role('button',name='Inspect finding',exact=True).first.wait_for()
                page.get_by_role('button',name='Next',exact=True).click();expect(page.locator('.pagination')).to_contain_text('26–')
                page.get_by_label('Finding status',exact=True).select_option('UNMAPPED');expect(page.get_by_text('Not mapped to CQI · finding retained',exact=True).first).to_be_visible()
                page.get_by_label('Finding status',exact=True).select_option('FAIL');shot('posture_current')
                page.get_by_text('New assessment · STANDARD / FULL / Passive',exact=True).click();expect(page.get_by_label('Assessment profile').locator('option')).to_have_count(3);expect(page.get_by_label('Assessment profile')).to_have_value('STANDARD');expect(page.get_by_role('button',name='Run Security Posture')).to_be_disabled()
                page.get_by_label('Assessment profile').select_option('FULL_AUTHORIZED');expect(page.get_by_role('button',name='Run Security Posture')).to_be_disabled()
                passed('posture_filters_pagination_all_three_profiles_preview_disabled')
                page.get_by_role('tab',name='Assessment history',exact=True).click();page.get_by_role('button',name='Inspect attempt',exact=True).first.wait_for();expect(page.get_by_text('Complete assessment attempt history',exact=True)).to_be_visible()
                history=get('/api/product/history?limit=100');assert len(history['items'])==history['total'];result['historical_attempt_states']=sorted(set(j['status'] for j in history['items']))
                page.get_by_role('button',name='Inspect attempt',exact=True).first.click();expect(page.get_by_role('dialog')).to_contain_text('does not select it as completed CQI evidence');page.keyboard.press('Escape')
                passed('complete_actual_history_states_readonly_attempt_inspection')
                aid='posture-20261027T172357Z-b6df0bf04712';page.get_by_label('Posture snapshot').select_option(aid);page.get_by_role('tab',name='Execution details',exact=True).click()
                expect(page.get_by_text('Passive findings: 1182',exact=False)).to_be_visible();shot('historical_full_recovered_counts')
                passed('historical_FULL_1182_verified_metadata_recovered')
                nav('Overview');expect(page.get_by_text('D6 is unavailable for this historical posture. Current incidents are not substituted.',exact=True)).to_be_visible()
                passed('historical_D6_not_borrowed_from_current_telemetry')
                # Browser-only controlled job states: never sent to lab API or executor.
                fixture=deepcopy(get('/api/product/assessment?mode=LIVE_LAB&assessment_id='+aid));fixture['preview_read_only']=False
                fixture['latest_execution']={'assessment_id':'BROWSER-FIXTURE-owned-job','status':'QUEUED','assessment_profile':'STANDARD','mode':'STANDARD','target':fixture['selection']['target'],
                    'provider_statuses':{'native':'COMPLETE','zap':'QUEUED'},'cancellation':{'eligible':False,'reason':'NO_OWNED_RUNNING_ASSESSMENT'},'zap_progress':{}}
                def job_response(r):r.fulfill(status=200,json=fixture)
                page.route('**/api/product/assessment?**',job_response)
                page.route('**/api/health',lambda r:r.fulfill(status=200,json={'mode':'LIVE_LAB','preview_read_only':False,'model_integrity':'VERIFIED'}))
                page.reload();page.locator('.minimal-quality-hero').wait_for();change();page.get_by_label('Posture snapshot').select_option(aid);nav('Security posture')
                expect(page.locator('.execution-banner')).to_contain_text('QUEUED');page.get_by_text('New assessment · STANDARD / FULL / Passive',exact=True).click();page.get_by_role('checkbox').check();expect(page.get_by_role('button',name='Run Security Posture')).to_be_disabled()
                page.get_by_role('button',name='View progress and cancellation',exact=True).click();expect(page.get_by_role('button',name='Request cancellation of owned assessment')).to_be_disabled()
                fixture['latest_execution'].update(status='RUNNING',provider_statuses={'native':'COMPLETE','zap':'RUNNING'},cancellation={'eligible':True,'reason':'OWNED_RUNNING_ASSESSMENT'})
                expect(page.get_by_role('button',name='Request cancellation of owned assessment')).to_be_enabled()
                expect(page.locator('.source-label').filter(has_text='BROWSER-FIXTURE-owned-job')).to_be_visible()
                def fake_cancel(r):
                    result['fixture_mutations'].append({'path':urlsplit(r.request.url).path,'method':r.request.method,'forwarded':False});r.fulfill(status=200,json={'status':'CANCELLATION_REQUESTED'})
                page.route('**/api/posture/assessments/BROWSER-FIXTURE-owned-job/cancel',fake_cancel)
                assert not result['fixture_mutations'];page.get_by_role('button',name='Request cancellation of owned assessment').click();expect(page.get_by_text('Cancellation requested. Awaiting the existing worker’s final state.',exact=True)).to_be_visible();assert len(result['fixture_mutations'])==1
                for state in ('FAILED','INTERRUPTED','COMPLETE'):
                    fixture['latest_execution'].update(status=state,error='BROWSER FIXTURE: '+state,cancellation={'eligible':False})
                    expect(page.get_by_text('BROWSER FIXTURE: '+state,exact=True)).to_be_visible()
                    expect(page.get_by_text(aid+' · PARTIAL',exact=True)).to_be_visible();expect(page.get_by_text('Cancellation requested. Awaiting the existing worker’s final state.',exact=True)).to_have_count(0)
                shot('fake_execution_completed')
                passed('BROWSER_FIXTURE_queued_running_cancel_duplicate_prevention_terminal_states_selected_snapshot_unchanged')
                page.unroute('**/api/product/assessment?**');page.unroute('**/api/posture/assessments/BROWSER-FIXTURE-owned-job/cancel');page.unroute('**/api/health')
                if extra_checks:extra_checks(page,get,nav,shot,passed,result)
                assert not result['blocked_mutations'],result['blocked_mutations'];assert not result['foreign_requests'],result['foreign_requests'];assert not result['javascript_errors'],result['javascript_errors']
                passed('no_forwarded_mutations_foreign_requests_or_JS_errors')
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
        result['files_sha256']={f.name:hashlib.sha256(f.read_bytes()).hexdigest() for f in out.glob('*.png')}
        (out/'browser_receipt.json').write_text(json.dumps(result,indent=2)+'\n')
if __name__=='__main__':main()
