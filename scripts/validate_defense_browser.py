#!/usr/bin/env python3
"""GET-only actual-backend browser acceptance. No fixtures, proxy or control POST."""
import hashlib,json,os
from pathlib import Path
from urllib.parse import urlsplit
from urllib.request import urlopen
ROOT=Path(__file__).resolve().parents[1]
OUT=Path('/tmp/cyberquality-defense-validation')
BASE='http://127.0.0.1:18010'

def main():
    from playwright.sync_api import sync_playwright,expect
    expect.set_options(timeout=15000)
    OUT.mkdir(exist_ok=True,mode=0o700)
    if (OUT/'browser_receipt.json').exists():raise ValueError('Prior browser receipt exists; do not overwrite it')
    result={'status':'INCOMPLETE','checks':[],'write_requests':[],'foreign_requests':[],'JS_errors':[],'fixtures_used':False,'screenshots':[]}
    def get(path):
        with urlopen(BASE+path,timeout=30) as r:return json.load(r)
    def passed(name):result['checks'].append(name);print('PASS '+name,flush=True)
    try:
        info=get('/api/candidate/status');assert not info['fixtures_used'] and info['application_class']=='Application'
        source=get('/api/product/assessment?mode=LIVE_LAB')
        with sync_playwright() as p:
            browser=p.chromium.launch(headless=True,executable_path=str(ROOT/'.tools/ms-playwright/chromium_headless_shell-1248/chrome-headless-shell-linux64/chrome-headless-shell'),env={**os.environ,'LD_LIBRARY_PATH':str(ROOT/'.tools/chromium-runtime/extracted/usr/lib/x86_64-linux-gnu')})
            try:
                page=browser.new_page(viewport={'width':1600,'height':1000});page.set_default_timeout(20000)
                def boundary(route):
                    r=route.request;u=urlsplit(r.url)
                    if r.method not in ('GET','HEAD','OPTIONS'):result['write_requests'].append(u.path);route.abort()
                    elif u.hostname!='127.0.0.1' or u.port!=18010:result['foreign_requests'].append(u.netloc);route.abort()
                    else:route.continue_()
                page.route('**/*',boundary);page.on('pageerror',lambda e:result['JS_errors'].append(str(e)))
                def nav(name):page.get_by_role('navigation',name='Main navigation').get_by_role('button',name=name,exact=True).click()
                def shot(name):
                    page.screenshot(path=str(OUT/(name+'.png')),full_page=not page.get_by_role('dialog').count());result['screenshots'].append(name+'.png')
                def selection():
                    if page.locator('.context-change').get_attribute('open') is None:page.locator('.context-change>summary').click()
                page.goto(BASE);page.locator('.minimal-quality-hero').wait_for()
                expect(page.locator('.quality-hero .gauge strong')).to_have_text(f"{source['scientific_cqi']['conditional_overall']:.2f}")
                expect(page.locator('.coverage-reading')).to_contain_text(f"{source['scientific_cqi']['coverage']['observability']*100:.2f}%")
                expect(page.get_by_text('Read-only preview · actions disabled',exact=True)).to_be_visible();shot('overview_actual_external_journal')
                passed('Actual_current_assessment_CQI_values_context_and_readonly_capability')
                page.set_viewport_size({'width':768,'height':1000});assert page.evaluate('document.documentElement.scrollWidth<=innerWidth+1');shot('overview_768');page.set_viewport_size({'width':1600,'height':1000})
                nav('Security posture');page.get_by_role('button',name='Inspect finding',exact=True).first.wait_for();expect(page.locator('.pagination')).to_contain_text('of '+str(len(source['snapshot']['posture']))+' findings')
                page.get_by_role('button',name='Inspect finding',exact=True).first.click();expect(page.get_by_role('dialog')).to_contain_text('Technical evidence');page.keyboard.press('Escape')
                page.get_by_text('New assessment · STANDARD / FULL / Passive',exact=True).click();expect(page.get_by_label('Assessment profile').locator('option')).to_have_count(3);expect(page.get_by_role('button',name='Run Security Posture')).to_be_disabled();page.get_by_text('New assessment · STANDARD / FULL / Passive',exact=True).click();shot('posture_actual_native_zap')
                page.get_by_role('tab',name='Assessment history',exact=True).click();page.get_by_role('button',name='Inspect attempt',exact=True).first.click();expect(page.get_by_role('dialog')).to_contain_text('does not select it as completed CQI evidence');page.keyboard.press('Escape')
                passed('Actual_posture_findings_provenance_history_and_three_gated_profiles')
                nav('Behavioral monitoring');page.get_by_role('button',name='Explain',exact=True).first.click();expect(page.get_by_role('dialog')).to_contain_text('WHY ')
                page.get_by_role('tab',name='Important factors',exact=True).click();expect(page.get_by_role('dialog')).to_contain_text('Benign TRAIN median');page.get_by_text('Technical details',exact=True).click();expect(page.get_by_role('dialog')).to_contain_text('Raw feature values');expect(page.get_by_role('dialog')).to_contain_text('XGBoost attribution');shot('actual_live_explanation');page.keyboard.press('Escape')
                passed('Actual_external_journal_numeric_explanation_SHAP_features')
                nav('Incidents');expect(page.get_by_text('Behavioral episodes',exact=True)).to_be_visible()
                if source['snapshot']['incidents']:
                    page.get_by_role('button',name='Inspect episode',exact=True).first.click();expect(page.get_by_role('dialog')).to_contain_text('Why this episode exists');page.keyboard.press('Escape')
                passed('Actual_saved_episode_records_and_window_incident_distinction')
                selection();page.get_by_label('Evidence view').select_option('ACCEPTED_REPLAY');page.get_by_label('Evaluation set').select_option('ATTACK_HOLDOUT')
                nav('Model & research');expect(page.locator('.benchmark-bars')).to_contain_text('65/68');expect(page.locator('.benchmark-bars')).to_contain_text('41/68');expect(page.locator('.benchmark-bars')).to_contain_text('3/68')
                page.get_by_role('tab',name='Classification',exact=True).click();expect(page.locator('.research-measures')).to_contain_text('99/101');expect(page.locator('.confusion-matrix tbody tr')).to_have_count(8);shot('accepted_XGBoost_evaluation')
                passed('Real_hash_bound_three_pipeline_benchmark_and_XGBoost_matrix')
                nav('Cybersecurity quality');expect(page.locator('.dimension-card')).to_have_count(6);page.get_by_role('tab',name='Legacy CQI v1',exact=True).click();expect(page.get_by_text('Legacy CQI · fusion-cqi-1.1',exact=True)).to_be_visible();page.get_by_role('tab',name='Sensitivity & policy',exact=True).click();expect(page.get_by_text('Weight sensitivity',exact=True)).to_be_visible()
                passed('Real_versioned_CQI_v2_v1_sensitivity_and_all_six_dimensions')
                nav('System & evidence');page.get_by_role('button',name='Inspect accepted generic example',exact=True).click();expect(page.get_by_text('ACCEPTED GENERIC FIXTURE · not newly supplied telemetry',exact=True)).to_be_visible();expect(page.get_by_role('link',name='Open final v2 report',exact=True)).to_be_visible();page.get_by_text('Authorized laboratory controls',exact=True).click();expect(page.get_by_role('button',name='Start monitoring',exact=True)).to_be_disabled();expect(page.get_by_role('button',name='Stop monitoring',exact=True)).to_be_disabled()
                passed('Real_normalization_capabilities_reports_and_disabled_monitor_operations')
                assert not result['write_requests'] and not result['foreign_requests'] and not result['JS_errors']
                passed('Seven_destinations_no_fixtures_no_mutations_no_foreign_requests_no_JS_errors')
            finally:browser.close()
        result['status']='PASS'
    except Exception as e:
        result['status']='FAIL';result['failure']=str(e);raise
    finally:
        result['screenshots_sha256']={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in OUT.glob('*.png')}
        (OUT/'browser_receipt.json').write_text(json.dumps(result,indent=2)+'\n')
if __name__=='__main__':main()
