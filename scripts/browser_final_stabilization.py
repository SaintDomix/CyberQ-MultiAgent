#!/usr/bin/env python3
"""Reuse C2 acceptance, then verify polished context and fake monitoring/error paths."""
from copy import deepcopy
import sys
from urllib.parse import urlsplit
from browser_ux_c2_acceptance import main


def final_checks(page,get,nav,shot,passed,result):
    from playwright.sync_api import expect
    page.set_viewport_size({'width':1600,'height':1000});page.reload();page.locator('.minimal-quality-hero').wait_for()
    expect(page.get_by_text('Read-only preview · actions disabled',exact=True)).to_be_visible()
    expect(page.locator('.minimal-overview')).to_contain_text('Assessed target uses unencrypted HTTP')
    expect(page.locator('.context-change')).not_to_have_attribute('open','')
    assert not page.get_by_text('Accepted model verified',exact=True).count()
    assert not page.get_by_text('EVIDENCE → CONTEXT → SECURITY QUALITY',exact=True).count()
    source=get('/api/product/assessment?mode=LIVE_LAB')
    expect(page.locator('.quality-hero .gauge strong')).to_have_text(f"{source['scientific_cqi']['conditional_overall']:.2f}")
    expect(page.locator('.coverage-reading')).to_contain_text(f"{source['scientific_cqi']['coverage']['observability']*100:.2f}%")
    passed('polished_context_true_numbers_HTTP_display_and_no_redundant_chrome')
    nav('Security posture');page.get_by_role('button',name='Inspect finding',exact=True).first.wait_for()
    page.get_by_label('Finding dimension',exact=True).select_option('D1');page.get_by_label('Finding status',exact=True).select_option('FAIL')
    expect(page.locator('.finding-summary').filter(has_text='Assessed target uses unencrypted HTTP')).to_have_count(1)
    page.get_by_label('Finding dimension',exact=True).select_option('ALL');page.get_by_label('Finding status',exact=True).select_option('ALL')
    expect(page.locator('.pagination')).to_contain_text('of '+str(len(source['snapshot']['posture']))+' findings')
    for width in (1600,1280,768):
        page.set_viewport_size({'width':width,'height':1000})
        assert page.evaluate('document.documentElement.scrollWidth <= innerWidth + 1')
        expect(page.get_by_text('Read-only preview · actions disabled',exact=True)).to_be_visible()
        shot('polished_posture_'+str(width))
    page.set_viewport_size({'width':1600,'height':1000})
    passed('Posture_desktop_1280_768_preview_marker_and_page_overflow')
    nav('System & evidence');meta=get('/api/report/final')
    expect(page.get_by_role('link',name='Open final v2 report',exact=True)).to_be_visible()
    for key in ('markdown_url','json_url','historical_v1_url'):
        path=meta[key];assert path.startswith('/') and not path.startswith('//')
        response=page.request.get(page.url.split('/',3)[0]+'//'+urlsplit(page.url).netloc+path)
        assert response.status==200,(key,response.status)
    passed('actual_final_v2_MD_JSON_and_historical_v1_report_links')
    # In-browser fake normal-operation service. Actual preview stays read-only.
    fixture=deepcopy(source);fixture['preview_read_only']=False;runtime=fixture['snapshot']['status']['runtime']
    runtime.update(process_running=False,process_state='STOPPED',last_error=None)
    page.route('**/api/health',lambda r:r.fulfill(status=200,json={'mode':'LIVE_LAB','preview_read_only':False,'model_integrity':'VERIFIED'}))
    page.route('**/api/product/assessment?**',lambda r:r.fulfill(status=200,json=fixture))
    calls=[]
    def monitor(route):
        action=urlsplit(route.request.url).path.rsplit('/',1)[-1];calls.append(action)
        runtime.update(process_running=action=='start',process_state='RUNNING' if action=='start' else 'STOPPED')
        result['fixture_mutations'].append({'path':urlsplit(route.request.url).path,'method':route.request.method,'forwarded':False,'fixture':'MONITOR_ONLY'})
        route.fulfill(status=200,json={'process_running':runtime['process_running'],'process_state':runtime['process_state'],'exit_code':None,'session':None,'last_error':None})
    page.route('**/api/runtime/start',monitor);page.route('**/api/runtime/stop',monitor)
    page.reload();page.locator('.minimal-quality-hero').wait_for();nav('System & evidence');page.get_by_text('Authorized laboratory controls',exact=True).click()
    start=page.get_by_role('button',name='Start monitoring',exact=True);stop=page.get_by_role('button',name='Stop monitoring',exact=True)
    expect(start).to_be_enabled();expect(stop).to_be_disabled();assert not calls
    start.click();expect(start).to_be_disabled();expect(stop).to_be_enabled();stop.click();expect(start).to_be_enabled();expect(stop).to_be_disabled();assert calls==['start','stop']
    passed('BROWSER_FIXTURE_explicit_monitor_start_stop_duplicate_gating_no_mode_coupling')
    for pattern in ('**/api/health','**/api/product/assessment?**','**/api/runtime/start','**/api/runtime/stop'):page.unroute(pattern)
    page.route('**/api/product/assessment?**',lambda r:r.fulfill(status=503,json={'error':'SOURCE_UNAVAILABLE','message':'BROWSER FIXTURE: evidence unavailable'}))
    page.reload();expect(page.get_by_role('alert')).to_contain_text('BROWSER FIXTURE: evidence unavailable');assert not page.locator('.gauge').count()
    passed('503_unavailable_does_not_substitute_score_or_legacy')
    page.unroute('**/api/product/assessment?**');page.route('**/api/product/assessment?**',lambda r:r.fulfill(status=200,json={'schema_version':'unexpected-contract'}))
    page.reload();expect(page.get_by_role('alert')).to_contain_text('Invalid product evidence contract');assert not page.locator('.gauge').count()
    passed('unexpected_200_contract_rejected_without_invented_numbers')
    page.unroute('**/api/product/assessment?**');page.route('**/api/product/assessment?**',lambda r:r.fulfill(status=404,json={'error':'BROWSER_FIXTURE_PROJECTION_ABSENT'}))
    page.reload();expect(page.get_by_text('LEGACY POLICY VIEW',exact=False)).to_be_visible();nav('System & evidence');page.get_by_text('Authorized laboratory controls',exact=True).click()
    expect(page.get_by_role('button',name='Start monitoring',exact=True)).to_be_disabled();expect(page.get_by_role('button',name='Stop monitoring',exact=True)).to_be_disabled()
    expect(page.get_by_text('Read-only preview · actions disabled',exact=True)).to_be_visible()
    passed('404_legacy_fallback_preserves_readonly_preview_controls')
    page.unroute('**/api/product/assessment?**')

if __name__=='__main__':
    if len(sys.argv)==1:
        sys.argv+=['--port','18008','--assets','demo/frontend/preview-final-stabilization-20261104','--output','outputs/ux/final_stabilization_20261104_02','--skip-before']
    main(extra_checks=final_checks)
