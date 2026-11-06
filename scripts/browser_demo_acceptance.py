#!/usr/bin/env python3
"""Actual loopback UI acceptance; starts replay only and blocks foreign browser requests."""
import json
import os
from pathlib import Path
import sys
from urllib.parse import urlsplit
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from demo.operations import start, stop
from demo.release_pack import write_new


def main():
    target=ROOT/'outputs/demo/browser_acceptance.json'
    if target.exists():raise ValueError('Refuse overwrite of browser receipt')
    port=18002;result=start('ACCEPTED_REPLAY',port)
    errors=[];external=[]
    try:
        from playwright.sync_api import sync_playwright
        env=dict(os.environ);env['LD_LIBRARY_PATH']=str(ROOT/'.tools/chromium-runtime/extracted/usr/lib/x86_64-linux-gnu')
        with sync_playwright() as p:
            executable=ROOT/'.tools/ms-playwright/chromium_headless_shell-1248/chrome-headless-shell-linux64/chrome-headless-shell'
            browser=p.chromium.launch(headless=True,executable_path=str(executable),env=env)
            try:
                page=browser.new_page(viewport={'width':1920,'height':1080})
                def scope(route):
                    if urlsplit(route.request.url).hostname!='127.0.0.1':external.append(route.request.url);route.abort()
                    else:route.continue_()
                page.route('**/*',scope);page.on('pageerror',lambda e:errors.append(str(e)))
                page.goto(f'http://127.0.0.1:{port}/');page.get_by_role('button',name='A · Normal benign',exact=True).wait_for()
                nav=page.get_by_role('navigation',name='Main navigation')
                page.get_by_role('button',name='A · Normal benign',exact=True).click();page.locator('.dimension-card').first.wait_for()
                assert page.locator('.dimension-card').count()==6
                page.screenshot(path='/tmp/release_overview_1920.png',full_page=True)
                page.get_by_role('button',name='B · Known attempt',exact=True).click()
                nav.get_by_role('button',name='Live monitoring',exact=True).click()
                page.get_by_role('button',name='Explain',exact=True).first.click();page.get_by_role('dialog').wait_for();page.get_by_role('button',name='Close detail').click()
                nav.get_by_role('button',name='Incidents',exact=True).click();page.get_by_role('button',name='Inspect episode').first.click();page.get_by_role('dialog').wait_for();page.get_by_role('button',name='Close detail').click()
                nav.get_by_role('button',name='Security posture',exact=True).click();page.get_by_label('Posture status').select_option('DISMISSED');assert page.locator('tbody tr').count()==1
                nav.get_by_role('button',name='Cybersecurity quality',exact=True).click();page.get_by_role('tab',name='Contextual fusion').click();page.get_by_text('NO DIRECT CQI EFFECT',exact=True).wait_for()
                nav.get_by_role('button',name='Model & research',exact=True).click();page.get_by_text('3.03%',exact=True).wait_for();page.get_by_text('93.94%',exact=True).wait_for()
                nav.get_by_role('button',name='System & evidence',exact=True).click()
                with page.expect_popup() as popup:page.get_by_role('link',name='Open final v2 report',exact=True).click()
                popup.value.wait_for_load_state();assert 'Accepted Behavioral v2' in popup.value.locator('body').inner_text();popup.value.close()
                with page.expect_popup() as popup:page.get_by_role('link',name='Open original report',exact=True).click()
                popup.value.wait_for_load_state();assert 'Cybersecurity Quality' in popup.value.locator('body').inner_text();popup.value.close()
                page.get_by_role('button',name='C · Suppressed UNKNOWN observation',exact=True).click();nav.get_by_role('button',name='Live monitoring',exact=True).click();page.get_by_text('SUPPRESSED ISOLATED ANOMALY',exact=True).wait_for()
                page.locator('.control-selectors select').first.select_option('LIVE_LAB')
                page.get_by_text('No accepted-v2 live runtime session selected. Replay data is not substituted.',exact=True).wait_for()
                page.locator('.control-selectors select').first.select_option('ACCEPTED_REPLAY')
                nav.get_by_role('button',name='Overview',exact=True).click();page.locator('.dimension-card').first.wait_for()
                page.set_viewport_size({'width':1280,'height':900})
                assert page.evaluate('document.documentElement.scrollWidth <= innerWidth + 1')
                page.screenshot(path='/tmp/release_overview_1280.png',full_page=True)
                assert not errors,errors;assert not external,external
            finally:browser.close()
        write_new(target,{'status':'PASS','pages':7,'viewports':['1920x1080','1280x900'],
            'actual_loopback_backend':True,'external_requests':len(external),'javascript_errors':errors,
            'final_v2_and_historical_v1_report_links':'PASS','scenario_reset':'PASS','live_monitor_started':False})
        print('Browser acceptance PASS: actual local API, 7 pages, 3 scenarios, two report links, modes, responsive layout; no external requests.')
    finally:stop()


if __name__=='__main__':main()
