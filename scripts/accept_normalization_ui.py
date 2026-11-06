#!/usr/bin/env python3
"""Isolated real product API/browser proof; never stops the operator's live demo."""
import argparse
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time
from urllib.parse import urlsplit
from urllib.request import build_opener,ProxyHandler

ROOT=Path(__file__).resolve().parents[1]


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--port',type=int,default=18004)
    p.add_argument('--out',default='outputs/normalization/task2c_03/api_ui_acceptance.json');a=p.parse_args()
    if not 1024<=a.port<=65535:raise ValueError('Invalid loopback port')
    out=(ROOT/a.out).resolve()
    if not out.is_relative_to(ROOT/'outputs/normalization') or out.exists():raise ValueError('New bounded receipt path required')
    # Refuse occupied ports, never adopt or kill an existing server.
    with socket.socket() as check:check.bind(('127.0.0.1',a.port))
    control_state=ROOT/'runtime/demo_control/state.json';before=control_state.read_bytes() if control_state.exists() else None
    code="import uvicorn; from demo.backend.app import create_app; from demo.backend.config import Config; uvicorn.run(create_app(Config(mode='ACCEPTED_REPLAY')),host='127.0.0.1',port="+str(a.port)+",log_level='error')"
    env=dict(os.environ);env['PYTHONPATH']=str(ROOT/'src')+':'+str(ROOT)
    server=subprocess.Popen([sys.executable,'-B','-c',code],cwd=ROOT,env=env,
        stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    opener=build_opener(ProxyHandler({}));origin='http://127.0.0.1:'+str(a.port)
    errors=[];denied=[];responses=[]
    try:
        for _ in range(60):
            if server.poll() is not None:raise RuntimeError('Isolated backend startup failed')
            try:
                with opener.open(origin+'/api/health',timeout=1) as f:
                    assert json.load(f)['mode']=='ACCEPTED_REPLAY';break
            except OSError:time.sleep(.2)
        else:raise TimeoutError('Bounded backend startup deadline')
        from playwright.sync_api import sync_playwright,expect
        with sync_playwright() as browser_api:
            browser_env=dict(env);browser_env['LD_LIBRARY_PATH']=str(ROOT/'.tools/chromium-runtime/extracted/usr/lib/x86_64-linux-gnu')
            browser=browser_api.chromium.launch(headless=True,
                executable_path=str(ROOT/'.tools/ms-playwright/chromium_headless_shell-1248/chrome-headless-shell-linux64/chrome-headless-shell'),env=browser_env)
            try:
                page=browser.new_page(viewport={'width':1600,'height':1000})
                def scope(route):
                    u=urlsplit(route.request.url);method=route.request.method
                    if u.scheme=='http' and u.hostname=='127.0.0.1' and u.port==a.port and (method in ('GET','HEAD') or method=='POST' and u.path=='/api/ingestion/inspect'):route.continue_()
                    else:denied.append({'method':method,'path':u.path});route.abort()
                page.route('**/*',scope);page.on('pageerror',lambda e:errors.append(str(e)))
                page.goto(origin+'/',wait_until='domcontentloaded')
                expect(page.locator('.control-selectors select').first).to_have_value('ACCEPTED_REPLAY')
                page.get_by_role('navigation',name='Main navigation').get_by_role('button',name='System & evidence',exact=True).click()
                sample=(ROOT/'tests/fixtures/normalization/events.json').read_text()
                for text,state in [(sample,'BEHAVIORAL_COMPATIBLE_WITH_OPTIONAL_CONTEXT_MISSING'),
                    (json.dumps({'timestamp':'2026-01-01T00:00:01Z','client_ip':'192.0.2.10','method':'GET','path':'/academy/','status':200}),'BEHAVIORAL_INSUFFICIENT_TELEMETRY')]:
                    page.get_by_label('Telemetry sample').fill(text)
                    with page.expect_response(lambda r:urlsplit(r.url).path=='/api/ingestion/inspect') as response:
                        page.get_by_role('button',name='Inspect telemetry',exact=True).click()
                    r=response.value;assert r.status==200
                    payload=r.json();assert payload['capabilities']['behavioral']['state']==state
                    page.get_by_text(state,exact=True).wait_for()
                    assert payload['events_exported'] is False
                    responses.append(payload)
                assert not errors and not denied,(errors,denied)
            finally:browser.close()
        assert (control_state.read_bytes() if control_state.exists() else None)==before,'Operator demo ownership state changed'
        out.parent.mkdir(parents=True,exist_ok=True)
        with out.open('x') as f:json.dump({'result':'PASS','actual_product_app':True,'isolated_loopback_url':origin,
            'mode':'ACCEPTED_REPLAY','samples':responses,'javascript_errors':errors,'denied_requests':denied,
            'operator_demo_ownership_state_unchanged':True,'operator_monitor_touched':False,
            'new_target_traffic':False,'training_performed':False,'screenshots':False},f,indent=2,sort_keys=True);f.write('\n')
        print('PASS: actual API and rendered System diagnostics; rich/insufficient samples; operator demo untouched.')
    finally:
        server.terminate()
        try:server.wait(timeout=10)
        except subprocess.TimeoutExpired:server.kill();server.wait(timeout=3)


if __name__=='__main__':main()
