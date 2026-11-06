#!/usr/bin/env python3
"""Run local Node/React checks and retain their actual output; no browser/network."""
import json
import os
from pathlib import Path
import re
import subprocess
import uuid

ROOT=Path('/mnt/assignment/cyberquality_multiagent')


def main():
    assert Path.cwd().resolve()==ROOT
    state=ROOT/'runtime/coursework/assignment4'
    assert (state/'ui-task.json').is_file(), 'Generate a real completed task fixture first'
    assert (ROOT/'runtime/coursework/product-payload.json').is_file(), 'Run coursework_export_ui.py first'
    env=dict(os.environ,PRODUCT_TEST_PAYLOAD=str(ROOT/'runtime/coursework/product-payload.json'),
             MULTIAGENT_TEST_PAYLOAD=str(state/'ui-task.json'),TMPDIR=str(ROOT/'runtime/coursework/tmp'))
    node=ROOT/'.venv-coursework/lib/python3.10/site-packages/playwright/driver/node'
    result=subprocess.run([str(node),'--test','--test-reporter=tap','--experimental-test-isolation=none',
        'src/utils/data.test.js','src/utils/product.test.js','scripts/product_render.test.mjs',
        'scripts/monitoring_controls.test.mjs','scripts/multiagent_render.test.mjs'],
        cwd=ROOT/'demo/frontend',env=env,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=60,text=True)
    log=state/('frontend-'+uuid.uuid4().hex+'.log');log.write_text(result.stdout)
    counts={name:int(re.search(r'^# '+name+r' (\d+)$',result.stdout,re.M).group(1))
            for name in ('tests','pass','fail')}
    receipt={'exit_code':result.returncode,**counts,'log':str(log.relative_to(ROOT)),
             'browser_executed':False,'scope':'Node units and React server rendering on genuine saved-evidence/task payloads'}
    (state/'frontend-receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')
    print(json.dumps(receipt,indent=2));return result.returncode


if __name__=='__main__':raise SystemExit(main())
