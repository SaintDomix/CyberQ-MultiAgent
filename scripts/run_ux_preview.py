#!/usr/bin/env python3
"""Isolated loopback UX preview. No operational controls, scans or model execution."""
from pathlib import Path
import argparse,os,sys
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'src')]
os.environ['PRODUCT_FACTORY_ONLY']='1'

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--port',type=int,default=18004)
    p.add_argument('--assets',default='demo/frontend/preview-ux-20261104')
    p.add_argument('--retained-session',help='Optional existing journal, opened read-only')
    a=p.parse_args()
    if a.port==8000 or not 1024<=a.port<=65535:p.error('Use an isolated unprivileged port, never 8000')
    from demo.backend.preview import create_preview
    import uvicorn
    app=create_preview(ROOT/a.assets,a.retained_session)
    if not (ROOT/a.assets/'index.html').is_file():p.error('Isolated build missing; do not overwrite demo/frontend/dist')
    print(f'READ-ONLY UX PREVIEW http://127.0.0.1:{a.port} — no monitor or scanner providers',flush=True)
    uvicorn.run(app,host='127.0.0.1',port=a.port,log_level='warning')
if __name__=='__main__':main()
