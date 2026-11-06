#!/usr/bin/env python3
"""One-process local defense launcher for replay and authorized lab orchestration."""
from pathlib import Path
import argparse
import sys
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--port',type=int,default=8001)
    parser.add_argument('--frontend-dir',default='demo/frontend/dist',help='Existing built assets inside this repository')
    args=parser.parse_args()
    if not 1024<=args.port<=65535:parser.error('Port must be 1024..65535')
    if args.port != 8001: parser.error('Coursework requires port 8001')
    from coursework.isolation import install
    install()
    from demo.backend.config import confined
    assets=confined(ROOT,args.frontend_dir)
    if not (assets/'index.html').is_file():parser.exit(2,'Selected frontend build is unavailable.\n')
    try:
        import uvicorn
        from demo.backend.app import create_app
        from demo.backend.config import Config
        config=Config.environment();app=create_app(config,frontend_dir=assets)
    except ImportError:parser.exit(2,'Install demo dependencies: .venv/bin/python -m pip install -r demo/backend/requirements.txt\n')
    print(f'Local research dashboard: http://127.0.0.1:{args.port}',flush=True)
    print(f'Initial mode: {config.mode}. Passive LIVE LAB monitoring requires explicit operator controls; no retraining or traffic generation.',flush=True)
    uvicorn.run(app,host='127.0.0.1',port=args.port,log_level='warning')

if __name__=='__main__':main()
