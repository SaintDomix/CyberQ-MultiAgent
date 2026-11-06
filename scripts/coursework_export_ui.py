#!/usr/bin/env python3
"""Export saved-evidence UI fixtures only into coursework state."""
import json
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'src')]
from coursework.isolation import install,STATE
install()
from demo.backend.config import Config
from demo.backend.services import Application

def main():
    app=Application(Config());result={}
    for name,options in [('attack',{}),('benign',{'replay':'BENIGN_TEST'}),('empty',{'mode':'LIVE_LAB'})]:
        value=app.snapshot(**options)
        result[name]={k:([r.model_dump(by_alias=True) for r in v] if isinstance(v,list) else
            v.model_dump(by_alias=True) if hasattr(v,'model_dump') else v)
            for k,v in value.items() if k!='artifacts'}
    result['research']=app.research()
    path=STATE/'product-payload.json'
    path.write_text(json.dumps(result)+'\n')
    print(str(path))

if __name__=='__main__':main()
