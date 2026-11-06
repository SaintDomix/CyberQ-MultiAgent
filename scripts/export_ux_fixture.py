#!/usr/bin/env python3
"""Emit an API-shaped test fixture from saved evidence; no files or controls written."""
import json
import os
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'src')]
os.environ['PRODUCT_FACTORY_ONLY']='1'
from demo.backend.config import Config
from demo.backend.preview import preview_application
from demo.backend.product_api import ProductAssessment
from demo.backend.product_quality import product_assessment
from demo.backend.research_api import benchmark

if __name__=='__main__':
    service=preview_application(Config())
    def selected(source):
        p=ProductAssessment(**product_assessment(service,'ACCEPTED_REPLAY',source)).model_dump(mode='json')
        return {**p['snapshot'],**{k:v for k,v in p.items() if k not in ('snapshot','schema_version')}}
    print(json.dumps({'benign':selected('BENIGN_TEST'),'attack':selected('ATTACK_HOLDOUT'),
        'research':service.research(),'benchmark':benchmark()},allow_nan=False))
