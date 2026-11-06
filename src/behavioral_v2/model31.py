"""Schema/adapter-bound saved inference. Contains no fitting entry point."""
from pathlib import Path
import json
import joblib
import numpy as np
from branch2.reconciliation import reconcile
from .features31 import matrix
from .schema import FEATURES
from .inference import Package as AttributionBackend
from .data import write,sha


class Package31:
    def __init__(self,models,classifier,classes,reference,feature_schema,config):
        self.models=models;self.classifier=classifier;self.classes=classes
        self.reference=reference;self.feature_schema=feature_schema;self.config=config

    def predict(self,rows,*,explain=True,model=None,threshold=None):
        if not rows:return []
        x=matrix(rows,self.feature_schema);name=model or self.config['selected_model']
        scores={n:f['model'].score_samples(f['scaler'].transform(x)) for n,f in self.models.items()}
        cuts=self.config['thresholds'];cut=cuts[name] if threshold is None else threshold
        vectors=self.classifier.predict_proba(x);indices=vectors.argmax(axis=1)
        explanations=AttributionBackend.shap(self,x,indices) if explain else [None]*len(rows)
        result=[]
        for i,r in enumerate(rows):
            label=self.classes[int(indices[i])];confidence=float(vectors[i,indices[i]])
            anomalous=bool(scores[name][i]<cut)
            reconciliation=reconcile(anomalous,label,confidence,self.config['confidence_threshold'])
            known=label!='BENIGN' and confidence>=self.config['confidence_threshold']
            observation=('MODEL_DISAGREEMENT' if reconciliation['model_disagreement'] else
                'KNOWN_PATTERN' if known else 'NOVEL_OBSERVATION' if anomalous else 'NORMAL')
            deviation=(x[i]-self.reference['median'])/self.reference['scale']
            order=sorted(range(len(FEATURES)),key=lambda j:(-abs(deviation[j]),j))[:8]
            result.append({k:r.get(k) for k in ('run_id','label','partition','window_start','window_end','client_id','user_agent_id','source_file','source_sha256','line_numbers')})
            result[-1].update(novelty_model=name,novelty_anomalous=anomalous,
                novelty_score=float(scores[name][i]),novelty_threshold=float(cut),
                novelty_models={n:{'normality_score':float(s[i]),'threshold':float(cuts[n]),'anomalous':bool(s[i]<cuts[n])} for n,s in scores.items()},
                model_observation=observation,xgb_label=label,xgb_confidence=confidence,
                xgb_scores=vectors[i].tolist(),confidence_calibrated=False,reconciliation=reconciliation,
                # Compatibility for pre-existing episode helper only. Actual model
                # identity and all three raw model observations remain explicit.
                if_anomalous=anomalous,legacy_if_field_semantics='selected novelty input; consult novelty_model',
                robust_deviations=[{'feature':FEATURES[j],'value':float(x[i,j]),'signed_deviation':float(deviation[j])} for j in order],
                shap_explanation=explanations[i],causal=False,successful_exploitation_confirmed=False,training_performed=False)
        return result

    def save(self,path):
        path=Path(path);path.mkdir(parents=True,exist_ok=False)
        joblib.dump(self.models,path/'novelty.joblib');self.classifier.save_model(path/'xgboost.json')
        for name,value in {'feature_schema.json':self.feature_schema,'class_mapping.json':self.classes,
            'benign_reference.json':self.reference,'config.json':self.config}.items():write(path/name,value)
        write(path/'package_manifest.json',{'version':'behavioral-v3.1-package-1.0',
            'files_sha256':{p.name:sha(p) for p in sorted(path.iterdir())},'trusted_local_models_only':True})


def load(path):
    path=Path(path);m=json.loads((path/'package_manifest.json').read_text())
    if m.get('version')!='behavioral-v3.1-package-1.0':raise ValueError('Unknown package')
    required={'novelty.joblib','xgboost.json','feature_schema.json','class_mapping.json','benign_reference.json','config.json'}
    if set(m.get('files_sha256',{}))!=required:raise ValueError('Incomplete model package')
    for name,digest in m['files_sha256'].items():
        if Path(name).name!=name or sha(path/name)!=digest:raise ValueError('Package integrity mismatch')
    read=lambda n:json.loads((path/n).read_text())
    feature_schema=read('feature_schema.json');matrix([],feature_schema)
    from .platforms import MoodleBehaviorAdapter,GenericHTTPBehaviorAdapter
    identity=feature_schema['adapter']
    if identity['platform_id']=='moodle':adapter=MoodleBehaviorAdapter(identity['mount'])
    elif identity['platform_id']=='generic_http':adapter=GenericHTTPBehaviorAdapter(identity['routes'])
    else:raise ValueError('Unavailable platform adapter')
    if adapter.identity()!=identity:raise ValueError('Adapter implementation/identity mismatch')
    from xgboost import XGBClassifier
    classifier=XGBClassifier();classifier.load_model(path/'xgboost.json')
    reference=read('benign_reference.json');config=read('config.json');classes=read('class_mapping.json')
    from branch2.dataset import CLASSES
    if classes!=sorted(CLASSES) or reference['feature_order']!=list(FEATURES):raise ValueError('Class/reference schema mismatch')
    if config['schema_sha256']!=feature_schema['sha256']:raise ValueError('Config/schema mismatch')
    return Package31(joblib.load(path/'novelty.joblib'),classifier,classes,reference,feature_schema,config)
