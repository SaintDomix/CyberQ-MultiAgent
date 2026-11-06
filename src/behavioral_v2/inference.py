"""Inference-only candidate package, strict integrity/schema checks; no trainers."""
from pathlib import Path
import json
import joblib
import numpy as np
from branch2.reconciliation import reconcile
from .schema import schema, matrix, FEATURES
from .data import sha, write, new_dir


def robust_reference(values):
    med=np.median(values,axis=0);mad=np.median(abs(values-med),axis=0)
    iqr=np.percentile(values,75,axis=0)-np.percentile(values,25,axis=0)
    scale=np.where(mad>0,1.4826*mad,np.where(iqr>0,iqr/1.349,np.maximum(abs(med)*.1,1)))
    return {'feature_order':list(FEATURES),'median':med.tolist(),'MAD':mad.tolist(),'scale':scale.tolist(),
            'fit_partition':'TRAIN BENIGN only'}


class Package:
    def __init__(self,novelty,classifier,classes,reference,config):
        self.novelty=novelty;self.classifier=classifier;self.classes=classes
        self.reference=reference;self.config=config

    def predict(self,rows,*,model=None,threshold=None,explain=False):
        if not rows:return []
        name=model or self.config['selected_model']; fitted=self.novelty[name]
        x=matrix(rows);raw=fitted['model'].score_samples(fitted['scaler'].transform(x))
        cut=self.config['thresholds'][name] if threshold is None else threshold
        vectors=self.classifier.predict_proba(x);indices=vectors.argmax(axis=1)
        explanations=self.shap(x,indices) if explain else [None]*len(rows)
        output=[]
        for i,row in enumerate(rows):
            label=self.classes[int(indices[i])];confidence=float(vectors[i,indices[i]])
            decision=reconcile(bool(raw[i]<cut),label,confidence,self.config['confidence_threshold'])
            deviation=(x[i]-self.reference['median'])/self.reference['scale']
            order=sorted(range(len(FEATURES)),key=lambda j:(-abs(deviation[j]),j))[:8]
            output.append({k:row.get(k) for k in ('run_id','label','partition','window_start','window_end','client_id','user_agent_id','record_id','sequence')})
            output[-1].update(anomaly_model=name,normality_score=float(raw[i]),threshold=float(cut),
                if_anomalous=bool(raw[i]<cut), model_observation='ANOMALOUS' if raw[i]<cut else 'NORMAL',
                xgb_label=label,xgb_confidence=confidence,xgb_scores=vectors[i].tolist(),
                confidence_calibrated=False,reconciliation=decision,shap=explanations[i],
                robust_deviations=[{'feature':FEATURES[j],'value':float(x[i,j]),'signed_deviation':float(deviation[j])} for j in order],
                causal=False,successful_exploitation_confirmed=False)
        return output

    def shap(self,values,indices):
        """Exact native TreeSHAP on raw margins, with full-vector additivity QA."""
        try:
            import xgboost as xgb
            data=xgb.DMatrix(values);booster=self.classifier.get_booster()
            contributions=booster.predict(data,pred_contribs=True,approx_contribs=False,strict_shape=True)
            margins=booster.predict(data,output_margin=True,strict_shape=True)
            if contributions.shape!=(len(values),len(self.classes),len(FEATURES)+1) or not np.isfinite(contributions).all():
                raise ValueError('Shape/finiteness mismatch')
            if not np.allclose(contributions.sum(axis=2),margins,rtol=1e-5,atol=1e-4):
                raise ValueError('Additivity mismatch')
            result=[]
            for i,k in enumerate(indices):
                v=contributions[i,k,:-1];order=sorted(range(len(FEATURES)),key=lambda j:(-abs(v[j]),j))[:8]
                result.append({'status':'AVAILABLE','backend':'XGBOOST_NATIVE_EXACT_TREE_SHAP',
                    'output_space':'raw model margin','causal':False,
                    'additivity_max_absolute_error':float(np.max(abs(contributions.sum(axis=2)-margins))),
                    'top_features':[{'feature':FEATURES[j],'contribution':float(v[j])} for j in order]})
            return result
        except Exception:
            return [{'status':'UNAVAILABLE_OR_INCOMPATIBLE','causal':False,'top_features':[]} for _ in values]

    def save(self,path):
        path=new_dir(path)
        joblib.dump(self.novelty,path/'novelty.joblib')
        self.classifier.save_model(path/'xgboost.json')
        for name,value in {'schema.json':schema(),'classes.json':self.classes,'reference.json':self.reference,'config.json':self.config}.items():
            write(path/name,value)
        write(path/'package_manifest.json',{'version':'behavioral-v2-package-1.0',
            'trusted_local_deserialization_only':True,'files':{p.name:sha(p) for p in sorted(path.iterdir())}})


def load(path):
    path=Path(path);manifest=json.loads((path/'package_manifest.json').read_text())
    if manifest['version']!='behavioral-v2-package-1.0':raise ValueError('Wrong candidate package version')
    required={'novelty.joblib','xgboost.json','schema.json','classes.json','reference.json','config.json'}
    if set(manifest['files'])!=required:raise ValueError('Incomplete package')
    for name,digest in manifest['files'].items():
        if Path(name).name!=name or sha(path/name)!=digest:raise ValueError('Candidate integrity failure')
    read=lambda n:json.loads((path/n).read_text())
    if read('schema.json')!=schema():raise ValueError('Candidate schema identity mismatch')
    from xgboost import XGBClassifier
    classifier=XGBClassifier();classifier.load_model(path/'xgboost.json')
    reference=read('reference.json')
    if reference['feature_order']!=list(FEATURES):raise ValueError('Reference order mismatch')
    return Package(joblib.load(path/'novelty.joblib'),classifier,read('classes.json'),reference,read('config.json'))
