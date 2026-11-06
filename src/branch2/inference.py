"""Saved-model inference only. No trainer imports or fitting entry points."""
from dataclasses import dataclass
import math
import numpy as np
from .features import matrix
from .explanation import deviations, ShapExplainer
from .reconciliation import reconcile


@dataclass
class ModelPackage:
    isolation_forest: object
    classifier: object | None
    feature_schema: dict
    classes: list
    reference: dict
    reconciliation: dict
    metadata: dict

    def predict(self, rows, *, explain=True):
        values=matrix(rows,self.feature_schema)
        if not rows: return []
        decision=self.isolation_forest.decision_function(values)
        raw=-self.isolation_forest.score_samples(values)
        if self.classifier is not None:
            confidence=self.classifier.predict_proba(values)
            if confidence.shape!=(len(rows),len(self.classes)): raise ValueError('Classifier class mapping mismatch')
            indices=confidence.argmax(axis=1);scores=confidence.max(axis=1)
        else: indices=np.zeros(len(rows),dtype=int);scores=[None]*len(rows)
        shap=ShapExplainer(self.classifier).explain(values,indices) if explain else [{'method':'SHAP','status':'NOT_REQUESTED','top_features':[],'causal':False} for _ in rows]
        results=[]
        for i,row in enumerate(rows):
            label=self.classes[int(indices[i])] if self.classifier is not None else None
            anomaly=bool(decision[i]<0)
            severity=100/(1+math.exp(float(np.clip(decision[i]/self.metadata['if_severity_scale'],-30,30))))
            results.append({k:row[k] for k in ('run_id','window_start','window_end','source_file','source_sha256')})
            # Inference needs observed features/provenance, never ground-truth labels.
            results[-1].update(scenario=row.get('scenario'),label=row.get('label'))
            results[-1].update(if_anomalous=anomaly,if_decision_function=float(decision[i]),if_raw_anomaly_score=float(raw[i]),
                anomaly_severity_index=severity,anomaly_severity_is_probability=False,xgb_label=label,
                xgb_confidence=float(scores[i]) if scores[i] is not None else None,
                xgb_scores=confidence[i].tolist() if self.classifier is not None else None,
                reconciliation=reconcile(anomaly,label,float(scores[i]) if scores[i] is not None else None,self.reconciliation['confidence_threshold']),
                robust_explanation=deviations(values[i],self.reference),shap_explanation=shap[i],
                semantic_confirmation='CONTEXTUAL',semantic_scope='behavioral pattern/model evidence; no confirmed compromise')
        return results
