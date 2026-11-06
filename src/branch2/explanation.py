"""Robust deviations and optional SHAP raw-margin attribution, never causality."""
import importlib
import numpy as np
from .features import FEATURES


def benign_reference(values):
    med=np.median(values,axis=0); mad=np.median(np.abs(values-med),axis=0)
    # Zero MAD must not erase novel nonzero features (old implementation did).
    iqr=np.percentile(values,75,axis=0)-np.percentile(values,25,axis=0)
    scale=np.where(mad>0,1.4826*mad,np.where(iqr>0,iqr/1.349,np.maximum(np.abs(med)*.1,1.0)))
    return {'method':'median/MAD; IQR fallback; constant-feature scale=max(abs(median)*0.1,1)',
            'feature_order':list(FEATURES),'median':med.tolist(),'mad':mad.tolist(),'scale':scale.tolist()}


def deviations(row, reference, top=5):
    if reference['feature_order']!=list(FEATURES): raise ValueError('Reference schema mismatch')
    scores=(np.asarray(row)-reference['median'])/reference['scale']
    order=sorted(range(len(FEATURES)),key=lambda i:(-abs(scores[i]),i))[:top]
    return {'method':'robust_benign_feature_deviation','causal':False,'top_features':[
        {'feature':FEATURES[i],'value':float(row[i]),'benign_median':reference['median'][i],
         'signed_deviation':float(scores[i]),'absolute_deviation':float(abs(scores[i]))} for i in order]}


class ShapExplainer:
    def __init__(self, model, module=None):
        self.model=model;self.explainer=None;self.status='UNAVAILABLE'
        if model is None: self.status='CLASSIFIER_UNAVAILABLE';return
        try:
            shap=module or importlib.import_module('shap')
            self.explainer=shap.TreeExplainer(model,model_output='raw')
            self.status='AVAILABLE'
        except ImportError: self.status='DEPENDENCY_UNAVAILABLE'
        except Exception: self.status='INCOMPATIBLE_IMPLEMENTATION'

    def explain(self, values, predicted_indices, top=5):
        if self.explainer is None:
            native=self._native(values,predicted_indices,top)
            if native is not None:return native
            return [{'method':'SHAP','status':self.status,'top_features':[],'causal':False} for _ in values]
        try:
            raw=self.explainer.shap_values(values)
            array=np.asarray(raw)
            # Older SHAP list[class][sample,feature]; newer [sample,feature,class].
            if isinstance(raw,list): array=np.moveaxis(array,0,-1)
            results=[]
            for j,index in enumerate(predicted_indices):
                contribution=array[j,:,index] if array.ndim==3 else array[j]
                if len(contribution)!=len(FEATURES) or not np.isfinite(contribution).all(): raise ValueError('Incompatible SHAP shape')
                order=sorted(range(len(FEATURES)),key=lambda i:(-abs(contribution[i]),i))[:top]
                results.append({'method':'SHAP','status':'AVAILABLE','output_space':'raw model margin','causal':False,
                    'predicted_class_index':int(index),'top_features':[{'feature':FEATURES[i],'contribution':float(contribution[i])} for i in order]})
            return results
        except Exception:
            self.status='INCOMPATIBLE_IMPLEMENTATION'
            native=self._native(values,predicted_indices,top)
            if native is not None:return native
            return [{'method':'SHAP','status':'INCOMPATIBLE_IMPLEMENTATION','top_features':[],'causal':False} for _ in values]


    def _native(self, values, predicted_indices, top):
        """Exact XGBoost TreeSHAP, independent of Python SHAP loader compatibility.

        Native pred_contribs includes the bias and sums to the raw margin. Fail
        explicitly if shape, finiteness or full-vector additivity is invalid.
        """
        if not hasattr(self.model,'get_booster'):return None
        try:
            import xgboost
            booster=self.model.get_booster();data=xgboost.DMatrix(values)
            contributions=booster.predict(data,pred_contribs=True,approx_contribs=False,strict_shape=True)
            margins=booster.predict(data,output_margin=True,strict_shape=True)
            if contributions.ndim!=3 or contributions.shape[2]!=len(FEATURES)+1 or not np.isfinite(contributions).all():
                raise ValueError('Native TreeSHAP incompatible')
            if not np.allclose(contributions.sum(axis=2),margins,rtol=1e-5,atol=1e-4):
                raise ValueError('Native TreeSHAP additivity mismatch')
            results=[]
            for j,index in enumerate(predicted_indices):
                full=contributions[j,int(index)];vector=full[:-1]
                order=sorted(range(len(FEATURES)),key=lambda i:(-abs(vector[i]),i))[:top]
                results.append({'method':'SHAP','status':'AVAILABLE','backend':'XGBOOST_NATIVE_EXACT_TREE_SHAP',
                    'python_treeexplainer_status':self.status,'output_space':'raw model margin','causal':False,
                    'predicted_class_index':int(index),'raw_margin':float(margins[j,int(index)]),
                    'bias':float(full[-1]),'full_contribution_sum':float(full.sum()),
                    'additivity_max_absolute_error':float(np.max(np.abs(contributions.sum(axis=2)-margins))),
                    'top_features':[{'feature':FEATURES[i],'contribution':float(vector[i])} for i in order]})
            return results
        except Exception:
            return None
