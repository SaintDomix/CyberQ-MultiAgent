"""TRAIN-only novelty fitting; explicit validation benign order-statistic cutoffs."""
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.svm import OneClassSVM
from sklearn.neighbors import LocalOutlierFactor
from sklearn.preprocessing import RobustScaler
from branch2.models import IF_CONFIG
from branch2.final_pipeline import binary
from .schema import matrix

TARGETS = (.01, .02, .05, .10)


def require(rows, partition, benign=False):
    if not rows or any(r.get('partition') != partition or (benign and r.get('label') != 'BENIGN') for r in rows):
        raise ValueError('Wrong fitting/selection partition or non-benign fit data')


def fit_novelty(name, benign, seed=42):
    require(benign, 'TRAIN', True)
    if len(benign)<10: raise ValueError('Insufficient benign TRAIN windows')
    values=matrix(benign)
    scaler=RobustScaler().fit(values)
    x=scaler.transform(values)
    if name=='IF': model=IsolationForest(**IF_CONFIG,random_state=seed).fit(x)
    elif name=='OCSVM': model=OneClassSVM(nu=.1,kernel='rbf',gamma='scale',cache_size=200).fit(x)
    elif name=='LOF': model=LocalOutlierFactor(n_neighbors=min(20,len(x)-1),novelty=True,n_jobs=1).fit(x)
    else: raise ValueError('Unknown novelty model')
    return {'name':name,'model':model,'scaler':scaler,'seed':seed,
            'fit_run_ids':sorted({r['run_id'] for r in benign}),'fit_labels':['BENIGN']}


def scores(fitted, rows):
    # All three estimators: larger score_samples means more normal. No fitted
    # estimator-specific zero/offset is assumed after validation calibration.
    return fitted['model'].score_samples(fitted['scaler'].transform(matrix(rows)))


def threshold(benign_scores, target):
    """Strict lower-tail rule with empirical FPR <= target, including ties.

    Cutoff is ordered score[floor(target*n)]; score < cutoff is anomalous.
    Targets below 1/n coincide. Finite-sample targets are not population guarantees.
    """
    x=np.sort(np.asarray(benign_scores,dtype=float))
    if not len(x) or not np.isfinite(x).all() or not 0<target<1: raise ValueError('Invalid calibration')
    return float(x[min(int(np.floor(target*len(x))),len(x)-1)])


def calibrate(fitted, validation):
    require(validation,'VALIDATION')
    s=scores(fitted,validation); benign=np.asarray([r['label']=='BENIGN' for r in validation])
    if not benign.any() or benign.all(): raise ValueError('Validation benign and attacks required')
    candidates=[]
    for target in TARGETS:
        cut=threshold(s[benign],target)
        candidates.append({'target_benign_FPR':target,'threshold':cut,
            'validation':binary(~benign,s<cut),'selection_partition':'VALIDATION'})
    # Predeclared operational ceiling 5%; maximize validation attack recall within
    # ceiling, then minimize realized benign FPR, then lower target.
    eligible=[c for c in candidates if c['target_benign_FPR']<=.05 and c['validation']['FPR']<=.05]
    chosen=max(eligible,key=lambda c:(c['validation']['recall'] or 0,-c['validation']['FPR'],-c['target_benign_FPR']))
    return {**chosen,'candidates':candidates,'benign_validation_windows':int(benign.sum()),
            'empirical_resolution':1/int(benign.sum()),'test_used_for_selection':False,
            'rule':'score_samples < cutoff; equality normal',
            'selection':'target <=5%; max VALIDATION attack recall; lower realized benign FPR; lower target'}
