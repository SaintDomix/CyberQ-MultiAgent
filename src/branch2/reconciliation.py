"""Parallel decisions; classifier confidence is an uncalibrated model score."""
import math

DEFAULT={'confidence_threshold':.8,'version':'reconciliation-1.0'}


def reconcile(anomalous, label, confidence, threshold=.8):
    if not 0<=threshold<=1 or not math.isfinite(threshold): raise ValueError('Invalid confidence threshold')
    if label is not None and (confidence is None or not math.isfinite(confidence) or not 0<=confidence<=1): raise ValueError('Invalid classifier confidence')
    confident=label is not None and confidence>=threshold
    attack=confident and label!='BENIGN'
    disagreement=bool(label is not None and confident and anomalous==(label=='BENIGN'))
    if attack: decision=label;reason='KNOWN_ATTACK_WITH_ANOMALY_SUPPORT' if anomalous else 'KNOWN_ATTACK_MODEL_DISAGREEMENT'
    elif anomalous: decision='UNKNOWN_ANOMALY';reason='ANOMALY_WITHOUT_CONFIDENT_KNOWN_ATTACK'
    elif confident and label=='BENIGN': decision='BENIGN';reason='BOTH_BENIGN_NORMAL'
    else: decision='UNCERTAIN';reason='NORMAL_IF_WITH_UNCERTAIN_OR_UNAVAILABLE_CLASSIFIER'
    return {'decision':decision,'reason':reason,'model_disagreement':disagreement,'if_anomalous':bool(anomalous),
        'xgb_label':label,'xgb_confidence':confidence,'confidence_threshold':threshold,'confidence_calibrated':False}
