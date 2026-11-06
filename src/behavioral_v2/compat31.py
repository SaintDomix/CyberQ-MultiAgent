"""Explicit compatibility at the Fusion boundary; frozen CQI math is untouched."""
import copy
from fusion.pipeline import assemble


def observations(predictions,model_id,schema_sha256):
    output=[]
    for p in predictions:
        for key in ('record_id','sequence','emitted_at_utc','source_byte_ranges','session_id'):
            if not p.get(key):raise ValueError('Real live emission/provenance required; do not invent timestamps')
        if p.get('model_id')!=model_id or p.get('schema_sha256')!=schema_sha256 or p.get('training_performed') is not False:
            raise ValueError('Candidate provenance mismatch')
        q=copy.deepcopy(p)
        q['if_anomalous']=p['novelty_anomalous']
        q['semantic_scope']='Selected '+p['novelty_model']+' observation; legacy if_anomalous is compatibility input, not an IF-specific assertion. Attempt semantics; no exploit confirmation.'
        q['robust_explanation']={'causal':False,'top_features':p['robust_deviations']}
        q['feature_schema_version']='dataset-v3.1-features-2.1'
        output.append(q)
    return output


def fuse(posture,predictions,model_id,schema_sha256,*,as_of=None,lookback=300):
    rows=observations(predictions,model_id,schema_sha256)
    return {'compatibility_version':'behavioral-v3.1-to-fusion-1.0',
        'raw_model_observations':copy.deepcopy(predictions),
        'fusion':assemble(posture,rows,'current-posture','candidate-live-observations',as_of,lookback),
        'limitations':['Existing Fusion scores raw reconciliation evidence and groups temporal episodes. Candidate alert-persistence is separate presentation policy, not a hidden CQI adjustment.',
            'No current live integration/promotion is asserted by this compatibility function.']}
