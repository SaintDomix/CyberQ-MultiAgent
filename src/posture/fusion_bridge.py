"""Current correlations require fresh weakness evidence, not coverage metadata."""
from copy import deepcopy
from fusion.schema import stable_id


def current_correlations(artifacts):
    observed = {r['evidence_id'] for r in artifacts['canonical_evidence']
                if r['source_branch'] == 'BRANCH1_POSTURE' and r['check_result'] in ('FAIL', 'PARTIAL')
                and r['score_eligible']}
    out = []
    for correlation in artifacts['correlations']:
        matching = sorted(observed & set(correlation['posture_evidence_ids']))
        if not matching: continue
        c = deepcopy(correlation)
        c['posture_evidence_ids'] = matching
        c['correlation_id'] = stable_id('current-context', [c['rule_id'], c['behavior_cluster_id'], matching])
        c['explanation'] += ' Current context excludes NOT_REEVALUATED, dismissed and passing controls; score remains unchanged.'
        out.append(c)
    return out
