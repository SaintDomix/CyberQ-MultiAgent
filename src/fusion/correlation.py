"""Context-only semantic association; scoring never consumes these objects."""
import re
from .schema import stable_id
from .dedup import clusters


def matches(decision, item):
    text = (item.finding_type + ' ' + str(item.source_details.get('explanation') or '')).lower()
    category = item.category
    if decision == 'SQLI_ATTEMPT':
        return item.source_record_id == 'ADV-MSA-26-0031' or bool(re.search(r'\bsql injection\b|\bsqli\b', text))
    if decision == 'XSS_ATTEMPT': return bool(re.search(r'\bxss\b|cross.site scripting', text))
    if decision == 'REQUEST_BURST_DOS_LIKE': return bool(re.search(r'\bdos\b|denial.of.service', text))
    if decision == 'BRUTE_FORCE': return category in ('Authentication & Session', 'Authentication & Access') or 'authentication' in text
    if decision == 'ENUMERATION_RECONNAISSANCE': return category in ('Exposure', 'Information Disclosure', 'Privacy & Exposure')
    if decision == 'ADMIN_PROBING': return category in ('Access Control', 'Exposure', 'Authentication & Access')
    if decision == 'PATH_TRAVERSAL_ATTEMPT':
        return category in ('Exposure', 'Information Disclosure', 'Privacy & Exposure') and bool(re.search(r'path traversal|file disclosure|exposed .*file|exposed git metadata|exposed environment', text))
    return False


def correlate(posture, behavior, behavioral_clusters=None):
    out = []
    by_id = {item.evidence_id: item for item in behavior}
    for cluster in (clusters(behavior) if behavioral_clusters is None else behavioral_clusters):
        members = [by_id[eid] for eid in cluster['member_evidence_ids'] if eid in by_id]
        if not members: continue
        decision = members[0].behavior_class
        matched = sorted(x.evidence_id for x in posture if matches(decision, x))
        if not matched: continue
        rule = 'CONTEXT_' + decision
        out.append({'correlation_id': stable_id('correlation', [rule, cluster['cluster_id'], matched]),
            'behavior_record_ids': sorted(x.source_record_id for x in members),
            'behavior_cluster_id': cluster['cluster_id'], 'behavior_evidence_ids': sorted(x.evidence_id for x in members), 'posture_evidence_ids': matched, 'rule_id': rule,
            'relationship': 'SEMANTIC_CONTEXT_ASSOCIATION', 'confidence_semantics': 'CONTEXTUAL',
            'causal': False, 'exploit_confirmed': False, 'score_effect': 'NONE',
            'explanation': 'Related observable posture and behavioral pattern; association does not upgrade confirmation or prove exploitation.'})
    return sorted(out, key=lambda x: x['correlation_id'])
