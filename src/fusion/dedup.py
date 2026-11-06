"""Explicit reviewed root-condition rules; no fuzzy text clustering."""
from .schema import stable_id, utc, dumps

RULES = {
    'PLAINTEXT_TRANSPORT': ({'TLS-001', 'TLS-003', 'HDR-001', 'COOKIE-MoodleSession-SECURE'}, 'D1',
        'One lack-of-HTTPS root condition; cross-dimension Secure cookie retained and scored once in D1.'),
    'WEBSERVER_WRITE_PERMISSIONS': ({'FS-001', 'FS-002'}, 'D5', 'Related webserver write-permission observations.'),
}


def clusters(items):
    groups = {}
    for item in items:
        if item.source_branch == 'BRANCH2_BEHAVIOR' and item.score_eligible and item.behavior_class != 'BENIGN':
            continue
        rule, dimension, rationale = 'INDEPENDENT_EVIDENCE', item.dimension, 'Distinct evidence; no reviewed shared-root rule.'
        if item.source_branch == 'BRANCH1_POSTURE':
            for name, (members, dim, why) in RULES.items():
                if item.source_record_id in members: rule, dimension, rationale = name, dim, why
            if item.source_record_id == 'PATCH-001' or item.source_record_id.startswith('ADV-MSA-'):
                rule, dimension, rationale = 'MOODLE_PATCH_LEVEL', 'D4', 'Installed patch level and advisory breadth; maximum, not advisory sum.'
        # Reviewed families are scoped to this one-platform posture snapshot. Missing
        # per-control assets are preserved as missing, not used to split a known root.
        key = (rule, item.source_path, item.evidence_id if rule == 'INDEPENDENT_EVIDENCE' else '')
        group = groups.setdefault(key, {'rule_id': rule, 'dimension': dimension, 'rationale': rationale, 'members': {}})
        group['members'][item.evidence_id] = item
    out = []
    for key, group in sorted(groups.items()):
        members = sorted(group.pop('members').values(), key=lambda x: x.evidence_id)
        eligible = [x for x in members if x.score_eligible]
        rep = sorted(eligible, key=lambda x: (-x.contribution, x.evidence_id))[0] if eligible else None
        out.append({**group, 'cluster_id': stable_id('cluster', key),
            'contribution': rep.contribution if rep else None, 'score_eligible': bool(eligible),
            'representative_evidence_id': rep.evidence_id if rep else None,
            'member_evidence_ids': [x.evidence_id for x in members], 'member_count': len(members),
            'member_finding_ids': sorted(set(x.source_record_id for x in members)),
            'advisory_ids': sorted(set(x.source_record_id for x in members if x.source_record_id.startswith('ADV-MSA-'))),
            'advisory_count': len(set(x.source_record_id for x in members if x.source_record_id.startswith('ADV-MSA-'))),
            'severity_breadth': sorted(set(str(x.severity) for x in members)),
            'recommendations': sorted(set(x.recommendation for x in members if isinstance(x.recommendation, str) and x.recommendation)),
        })
    out.extend(behavior_episodes(items))
    return sorted(out, key=lambda x: x['cluster_id'])


EPISODE_RULE = 'TEMPORALLY_CORRELATED_BEHAVIOR_EPISODE'
IDENTITY_FIELDS = ('client_id', 'user_agent_id', 'session_id', 'run_id', 'source_file',
                   'source_path', 'source_device', 'source_inode', 'model_id', 'schema_sha256')


def window_interval(item):
    """Missing timing cannot justify a merge; supplied malformed timing fails closed."""
    start, end = item.timestamps.get('window_start'), item.timestamps.get('window_end')
    if start is None or end is None:
        return None
    start, end = utc(start), utc(end)
    if (end - start).total_seconds() != 10 or start.microsecond or int(start.timestamp()) % 10:
        raise ValueError('Behavior episode requires aligned fixed 10-second windows')
    return start, end


def behavior_episodes(items):
    streams, singletons = {}, []
    for item in items:
        if item.source_branch != 'BRANCH2_BEHAVIOR':
            continue
        interval = window_interval(item)
        identity = {k: item.provenance.get(k) for k in IDENTITY_FIELDS}
        identity['input_artifact'] = item.source_path
        # Without a retained client/session/source identity we cannot establish
        # that adjacent observations describe the same behavioral stream.
        supported = (identity['client_id'] is not None and identity['session_id'] is not None
                     and (identity['source_file'] is not None or identity['source_path'] is not None))
        if interval is None or not supported:
            if item.score_eligible and item.behavior_class != 'BENIGN':
                singletons.append(([item], interval, identity, 'Missing timing/identity; no inferred merge.'))
            continue
        streams.setdefault(dumps(identity), []).append((interval, item, identity))
    episodes = list(singletons)
    for key in sorted(streams):
        rows = sorted(streams[key], key=lambda row: (row[0], row[1].provenance.get('sequence', 0), row[1].evidence_id))
        current, previous_end, previous_class = [], None, None
        for interval, item, identity in rows:
            qualifies = item.score_eligible and item.behavior_class != 'BENIGN'
            contiguous = (qualifies and current and item.behavior_class == previous_class
                          and interval[0] == previous_end)
            if current and not contiguous:
                episodes.append((current, None, identity, 'Exact window adjacency; matching class and retained stream identity.'))
                current = []
            if qualifies:
                current.append(item)
            # BENIGN and different classes break the stream, never bridge episodes.
            previous_end, previous_class = interval[1], item.behavior_class
        if current:
            episodes.append((current, None, identity, 'Exact window adjacency; matching class and retained stream identity.'))
    out = []
    for members, interval, identity, why in episodes:
        members = sorted(members, key=lambda x: (x.timestamps.get('window_start') or '',
                                                x.provenance.get('sequence', 0), x.evidence_id))
        intervals = [window_interval(x) for x in members]
        rep = sorted(members, key=lambda x: (-x.contribution, x.evidence_id))[0]
        start = min(x[0] for x in intervals).isoformat() if all(intervals) else None
        end = max(x[1] for x in intervals).isoformat() if all(intervals) else None
        ids = [x.evidence_id for x in members]
        out.append({'cluster_id': stable_id('episode', [EPISODE_RULE, identity, rep.behavior_class, sorted(ids)]),
            'rule_id': EPISODE_RULE, 'dimension': 'D6', 'behavior_class': rep.behavior_class,
            'contribution': rep.contribution, 'max_contribution': rep.contribution, 'score_eligible': True,
            'representative_evidence_id': rep.evidence_id, 'member_evidence_ids': ids,
            'member_source_record_ids': [x.source_record_id for x in members],
            'member_sequences': [x.provenance.get('sequence') for x in members],
            'member_finding_ids': sorted(x.source_record_id for x in members), 'member_count': len(members),
            'episode_start': start, 'episode_end': end, 'stream_identity': identity,
            'adjacency_tolerance_seconds': 0, 'window_seconds': 10,
            'rationale': why + ' Episode contribution is maximum member contribution; no window multiplication.',
            'advisory_ids': [], 'advisory_count': 0, 'severity_breadth': sorted(set(str(x.severity) for x in members)),
            'recommendations': []})
    return sorted(out, key=lambda x: x['cluster_id'])
