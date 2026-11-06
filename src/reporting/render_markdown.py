"""Shared report content plus deterministic Markdown rendering."""


def number(value):
    return 'Not assessed' if value is None else f'{value:.2f}'


def sections(a, comparison):
    horizon=a['behavior_horizon'];cqi=a['cqi'];bc=a['coverage']['branch2'];s=a['sensitivity']
    result=[]
    def add(title,paragraphs,headers=None,rows=None):
        result.append({'title':title,'paragraphs':paragraphs,'headers':headers or [],'rows':rows or []})
    add('A. Executive Summary',[
        f"CQI {number(cqi['cqi'])}/100: quality index, not probability of attack or compromise.",
        f"Assessment evidence time: {horizon['as_of']}; recent behavior lookback: {horizon['behavior_lookback_seconds']} seconds.",
        'Equal baseline dimension weights and ordinal coefficients are not empirically calibrated. Attempts do not establish successful exploitation.',
        'Local Moodle laboratory results do not establish universality across learning platforms.'])
    add('B. Cybersecurity Quality Dimensions',[],['Dimension','Quality','Risk index','Baseline weight','Effective weight','Status','Evidence count'],
        [[d['dimension']+' '+d['name'],number(d['quality']),number(d['risk']),d['baseline_weight_exact'],
          number(cqi['normalized_available_dimension_weights'].get(d['dimension'])),d['score_status'],str(d['evidence_count'])] for d in a['dimensions']])
    add('C. Top Risk Drivers',['Ranked by deduplicated cluster contribution; ties use stable cluster IDs. These are ordinal contributions, not causal percentages.'],
        ['Rank / cluster','Dimension','Contribution','Representative','Members','Rationale','Recommendations'],
        [[str(i+1)+' / '+d['cluster_id'],d['dimension'],number(d['contribution']),d['representative_evidence']['source_record_id'],
          str(d['member_count']),d['rationale'],'; '.join(d['recommendations']) or 'See behavioral recommendations'] for i,d in enumerate(a['top_risk_drivers'])])
    add('D. Security Posture Findings',['Summary of the frozen posture snapshot; parent findings remain unchanged.'],
        ['Grouping','Value','Count'],[[group,value,str(count)] for group,values in a['posture_summary'].items() for value,count in values.items()])
    add('E. Behavioral Analysis',[
        f"Raw selected windows: {bc['recent_selected_predictions']}; BENIGN: {bc['benign']}; UNKNOWN_ANOMALY: {bc['unknown_anomaly']}; UNCERTAIN: {bc['uncertain']}; known attempt windows: {bc['known_attack_attempts']}.",
        f"Non-benign behavioral episodes: {len(a['behavioral_episodes'])}. Multiple contiguous windows in an episode are not multiple attacks. Episode contribution is the maximum member contribution."],
        ['Class','Episode start','Episode end','Windows','Contribution','Source member records','Semantics'],
        [[e['behavior_class'],e['episode_start'] or 'Not supplied',e['episode_end'] or 'Not supplied',str(e['member_count']),number(e['contribution']),
          ', '.join(e['member_source_record_ids']),e['semantic_scope']+'; successful exploitation NOT confirmed'] for e in a['behavioral_episodes']])
    add('F. Cross-Branch Correlation',[
        'Contextual != causal. Associations do not confirm exploitation, upgrade VERSION_BASED findings, or affect CQI.'],
        ['Rule','Behavior records','Posture evidence','Score effect'],
        [[c['rule_id'],', '.join(c['behavior_record_ids']),', '.join(c['posture_evidence_ids']),c['score_effect']] for c in a['correlations']])
    add('G. Explainability',[
        'Branch 2 XGBoost explanations use SHAP where available from upstream frozen M2D artifacts. M3C does not compute or fabricate SHAP results; raw-margin attribution is not causal.',
        'Selected-window upstream SHAP statuses: '+', '.join(f'{k}={v}' for k,v in a['upstream_explainability']['selected_window_shap_status_counts'].items()),
        'CQI is directly explained by the deterministic coefficients, root-condition/episode maxima, dimensions and formula: '+cqi['formula']])
    add('H. Recommendations',['Actions are deduplicated across evidence; no claim of successful exploitation.'],
        ['Action','Linked evidence count'],[[r['action'],str(len(r['evidence_ids']))] for r in a['recommendations']])
    add('I. Sensitivity Analysis',[
        f"Baseline CQI: {number(s['baseline_cqi'])}; range under +/-20% focal dimension-weight perturbations: {number(s['min_cqi'])} to {number(s['max_cqi'])}.",
        f"Absolute range: {number(s['absolute_range'])}; maximum deviation: {number(s['maximum_deviation'])}. Twelve variants; weights were not tuned from these results."])
    if comparison.get('status')=='COMPARED':
        d6=next(d for d in comparison['dimensions'] if d['dimension']=='D6')
        add('J. Baseline vs Controlled SQLI Scenario',[
            'PRE-SQLI BASELINE is not necessarily benign-only: '+str(comparison['baseline_behavior_counts']['benign'])+' BENIGN windows and '+str(comparison['baseline_behavior_counts']['unknown_anomaly'])+' UNKNOWN_ANOMALY windows.',
            f"Baseline as-of: {comparison['baseline_as_of']}; SQLI as-of: {comparison['sqli_as_of']}; lookback {comparison['lookback_seconds']} seconds.",
            f"PRE-SQLI CQI {number(comparison['baseline_cqi'])}; SQLI CQI {number(comparison['sqli_cqi'])}; delta {number(comparison['delta'])}.",
            f"D6 quality {number(d6['baseline_quality'])} to {number(d6['sqli_quality'])}; changed dimensions: {', '.join(comparison['changed_dimensions']) or 'none'}.",
            'D1-D5 unchanged: '+str(not any(d in comparison['changed_dimensions'] for d in ('D1','D2','D3','D4','D5')))+'.',
            f"SQLI episodes: {comparison['sqli_episode_count']}; member window counts: {comparison['sqli_episode_member_counts']}; contextual SQLI correlations: {len(comparison['sqli_contextual_correlations'])}.",
            comparison['interpretation']],['Dimension','Baseline quality','SQLI quality','Delta'],
            [[d['dimension'],number(d['baseline_quality']),number(d['sqli_quality']),number(d['delta'])] for d in comparison['dimensions']])
    else:add('J. Baseline vs Controlled SQLI Scenario',['Comparison not requested. Supply both evidence-time comparison arguments; no scenario result is invented.'])
    add('K. Coverage and Limitations',[
        'Posture coverage: '+', '.join(f'{k}={v}' for k,v in a['coverage']['branch1'].items()),
        'Behavior coverage: '+', '.join(f'{k}={v}' for k,v in bc.items()),
        'Data-quality observations: '+str(len(a['coverage']['data_quality_observations']))+'; actual scoring exclusions: '+str(len(a['coverage']['exclusions']))+'.',
        *a['limitations']])
    add('L. Provenance / Reproducibility',[
        'Assessment schema: '+a['schema_version']+'; Fusion policy: '+a['fusion_policy_version']+'.',
        'Model package identity: '+a['model_package_identity']['model_id'],
        'Feature schema identity: '+a['model_package_identity']['feature_schema_sha256'],
        'Offline command consumes four frozen JSON artifacts; no training, network, Apache log access or wall-clock selection. --as-of selects evidence time; output must be a fresh directory.',
        'See provenance.json, nested Fusion states, acceptance.json and artifact_manifest.json for integrity and reproducibility.'],
        ['Input','Path','SHA256'],[[k,v['path'],v['sha256']] for k,v in a['provenance']['inputs'].items()])
    return result


def md(value):
    # Neutralize embedded source HTML and preserve readable pipe tables.
    import html
    return html.escape(str(value),quote=False).replace('|','\\|').replace('\n',' ')


def render_markdown(assessment,comparison):
    lines=['# Cybersecurity Quality Assessment Report','']
    for section in sections(assessment,comparison):
        lines += ['## '+section['title'],'']
        for paragraph in section['paragraphs']:lines += [md(paragraph),'']
        if section['headers']:
            lines += ['| '+' | '.join(map(md,section['headers']))+' |','| '+' | '.join('---' for _ in section['headers'])+' |']
            lines += ['| '+' | '.join(map(md,row))+' |' for row in section['rows']]
            lines.append('')
    return '\n'.join(lines)+'\n'
