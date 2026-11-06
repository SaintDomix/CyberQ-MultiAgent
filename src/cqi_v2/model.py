"""Coverage-aware, traceable CQI. No collection, inference, fitting or state mutation."""
from collections import defaultdict
from datetime import timedelta
from pathlib import Path
import json
import math
from branch2.live_storage import digest
from fusion.schema import DIMENSIONS,CATEGORIES,utc
from fusion.dedup import RULES
from posture.model import COOKIE_IDS
from .policy import Policy,aggregate
from .identity import current_exposure_aliases

UNKNOWN={'NOT_AVAILABLE','NOT_ASSESSED','NOT_TESTED','NOT_REEVALUATED','ERROR','FAILED','NOT_RUN'}


def registry():
    value=json.loads(Path(__file__).with_name('control_registry.json').read_text())
    if digest({k:v for k,v in value.items() if k!='sha256'})!=value['sha256']:raise ValueError('Control registry hash mismatch')
    return value


def leaves(row):
    # Explicit canonical membership is provenance, never fuzzy title matching.
    members=row.get('evidence',{}).get('members') if isinstance(row.get('evidence'),dict) else None
    if row.get('canonical_finding_id') and isinstance(members,list) and members:
        return [leaf for m in members for leaf in leaves(m)]
    return [row]


def root_for(fid):
    fid=COOKIE_IDS.get(fid,fid)
    for name,(members,dimension,why) in RULES.items():
        if fid in members:return name,dimension
    if fid=='PATCH-001' or fid.startswith('ADV-MSA-'):return 'MOODLE_PATCH_LEVEL','D4'
    return fid,None


def finding_value(row,policy,as_of,posture_time):
    """Support coefficient is evidence reliability, never attack probability."""
    result=row.get('current_state') or row.get('operational_status') or row.get('check_result','NOT_ASSESSED')
    confirmation=row.get('confirmation_status','NOT_TESTED')
    severity=row.get('severity')
    value={'source_id':row.get('evidence_id'),'finding_id':row.get('finding_id'),
        'sources':sorted(set(row.get('evidence_sources') or [row.get('evidence_source','UNKNOWN')])),
        'provenance':row.get('provenance',{}),'status':result,'confirmation':confirmation,
        'severity':severity,'observability':0.,'reliability':0.,'hazard':0.,'reason':None}
    validation=row.get('active_validation') or {}
    if validation:
        value['active_validation']={k:validation.get(k) for k in ('status','validator_id','assessment_id','timestamp','support_level','executed')}
        value['active_validation']['scoring_semantics']='Corroboration retained; no source-count multiplier or automatic confirmation promotion.'
    at=row.get('end_utc') or row.get('created_at') or posture_time
    if at is None:
        value['reason']='ASSESSMENT_TIMESTAMP_UNAVAILABLE';return value
    try:age=(as_of-utc(at)).total_seconds()
    except (ValueError,TypeError):value['reason']='ASSESSMENT_TIMESTAMP_INVALID';return value
    if age<0 or age>policy.posture_max_age_seconds:
        value['reason']='STALE_OR_FUTURE_POSTURE; historical evidence retained';return value
    if result=='NOT_APPLICABLE' or confirmation=='NOT_APPLICABLE':
        value.update(reason='EXPLICIT_NOT_APPLICABLE',applicable=False);return value
    value['applicable']=True
    if result in UNKNOWN or confirmation=='NOT_TESTED':value['reason']='UNOBSERVED_CONTROL';return value
    r=policy.reliability.get(confirmation)
    verified_resolution=row.get('lifecycle',{})
    if verified_resolution.get('state') in ('REMEDIATED','RESOLVED','OBSOLETE'):
        try:
            valid=(verified_resolution.get('verified') is True and bool(verified_resolution.get('evidence_reference'))
                and utc(at)<=utc(verified_resolution['verified_at'])<=as_of)
        except (ValueError,KeyError,TypeError):valid=False
        if valid and confirmation=='CONFIRMED':
            value.update(observability=1.,reliability=1.,reason='VERIFIED_REMEDIATION_OR_OBSOLESCENCE');return value
        value['reason']='UNVERIFIED_LIFECYCLE; underlying weakness retained'
    if result=='PASS':
        if r is None:value['reason']='PASS_WITHOUT_SUPPORTED_EVIDENCE';return value
        value.update(observability=1.,reliability=r,reason='OBSERVED_PASS');return value
    if result=='DISMISSED' or confirmation=='FALSE_POSITIVE':
        if confirmation!='FALSE_POSITIVE':value['reason']='UNVERIFIED_DISMISSAL';return value
        value.update(observability=1.,reliability=1.,reason='EXPLICIT_FALSE_POSITIVE_DISPOSITION');return value
    if result not in ('FAIL','PARTIAL') or r is None or severity not in policy.severity:
        value['reason']='UNMAPPED_SEVERITY_STATUS_OR_RELIABILITY';return value
    k=policy.partial_observability if result=='PARTIAL' else 1.
    multiplier=policy.partial_weakness if result=='PARTIAL' else 1.
    value.update(observability=k,reliability=r,hazard=policy.severity[severity]*r*multiplier,
                 severity_coefficient=policy.severity[severity],result_coefficient=multiplier,
                 reason=value['reason'] or 'SUPPORTED_CURRENT_WEAKNESS')
    return value


def behavior_value(observations,incidents,as_of,policy,closures=()):
    cutoff=as_of-timedelta(seconds=policy.behavior_horizon_seconds)
    by_id={}
    for row in observations:
        rid=row.get('record_id',row.get('observation_id'))
        if not rid:raise ValueError('Missing behavioral observation identity')
        if rid in by_id and digest(by_id[rid])!=digest(row):raise ValueError('Conflicting behavioral duplicate')
        by_id[rid]=row
    current={}
    for rid,row in sorted(by_id.items()):
        try:at=utc(row.get('emitted_at_utc') or row.get('window_end'))
        except (ValueError,TypeError):continue
        if cutoff<=at<=as_of:
            decision=row.get('reconciliation',{}).get('decision',row.get('reconciled_label'))
            if decision in {'BENIGN','UNCERTAIN'}|set(policy.behavior):current[rid]=row
    lifecycle={}
    for closure in closures:
        eid=closure.get('episode_id')
        if not eid or eid in lifecycle:raise ValueError('Missing/conflicting incident lifecycle identity')
        lifecycle[eid]=closure
    seen={};active=[];history=[]
    for raw in incidents:
        if hasattr(raw,'model_dump'):raw=raw.model_dump(mode='json',by_alias=True)
        eid=raw.get('episode_id')
        if not eid:raise ValueError('Stable accepted episode ID required')
        if eid in seen and digest(seen[eid])!=digest(raw):raise ValueError('Conflicting incident duplicate')
        seen[eid]=raw
    for eid,raw in sorted(seen.items()):
        label=raw.get('behavior_class',raw.get('class'))
        ids=raw.get('observation_ids',raw.get('member_record_ids',[]))
        try:last=utc(raw.get('last_seen') or raw.get('end'))
        except (ValueError,TypeError):raise ValueError('Episode timing required') from None
        if label not in policy.behavior:raise ValueError('Unsupported incident class')
        # No re-grouping: only accepted episodes, cross-checked against retained observations.
        related=[current[i] for i in ids if i in current]
        if not related or not cutoff<=last<=as_of:
            history.append({'episode_id':eid,'state':'OUTSIDE_ACTIVITY_HORIZON; NOT_VERIFIED_RESOLVED'});continue
        if any((r.get('reconciliation',{}).get('decision',r.get('reconciled_label')))!=label for r in related):
            raise ValueError('Incident/reconciliation identity mismatch')
        closure=lifecycle.get(eid,{})
        try:
            resolved=closure.get('state') in ('CLOSED','RESOLVED') and closure.get('verified') is True and bool(closure.get('evidence_reference')) and last<=utc(closure['verified_at'])<=as_of
        except (ValueError,KeyError,TypeError):resolved=False
        if resolved:
            history.append({'episode_id':eid,'state':'VERIFIED_CLOSED','evidence_reference':closure['evidence_reference']});continue
        anomalous=any(r.get('novelty_anomalous',r.get('novelty_state')=='ANOMALOUS') for r in related)
        support=1. if anomalous or label=='UNKNOWN_ANOMALY' else policy.disagreement_support
        active.append({'root_id':'episode:'+eid,'episode_id':eid,'dimension':'D6','behavior_class':label,
            'hazard':policy.behavior[label]*support,'severity_coefficient':policy.behavior[label],
            'reliability':support,'observation_ids':sorted(set(ids)),'reason':'ACCEPTED_EPISODE; not successful exploitation'})
    return {'available':bool(current),'observations':len(current),'active_incidents':active,'historical_incidents':history,
        'isolated_or_unqualified_observations':len(set(current)-{i for e in active for i in e['observation_ids']}),
        'activity_horizon_seconds':policy.behavior_horizon_seconds,'as_of':as_of.isoformat(),
        'recovery_semantics':'Verified closure removes that episode, or activity-horizon expiry with fresh telemetry permits temporal activity recovery. Expiry is NOT remediation. Missing telemetry never establishes recovery.',
        'missing_reason':None if current else 'NO_RECENT_VERIFIED_BEHAVIORAL_OBSERVATIONS'}


def evaluate(posture_rows,*,as_of,observations=(),incidents=(),platform='moodle',
             posture_time=None,controls=None,policy=None,closures=(),dimension_applicability=None,known_controls=()):
    p=policy or Policy();at=utc(as_of)
    posture_rows=list(posture_rows)
    if platform not in ('moodle','generic_web'):raise ValueError('Explicit platform identity required')
    reg=registry() if controls is None else {'version':'explicit-test-registry','controls':controls,'sha256':digest(controls)}
    expected={};groups=defaultdict(list);warnings=[];row_ids={};assessment_ids=set()
    for spec in reg['controls']:
        fid=spec['control_id']
        if fid in expected and expected[fid]!=spec:raise ValueError('Duplicate control specification')
        if spec['dimension'] not in DIMENSIONS:raise ValueError('Invalid registry dimension')
        if platform=='generic_web' and spec.get('platform_scope')=='PLATFORM_MOODLE':continue
        expected[fid]=spec
    # Identity correction only: fixed policy, coefficients and raw evidence stay
    # unchanged. A current verified equivalent covers its old placeholder ID.
    flat_rows=[row for parent in posture_rows for row in leaves(parent)]
    aliases,identity_corrections=current_exposure_aliases(flat_rows,expected)
    # Retain previously declared *identities*, never prior PASS/FAIL or severity.
    # New mapped controls need a stable comparison scope across assessments.
    for spec in known_controls:
        if set(spec)!={'control_id','root_id','dimension','platform_scope'} or spec['dimension'] not in DIMENSIONS:
            raise ValueError('Invalid comparison-scope control')
        fid=aliases.get(spec['control_id'],spec['control_id'])
        if fid not in expected:expected[fid]=dict(spec)
    for original in posture_rows:
        for row in leaves(original):
            if original.get('active_validation') and row.get('finding_id')==original.get('finding_id'):
                row=dict(row,active_validation=original['active_validation'])
            if row.get('assessment_id'):assessment_ids.add(row['assessment_id'])
            original_id=COOKIE_IDS.get(row.get('finding_id'),row.get('finding_id'))
            fid=aliases.get(original_id,original_id);eid=row.get('evidence_id')
            if not fid or not eid:raise ValueError('Canonical finding identity required')
            if eid in row_ids:
                if digest(row_ids[eid])!=digest(row):raise ValueError('Conflicting finding identity')
                continue
            row_ids[eid]=row
            if fid in expected:
                spec=expected[fid];root,dim=spec['root_id'],spec['dimension']
            else:
                if platform=='generic_web' and any(s['control_id']==fid and s.get('platform_scope')=='PLATFORM_MOODLE' for s in reg['controls']):continue
                root,dim_override=root_for(fid);dim=dim_override or CATEGORIES.get(row.get('category'))
                if not dim:
                    warnings.append({'finding_id':fid,'reason':'UNMAPPED_FINDING; no invented penalty'});continue
                # Additional mapped findings add independent hazard, never denominator credit.
                root=row.get('weakness_key') or row.get('canonical_finding_id') or root
            value=finding_value(row,p,at,posture_time)
            if fid!=original_id:value['canonical_control_id']=fid
            groups[(dim,root)].append((fid,value))
    if len(assessment_ids)>1:raise ValueError('Posture inputs must describe one current assessment')
    roots=defaultdict(list)
    for fid,spec in expected.items():roots[(spec['dimension'],spec['root_id'])].append(fid)
    applicable={};records=[]
    for key in sorted(set(roots)|set(groups)):
        dim,rid=key;members=groups[key];required=roots.get(key,[]);extra=not required
        by_control={fid:[v for f,v in members if f==fid] for fid in required}
        observed=[];effective=[];applicable_ids=[];upper_hazards=[]
        for fid,values in by_control.items():
            if values and all(v.get('applicable') is False for v in values):continue
            applicable_ids.append(fid)
            k_i=max((v['observability'] for v in values),default=0.)
            observed.append(k_i)
            effective.append(max((v['observability']*v['reliability'] for v in values),default=0.))
            h_i=max((v['hazard'] for v in values),default=0.)
            upper_hazards.append(h_i+(1-k_i)*p.missing_control_hazard)
        if required and not applicable_ids:continue
        if extra and members and all(v.get('applicable') is False for f,v in members):continue
        k=min(observed) if observed else (1. if extra else 0.)
        e=min(effective) if effective else (1. if extra else 0.)
        h=max((v['hazard'] for f,v in members),default=0.)
        # Missingness budget bounds any removed known contribution (h<=1).
        gap=max(0.,max(upper_hazards,default=h)-h) if not extra else (1-max((v['observability'] for f,v in members),default=0.))*p.missing_control_hazard
        record={'root_id':rid,'dimension':dim,'hazard':h,'coverage':k,'effective_coverage':e,
            'missing_hazard_allowance':gap,'registry_control_ids':sorted(applicable_ids),
            'supplementary_mapped_weakness':extra,'sources':sorted({s for f,v in members for s in v['sources']}),
            'evidence_ids':sorted(v['source_id'] for f,v in members),'members':[v for f,v in sorted(members,key=lambda x:(x[0],str(x[1]['source_id'])))],
            'deduplication':'EXPLICIT_CONTROL_AND_REVIEWED_ROOT_MAX; no source summation'}
        records.append(record)
        if not extra:applicable[key]=record
    b=behavior_value(observations,incidents,at,p,closures)
    records+=b['active_incidents']
    applicability=dimension_applicability or {}
    if set(applicability)-set(DIMENSIONS):raise ValueError('Invalid dimension applicability')
    dims=[];lower={};upper={};coverage_values=[]
    for d,name in DIMENSIONS.items():
        relevant=[r for r in records if r['dimension']==d];units=[r for (dim,_),r in applicable.items() if dim==d]
        explicit_na=applicability.get(d)
        if explicit_na and (explicit_na.get('state')!='NOT_APPLICABLE' or not explicit_na.get('evidence_reference')):raise ValueError('Applicability proof required')
        if explicit_na and any(r['hazard']>0 for r in relevant):raise ValueError('Cannot exclude a known failed dimension')
        is_na=bool(explicit_na) or (d!='D6' and not units and not relevant)
        if d=='D6':
            n=1;obs=eff=1. if b['available'] else 0.;missing=0. if b['available'] else p.missing_control_hazard
        else:
            n=len(units);obs=math.fsum(r['coverage'] for r in units)/n if n else 0.
            eff=math.fsum(r['effective_coverage'] for r in units)/n if n else 0.
            missing=math.fsum(r['missing_hazard_allowance'] for r in relevant)
        h=math.fsum(r['hazard'] for r in relevant)
        conditional=100*math.exp(-p.hazard_scale*h) if (obs>0 or relevant and h>0) else None
        lo=100*math.exp(-p.hazard_scale*(h+missing));hi=100*math.exp(-p.hazard_scale*h)
        if not is_na:
            if obs==0 and not relevant:lo=0.;hi=100.
            lower[d]=lo;upper[d]=hi;coverage_values.append((d,obs,eff))
        state='NOT_APPLICABLE' if is_na else 'INSUFFICIENT_EVIDENCE' if obs==0 else 'PARTIAL_EVIDENCE' if obs<1 or eff<1 else 'SCORED'
        dims.append({'dimension_id':d,'name':name,'score':None if is_na or obs==0 else lo,
            'conditional_quality':None if is_na else conditional,'quality_bounds':None if is_na else {'lower':lo,'upper':hi,'semantics':'Policy missing-control sensitivity envelope; NOT a statistical confidence interval'},
            'status':state,'coverage':None if is_na else obs,'effective_coverage':None if is_na else eff,
            'applicable_control_units':n,'supported_hazard':h,'unobserved_hazard_allowance':missing,
            'contributors':relevant,'policy_weight':p.weights[d],
            'explanation':'100*exp(-ln(2)*(sum of maximum supported root hazards + unobserved allowance)); extra PASS evidence cannot raise quality.','applicability_evidence':explicit_na})
    any_observed=any(v>0 for d,v,e in coverage_values)
    total=math.fsum(p.weights[d] for d,v,e in coverage_values)
    obs=math.fsum(p.weights[d]*v for d,v,e in coverage_values)/total if total else None
    eff=math.fsum(p.weights[d]*e for d,v,e in coverage_values)/total if total else None
    lo=aggregate(lower,p.weights,guard=p.compensation_points);hi=aggregate(upper,p.weights,guard=p.compensation_points)
    estimates={d['dimension_id']:d['conditional_quality'] for d in dims if d['conditional_quality'] is not None}
    status='INSUFFICIENT_EVIDENCE' if not any_observed else 'SCORED' if obs==1 and eff==1 else 'PARTIAL_EVIDENCE'
    result={'schema_version':'scientific-cqi-response-2.0','policy':p.export(),'registry':{'version':reg['version'],'sha256':reg['sha256']},
        'as_of':at.isoformat(),'platform':platform,'overall':lo if any_observed else None,'overall_status':status,
        'conditional_overall':aggregate(estimates,p.weights,guard=p.compensation_points),
        'overall_score_kind':'CONSERVATIVE_COVERAGE_BOUND; read alongside conditional_overall and coverage; zero need not mean observed total failure',
        'quality_bounds':{'lower':lo,'upper':hi,'semantics':'Fixed applicable dimensions; missing uncertainty is not probability.'},
        'coverage':{'observability':obs,'effective_reliability_coverage':eff,'applicable_root_units':sum(d['applicable_control_units'] for d in dims if d['status']!='NOT_APPLICABLE'),
            'applicable_control_ids':sorted(expected),'not_applicable_dimensions':[d['dimension_id'] for d in dims if d['status']=='NOT_APPLICABLE'],
            'comparison_scope_controls':sorted([{'control_id':fid,'root_id':s['root_id'],'dimension':s['dimension'],'platform_scope':s.get('platform_scope','GENERIC_HTTP')} for fid,s in expected.items()],key=lambda v:v['control_id']),
            'missing_dimensions':[d['dimension_id'] for d in dims if d['status']=='INSUFFICIENT_EVIDENCE'],
            'missing_controls':[{'root_id':r['root_id'],'dimension':r['dimension'],'control_ids':r['registry_control_ids'],'coverage':r['coverage'],'reason':'Required fresh control evidence is absent, incomplete or stale; never PASS.'} for r in applicable.values() if r['coverage']<1],
            'low_reliability_controls':[{'root_id':r['root_id'],'dimension':r['dimension'],'effective_coverage':r['effective_coverage']} for r in applicable.values() if r['effective_coverage']<r['coverage']],
            'comparison_signature':digest({'registry':reg['sha256'],'platform':platform,'roots':sorted([list(k) for k in applicable]),'coverage':[(d,v,e) for d,v,e in coverage_values]})},
        'dimensions':dims,'contributors':records,'behavioral':b,'warnings':warnings,
        'aggregation_alternatives':{method:aggregate(lower,p.weights,method=method,guard=p.compensation_points) for method in ('arithmetic','geometric','guarded_geometric')},
        'interpretation':'Ordinal conservative evidence-quality index, NOT probability of security/attack/compromise. Bounds express missing-evidence assumptions. Conditional estimate is not comparable when coverage differs.',
        'parameters_calibrated':False,'is_probability':False}
    if identity_corrections:result['control_identity_corrections']=identity_corrections
    result['result_sha256']=digest(result);return result


def compare(before,after):
    comparable=(before['policy']['sha256']==after['policy']['sha256'] and
                before['coverage']['comparison_signature']==after['coverage']['comparison_signature'])
    return {'comparable':comparable,'delta':after['overall']-before['overall'] if comparable and before['overall'] is not None and after['overall'] is not None else None,
        'reason':'SAME_POLICY_SCOPE_AND_COVERAGE' if comparable else 'NOT_COMPARABLE_POLICY_APPLICABILITY_OR_COVERAGE_CHANGED',
        'conservative_bound_delta':after['quality_bounds']['lower']-before['quality_bounds']['lower']}
