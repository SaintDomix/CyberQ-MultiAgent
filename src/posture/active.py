"""Current-finding adapter for the accepted Branch1 active-validation framework.

Probe generation, evaluation, role checks and rate limiting remain in branch1.active.
This layer adds closed deployment scope, a derived budget and presentation-only results.
"""
from collections import Counter
from dataclasses import replace
from pathlib import Path
import os
import re
import time
from urllib.parse import urlsplit, unquote, urljoin

from branch1 import Context
from branch1.common import Document
from branch1.active import Registry, SafetyPolicy, run_active
from branch1.active.runtime import RuntimeContext
from branch1.active.safety import Executor, SafetyError
from evidence_contracts import SecurityFinding, Provenance
from .policy import TARGET
from .privacy import sha, text
from .providers import now

VERSION='current-active-evidence-1.0'
# Exact maxima of the existing RequestSpec sequences, including optional session checks.
MAXIMUM={'sensitive_path':2,'open_redirect':2,'sql_injection':4,'unsafe_reflection_xss':3,
         'account_enumeration':4,'access_control':4,'session_control':4,'ssrf_context':0}
HARD_CEILING=sum(MAXIMUM.values())  # 23; not an arbitrary larger executor allowance.
TIMEOUT=5.0
RATE=.25
EXPOSURES={'EXPOSURE-001':'/server-status','EXPOSURE-002':'/phpinfo.php',
           'EXPOSURE-003':'/.git/HEAD','EXPOSURE-004':'/.env'}
DIRECT_PREFIXES=('TLS-','HDR-','COOKIE-','FS-','CFG-','PHP-','PLUGIN-','PATCH-','CORE-',
                 'ADV-','AUTH-INT-','SESSION-INT-','PRIV-','SSRF-DEF-')
NEGATIVE_MEANING='NOT_CONFIRMED means the bounded check obtained insufficient corroborating evidence; it does not mean false positive or PASS.'


def path_only(url):
    try:
        p=urlsplit(url).path
        if p in EXPOSURES.values(): return p
        if re.fullmatch(r'/\.__branch1_control_[0-9a-f]{16}',p):return '/.__branch1_control_[assessment]'
        if re.fullmatch(r'/moodle/(?:[A-Za-z_-]+/)*(?:[A-Za-z_-]+\.php)?',p):return p
    except (ValueError,TypeError):pass
    return '/[withheld-path]'


class CurrentSafetyPolicy(SafetyPolicy):
    def check(self,spec):
        super().check(spec)
        if self.target!=TARGET:raise SafetyError('Only the exact authorized Moodle target is permitted')
        p=urlsplit(spec.url); decoded=p.path
        for _ in range(4):decoded=unquote(decoded)
        if '..' in decoded.split('/') or '\\' in decoded or decoded!=p.path:
            raise SafetyError('Encoded or ambiguous path is prohibited')
        if (not p.path.startswith('/moodle/') and p.path not in EXPOSURES.values()
                and not re.fullmatch(r'/\.__branch1_control_[0-9a-f]{16}',p.path)):
            raise SafetyError('Path is not an existing reviewed Native exposure or Moodle route')


def fingerprint(spec):return spec.method,spec.url,spec.session_ref,spec.private_parameters


class CurrentExecutor(Executor):
    def __init__(self,policy,*,specs,absolute_deadline=None,**kw):
        super().__init__(policy,**kw)
        self.approved=Counter(fingerprint(s) for s in specs)
        self.deadline=self.clock()+len(specs)*policy.timeout+max(0,len(specs)-1)/policy.requests_per_second
        self.absolute_deadline=absolute_deadline
        if absolute_deadline is not None:self.deadline=min(self.deadline,absolute_deadline)

    def get(self,spec):
        key=fingerprint(spec)
        if self.clock()>=self.deadline or self.approved[key]<=0:
            raise SafetyError('Validation deadline or exact predeclared request plan exceeded')
        if self.absolute_deadline is not None:
            delay=max(0,1/self.policy.requests_per_second-(self.clock()-self.last_request)) if self.last_request is not None else 0
            if self.clock()+delay+self.policy.timeout>self.absolute_deadline:
                raise SafetyError('Whole assessment deadline cannot admit this bounded request')
        self.approved[key]-=1
        result=super().get(spec)
        if self.clock()>self.deadline:raise SafetyError('Validation deadline exceeded')
        return result


class PreparedRegistry(Registry):
    """Pass the accepted planner's current candidates to its unchanged executor loop."""
    def __init__(self,registry,candidates):
        self.validators=registry.validators;self.candidates=candidates
    def plan(self,parents,policy,runtime=None):return self.candidates


def parent_for(row,aid):
    doc=Document.generated('runtime/posture/'+aid+'/snapshot.json#pre-validation',row)
    return SecurityFinding(evidence_id=row['evidence_id'],finding_id=row['finding_id'],
        evidence_source=row['evidence_source'],category=row['category'],finding_type=row['finding_type'],
        check_result=row['check_result'],confirmation_status=row['confirmation_status'],severity=row.get('severity'),
        affected_asset=('http://192.168.226.132'+EXPOSURES[row['finding_id']]) if row['finding_id'] in EXPOSURES else row.get('affected_asset'),
        observed_value=row.get('observed_value'),evidence={},
        provenance=Provenance(doc.path,doc.sha256,0,doc.sha256,'current-active-parent'))


def observations(transcript,indices):
    out=[]
    for i in indices:
        entry=transcript[i];r=entry.get('response',{})
        location=next((v for k,v in r.get('headers',{}).items() if k.lower()=='location'),None)
        redirect={'observed':bool(location),'followed':False}
        if location and location!='<redacted>':
            try:
                p=urlsplit(urljoin(entry.get('url',TARGET),location))
                redirect.update(destination_scope='AUTHORIZED_ORIGIN' if p.scheme=='http' and p.hostname=='192.168.226.132' and p.port in (None,80) else 'OFF_ORIGIN_NOT_FOLLOWED',
                                path=path_only(p.path))
            except (ValueError,TypeError):redirect['destination_scope']='MALFORMED_WITHHELD'
        elif location:redirect['destination_scope']='WITHHELD'
        out.append({'request_index':i,'method':'GET','target_path':path_only(entry.get('url','')),
            'purpose':text(entry.get('purpose')), 'status':r.get('status'),
            'body_length':r.get('body_length'),'body_sha256':r.get('body_sha256'),
            'redirect':redirect,'error':entry.get('error'), 'response_body_retained':False})
    return out


def exported(result,aid,transcript):
    executed=result['execution_status'] in ('EXECUTED','CONTEXTUAL_ASSESSED')
    applicability=result['applicability'];support=result['confirmation_status']
    if applicability=='BUDGET_EXCLUDED':status='NOT_RUN'
    elif applicability=='MISSING_CONTEXT':status='NOT_AVAILABLE'
    elif applicability=='NOT_APPLICABLE':status='NOT_APPLICABLE'
    elif not executed:status='NOT_AVAILABLE'
    elif support=='CONFIRMED' and result['check_result'] in ('FAIL','PARTIAL'):status='CONFIRMED'
    elif support=='NOT_APPLICABLE':status='NOT_APPLICABLE'
    elif support=='NOT_TESTED':status='NOT_AVAILABLE'
    else:status='NOT_CONFIRMED'  # LIKELY/CONTEXTUAL retained, never upgraded.
    obs=observations(transcript,result['request_indices'])
    return {'validator_id':result['validator'],'status':status,'timestamp':now(),'assessment_id':aid,
        'parent_evidence_id':result['parent_evidence_id'],
        'finding_id':result['parent_finding_id'],'candidate_id':result['candidate_id'],
        'prerequisite_state':applicability,'execution_state':result['execution_status'],
        'executed':executed,'target_path':obs[0]['target_path'] if obs else None,
        'request_count':len(obs),'baseline_observation':obs[0] if obs else None,
        'probe_observations':obs[1:],'reason':text(result['reason']),
        'evidence_summary':{'outcome':result['outcome'],'source_check_result':result['check_result'],
                            'source_confirmation_status':support,'characteristics':result.get('characteristics',{}),
                            'observations':obs},
        'support_level':support,'safety_classification':'BOUNDED_READ_ONLY; no-follow; no exploit execution',
        'score_effect':'NONE','successful_exploitation_confirmed':False,'causal':False,
        'not_confirmed_semantics':NEGATIVE_MEANING}


class ActiveValidationStage:
    def __init__(self,project,executor_factory=CurrentExecutor,clock=time.monotonic):
        self.project=Path(project);self.executor_factory=executor_factory;self.clock=clock

    def run(self,rows,aid,absolute_deadline=None):
        registry=Registry();all_candidates=[];parents=[];executor=None
        runtime_error=False
        try:runtime=RuntimeContext.from_env('B1_ACTIVE_CONTEXT') if os.getenv('B1_ACTIVE_CONTEXT') else RuntimeContext()
        except (ValueError,TypeError):runtime=RuntimeContext();runtime_error=True
        planning=CurrentSafetyPolicy(TARGET,False,True,HARD_CEILING,TIMEOUT,RATE)
        for row in rows:
            exclusion=None
            if row['finding_id'].startswith(DIRECT_PREFIXES):exclusion='Directly observable header/cookie/version/filesystem/configuration control; no exploit test is appropriate.'
            elif row['category']=='UNMAPPED':exclusion='Unmapped passive rule has no reviewed active-validation mapping.'
            elif row['check_result'] not in ('FAIL','PARTIAL') or row['confirmation_status'] in ('FALSE_POSITIVE','VERSION_BASED'):
                exclusion='No eligible current FAIL/PARTIAL indication; historical and version-only results are not active targets.'
            parent=parent_for(row,aid);parents.append(parent)
            planned=registry.plan([parent],planning,runtime)
            for c in planned:
                session_mapping=runtime.mappings.get(parent.evidence_id,runtime.mappings.get(parent.finding_id,{})).get('session_control')
                if (c.proposed_validator=='session_control' and not session_mapping
                        and not any(p in row['finding_type'].lower() for p in ('session behavior','session lifecycle','session rotation','session invalidation','session fixation'))):
                    exclusion='An authentication-category label alone is not a session-behavior assertion; no appropriate active protocol is selected.'
                if exclusion:
                    c.proposed_validator=None;c.applicability='NOT_APPLICABLE';c.reason=exclusion;c.context={}
                elif c.proposed_validator:
                    if runtime_error and c.applicability!='NOT_APPLICABLE':
                        c.applicability='MISSING_CONTEXT';c.reason='Invalid server runtime mapping; no historical/session context was substituted.'
                    if c.proposed_validator=='open_redirect' and c.applicability=='NOT_APPLICABLE' and c.required_context:
                        c.applicability='MISSING_CONTEXT'
                    if c.applicability=='APPLICABLE':
                        ctx=c.context
                        if c.proposed_validator=='access_control' and ctx.get('roles_verified') is not True:
                            c.applicability='MISSING_CONTEXT';c.reason='Verified authorized role/session provenance (roles_verified=true) is required.'
                        elif (ctx.get('session_ref') or ctx.get('invalidated_session')) and ctx.get('session_verified') is not True:
                            c.applicability='MISSING_CONTEXT';c.reason='Previously verified authorized session provenance (session_verified=true) is required.'
                all_candidates.append(c)
        severity={'CRITICAL':4,'HIGH':3,'MEDIUM':2,'LOW':1,'INFO':0,None:-1}
        by_id={r['evidence_id']:r for r in rows}
        all_candidates.sort(key=lambda c:(-severity.get(by_id[c.parent_evidence_id].get('severity'),-1),c.parent_finding_id,c.proposed_validator or '',c.candidate_id))
        specs=[];ready=0;safe_plan=[]
        for c in all_candidates:
            if c.applicability!='APPLICABLE':continue
            requests=registry.validators[c.proposed_validator].requests(c)
            try:
                if len(requests)>MAXIMUM[c.proposed_validator]:raise SafetyError('Existing protocol exceeded its declared maximum')
                for spec in requests:replace(planning,active=True).check(spec)
            except (SafetyError,ValueError,TypeError):
                c.applicability='MISSING_CONTEXT';c.reason='Request violates the reviewed target/path/method policy; nothing was sent.';continue
            if len(specs)+len(requests)>HARD_CEILING:
                c.applicability='BUDGET_EXCLUDED';c.reason='Complete validator excluded by the derived 23-request hard ceiling; parent finding preserved.';continue
            planned_seconds=(len(specs)+len(requests))*TIMEOUT+max(0,len(specs)+len(requests)-1)/RATE
            if absolute_deadline is not None and self.clock()+planned_seconds+1>absolute_deadline:
                c.applicability='BUDGET_EXCLUDED';c.reason='Whole STANDARD assessment deadline cannot admit the complete validation protocol; current parent finding preserved.';continue
            specs.extend(requests);ready+=1
            safe_plan.append({'validator_id':c.proposed_validator,'finding_id':c.parent_finding_id,
                'candidate_id':c.candidate_id,'request_count':len(requests),
                'requests':[{'method':s.method,'target_path':path_only(s.url),
                             'query_values':'WITHHELD','spec_sha256':sha(repr(fingerprint(s)))} for s in requests]})
        policy=replace(planning,active=ready>0,request_budget=max(1,len(specs)))
        ctx=Context(self.project)
        try:
            if ready:
                options={'absolute_deadline':absolute_deadline} if absolute_deadline is not None else {}
                executor=self.executor_factory(policy,specs=specs,runtime=runtime,clock=self.clock,**options)
            summary=run_active(ctx,parents,policy,registry=PreparedRegistry(registry,all_candidates),executor=executor,runtime=runtime)
            results=ctx.artifacts['active_validation_results.json']
            transcript=executor.transcript if executor else []
            exported_results=[exported(x,aid,transcript) for x in results]
        finally:
            if executor:executor.session.close()
        for row in rows:
            selected=[v for v in exported_results if v['parent_evidence_id']==row['evidence_id']]
            applicable=[v for v in selected if v['validator_id'] and v['status']!='NOT_APPLICABLE']
            order={'CONFIRMED':0,'NOT_CONFIRMED':1,'NOT_AVAILABLE':2,'NOT_RUN':3,'NOT_APPLICABLE':4}
            representative=min(applicable or selected,key=lambda v:order[v['status']])
            row['active_validation']={**representative,'results':selected,'score_effect':'NONE'}
            row['validation_sources']=sorted(set(row.get('evidence_sources',[])) | ({'ACTIVE_VALIDATION'} if any(v['executed'] for v in selected) else set()))
        counts=Counter(r['active_validation']['status'] for r in rows)
        return {'version':VERSION,'assessment_id':aid,'status':'COMPLETE','results':exported_results,
            'counts':{'eligible':sum(bool(r['active_validation']['validator_id']) and r['active_validation']['status']!='NOT_APPLICABLE' for r in rows),
                      'ready':ready,'executed':sum(any(v['executed'] for v in r['active_validation']['results']) for r in rows),
                      **dict(counts)},
            'budget':{'per_validator_maximum':MAXIMUM,'global_hard_ceiling':HARD_CEILING,
                'planned_requests':len(specs),'actual_requests':summary['requests_used'],
                'plan':safe_plan,
                'timeout_seconds':TIMEOUT,'requests_per_second':RATE,
                'max_duration_seconds':len(specs)*TIMEOUT+max(0,len(specs)-1)/RATE,
                'selection':'complete protocols, severity then finding ID then validator; no partial budget admission',
                'follow_redirects':False,'max_response_bytes':policy.max_response_bytes},
            'parent_findings_preserved':True,'score_effect':'NONE','successful_exploitation_confirmed':False}


def fail_closed(rows,aid):
    """Provider-wide failure still leaves all fresh Native/ZAP evidence intact."""
    for r in rows:
        r['active_validation']={'status':'NOT_AVAILABLE','assessment_id':aid,'finding_id':r['finding_id'],
            'validator_id':None,'timestamp':now(),'reason':'Active stage failed closed; fresh posture finding retained.',
            'request_count':None,'executed':None,'execution_state':'UNKNOWN','results':[],
            'score_effect':'NONE','not_confirmed_semantics':NEGATIVE_MEANING}
    return {'version':VERSION,'assessment_id':aid,'status':'FAILED','error':'Active stage failed closed; details withheld',
            'score_effect':'NONE','parent_findings_preserved':True}
