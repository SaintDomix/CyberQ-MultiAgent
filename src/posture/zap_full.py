"""Fresh, scoped, finite FULL_AUTHORIZED ZAP orchestration; no ML or CQI policy."""
from dataclasses import dataclass,asdict
from collections import Counter
import math
import shutil
import time
import json
from html.parser import HTMLParser
from urllib.parse import urljoin
from .providers import now
from .privacy import sha
from .target import sanitized_url,endpoint,parameter
from .zap_full_api import FullZapAPI
from .zap_normalize import normalize_alerts
from .zap_observability import progress_rules,stats_values,execution_report,completion_seconds,candidate_index,session_index

VERSION='zap-full-authorized-1.1'
# These are not exclusions for being active: injection, SQLi, XSS, command and
# template probes remain enabled. Explicit DoS/callback/custom script boundaries.
EXCLUDED={
 '30001':'Resource-exhaustion/buffer-overflow test; uncontrolled stress is prohibited.',
 '40044':'Billion Laughs deliberate resource exhaustion is prohibited.',
 '7':'Remote inclusion may fetch external payloads outside authorized target.',
 '40043':'Log4Shell callback/OAST outside the authorized application is not configured.',
 '90034':'Cloud metadata access is outside the authorized application.',
 '90023':'External entity file/callback behavior lacks an authorized external target.',
 '50000':'No operator-reviewed custom active scripts are configured.',
 '40045':'Spring4Shell file-write/webshell probe is not a non-destructive vulnerability test.',
 '10106':'Changes the configured HTTP origin to HTTPS; a second origin is not authorized by this profile.',
 '10047':'Changes HTTPS to HTTP; a second origin is not authorized by this profile.',
}

@dataclass(frozen=True)
class FullBudget:
    overall_seconds:int=4380
    spider_seconds:int=120
    client_seconds:int=90
    ajax_seconds:int=90
    active_seconds:int=completion_seconds()
    passive_seconds:int=120
    concurrency:int=4
    requests_per_second:int=8
    disk_minimum_bytes:int=500_000_000
    def __post_init__(self):
        if not (60<=self.overall_seconds<=7200 and 1<=self.spider_seconds<=300 and 1<=self.client_seconds<=120
            and 1<=self.ajax_seconds<=120 and 1<=self.active_seconds<=5400 and 1<=self.passive_seconds<=120
            and 1<=self.concurrency<=4 and 1<=self.requests_per_second<=8
            and self.disk_minimum_bytes>=500_000_000):raise ValueError('Full assessment bounds exceeded')


def capability_inventory(api,deadline):
    version=api.call('core','view','version',control_deadline=deadline)['version']
    addons=api.call('autoupdate','view','installedAddons',control_deadline=deadline)['installedAddons']
    active=api.call('ascan','view','scanners',control_deadline=deadline)['scanners']
    passive=api.call('pscan','view','scanners',control_deadline=deadline)['scanners']
    if len(addons)>250 or len(active)>200 or len(passive)>200:raise ValueError('Inventory size exceeded')
    installed={a['id'] for a in addons}
    mapping={'traditional_spider':('spider',True),'client_spider':('client',True),'ajax_spider':('spiderAjax',True),
        'forced_browse':('bruteforce',False),'fuzzer':('fuzz',False),'openapi':('openapi',True),
        'graphql':('graphql',True),'soap':('soap',True),'postman':('postman',True),
        'authentication':('authhelper',False),'session_management':('authhelper',False),
        'sequence':('sequence',False),'automation_framework':('automation',False),
        'technology_context':('core',True),'passive_scan':('pscan',True),'active_scan':('ascanrules',True)}
    caps={k:{'installed':addon in installed or addon=='core','available':addon in installed or addon=='core',
        'integrated':integrated,'executed':False,
        'reason':None if integrated else 'Installed capability; no generic automated job/session configured in this profile.'}
        for k,(addon,integrated) in mapping.items()}
    caps['forced_browse']['reason']='Installed GUI/add-on; no forced-browse API component exposed by this runtime.'
    caps['fuzzer']['reason']='Specialized message/location/payload/processor job required; no fuzz-everything operation.'
    caps['authentication']['reason']='Anonymous run; verified credentials/session configuration NOT_CONFIGURED.'
    servers=api.call('network','view','getLocalServers',control_deadline=deadline).get('localServers',[])
    if any(s.get('api') is True and s.get('address') not in ('127.0.0.1','::1') for s in servers):
        raise ValueError('Non-loopback ZAP API listener')
    return {'version':str(version),'addons':[{'id':a['id'],'version':str(a['version'])} for a in addons],
        'control_api_origin':api.origin if hasattr(api,'origin') else 'SYNTHETIC_LOOPBACK',
        'local_servers':[{k:s.get(k) for k in ('address','port','api','proxy')} for s in servers],
        'active_scanners':[{k:a.get(k) for k in ('id','name','policyId','status','quality','enabled','attackStrength','alertThreshold')} for a in active],
        'passive_scanners':[{k:a.get(k) for k in ('id','name','enabled','alertThreshold')} for a in passive],
        'capabilities':caps}


class FullZapProvider:
    def __init__(self,passive_provider,project,api_factory=FullZapAPI,clock=time.monotonic,pause=time.sleep):
        self.passive=passive_provider;self.project=project;self.api_factory=api_factory;self.clock=clock;self.pause=pause
        self.cancelled=False
    def run(self,aid,target,budget=None,progress=None,cancel=None,absolute_deadline=None):
        standard=target.scan_profile=='STANDARD'
        if standard:
            from .zap_standard import StandardBudget,scanner_policy,POLICY_ID
        b=budget or (StandardBudget() if standard else FullBudget());start=self.clock()
        deadline=start+b.overall_seconds
        if standard and absolute_deadline is not None:deadline=min(deadline,absolute_deadline-b.cleanup_seconds)
        cleanup_deadline=min(deadline+b.cleanup_seconds,absolute_deadline or float('inf')) if standard else None
        profile='STANDARD' if standard else 'FULL_AUTHORIZED';policy_id=POLICY_ID if standard else VERSION
        result={'provider_id':'zap_full','version':VERSION,'status':'FAILED','assessment_id':aid,
            'started_at':now(),'target_profile':target.export(aid),'profile':profile,'assessment_profile':profile,
            'findings':[],'stages':{},'policy':{'id':policy_id,'bounds':asdict(b),'request_ceiling':None,
                'semantics':'Finite stage/overall deadlines and rate/concurrency controls; no Native-sized request cap.'},
            'authentication_status':'NOT_CONFIGURED','causal':False,'successful_exploitation_confirmed':False}
        api=None;owned={};settings=[];policy_created=False;rate_created=False;mode_changed=False
        stage_deadline=deadline;progress_samples=[];spider_details=None;ajax_details=None;seed_metadata={}
        def call(c,k,n,**kw):return api.call(c,k,n,control_deadline=min(deadline,stage_deadline),**kw)
        def cleanup_call(c,k,n,**kw):
            limit=min(self.clock()+8,cleanup_deadline) if cleanup_deadline is not None else self.clock()+8
            if self.clock()>=limit:raise TimeoutError('BOUNDED_CLEANUP_DEADLINE')
            return api.call(c,k,n,control_deadline=limit,**kw)
        def emit(stage,data):
            result['stages'][stage]=data
            if progress:progress(stage,{k:v for k,v in data.items() if k not in ('urls','findings')})
        def guard():
            if (cancel and cancel()) or self.clock()>=deadline:raise TimeoutError('CANCELLED_OR_OVERALL_TIMEOUT')
            if shutil.disk_usage(self.project).free<b.disk_minimum_bytes:raise RuntimeError('DISK_GUARD')
        def stop_owned(component,sid):
            # Control cancellation must remain possible after the work deadline.
            cleanup_call(component,'action','stop',
                **({} if component=='ajaxSpider' else {'scanId':sid}))
        def wait(component,sid,seconds):
            began=self.clock();limit=min(deadline,began+seconds);last_sample=-100
            while True:
                guard()
                if component=='ajaxSpider':value=call(component,'view','status')['status'];done=value=='stopped'
                else:
                    value=call(component,'view','status',scanId=sid)['status']
                    done=str(value) in ('100','FINISHED','finished','STOPPED','stopped')
                if component=='ascan':
                    scans=call('ascan','view','scans').get('scans',[])
                    current=next((s for s in scans if str(s.get('id'))==sid),None)
                    # status() returns 100 for stopped jobs too. Require the owned
                    # job's natural finished state, not merely that endpoint.
                    done=done and current is not None and str(current.get('state','')).upper()=='FINISHED' and str(current.get('progress'))=='100'
                    if current is not None:value=current.get('progress',value)
                    if self.clock()-last_sample>=10 or done or self.clock()>=limit:
                        last_sample=self.clock()
                        try:rules=progress_rules(call('ascan','view','scanProgress',scanId=sid))
                        except Exception:rules=[]
                        sample={'elapsed_seconds':round(self.clock()-began,3),'progress':value,
                            'state':current.get('state') if current else 'OWNED_HANDLE_NOT_VISIBLE',
                            'request_count':current.get('reqCount') if current else None,
                            'alert_count':current.get('alertCount') if current else None,
                            'rules':rules}
                        progress_samples.append(sample)
                        result['active_progress_samples']=progress_samples
                        if progress:progress(component,{'status':'RUNNING','scan_id':sid,**sample})
                elif progress:progress(component,{'status':'RUNNING','scan_id':sid,'progress':value})
                if done:return 'COMPLETE',value
                if self.clock()>=limit:
                    stop_owned(component,sid)
                    return 'PARTIAL',value
                self.pause(min(1,max(0,limit-self.clock())))
        def configure(c,suffix,value):
            old=call(c,'view','option'+suffix)
            old=next(iter(old.values()))
            key='Boolean' if value in ('true','false') else 'Integer' if value.isdigit() else 'String'
            call(c,'action','setOption'+suffix,**{key:value})
            settings.append((c,suffix,key,str(old).lower() if isinstance(old,bool) else str(old)))
        def page_alerts():
            out=[];offset=0
            while True:
                guard();page=call('alert','view','alerts',baseurl=target.target_url,start=str(offset),count='100')['alerts']
                out.extend(page)
                if len(out)>10000:raise RuntimeError('ALERT_EXPORT_BOUND')
                if len(page)<100:return out
                offset+=len(page)
        try:
            if not getattr(self.passive,'owned_ephemeral',False) or not getattr(self.passive,'api',None):
                raise ValueError('OWNED_LOOPBACK_ZAP_UNAVAILABLE')
            guard();api=self.api_factory(self.passive.api,target)
            inventory=capability_inventory(api,deadline);result['inventory']=inventory
            if standard:result['standard_policy']=scanner_policy(inventory['active_scanners'])
            # Owned daemon only; no shared scanner session is adopted/stopped.
            for c in ('ascan','spider'):
                if call(c,'view','scans')['scans']:raise ValueError('SHARED_SCANNER_SESSION')
            if call('ajaxSpider','view','status')['status']!='stopped':raise ValueError('SHARED_AJAX_SESSION')
            if call('core','view','mode')['mode']!='safe':raise ValueError('FRESH_SAFE_RUNTIME_REQUIRED')
            call('core','action','newSession')
            if int(call('core','view','numberOfMessages')['numberOfMessages'])!=0:raise ValueError('NEW_SESSION_NOT_EMPTY')
            api.context_name=aid
            context_id=str(call('context','action','newContext',contextName=aid)['contextId'])
            api.context_id=context_id
            call('context','action','includeInContext',contextName=aid,regex=target.include_regex)
            for regex in target.exclusions:call('context','action','excludeFromContext',contextName=aid,regex=regex)
            call('context','action','setContextInScope',contextName=aid,booleanInScope='true')
            call('core','action','setMode',mode='protect')
            mode_changed=True
            if call('core','view','mode')['mode']!='protect':raise ValueError('PROTECTED_MODE_REQUIRED')
            result.update(context_id=context_id,context_name=aid,zap_mode='PROTECTED',zap_mode_api='protect',session_lifecycle='FRESH_VERIFIED_EMPTY')
            inventory['capabilities']['technology_context']['executed']=True
            try:result['technologies']=call('context','view','includedTechnologyList',contextName=aid)
            except Exception:result['technologies']={'status':'NOT_AVAILABLE; no generic rules removed'}
            for c,suffix,value in [('ascan','ThreadPerHost',str(b.concurrency)),('ascan','DelayInMs','100'),
                ('ascan','MaxScanDurationInMins',str(math.ceil(b.active_seconds/60)+1)),('ascan','MaxRuleDurationInMins','0'),
                ('ascan','HandleAntiCSRFTokens','false'),('ascan','PersistTemporaryMessages','true'),
                ('spider','ThreadCount',str(b.concurrency)),('spider','MaxDuration',str(math.ceil(b.spider_seconds/60))),
                ('spider','PostForm','false'),('spider','ProcessForm','true'),('spider','LogoutAvoidance','true'),
                ('spider','MaxParseSizeBytes','1000000'),('spider','ParseRobotsTxt','false'),('spider','ParseSitemapXml','false')]:configure(c,suffix,value)
            if standard:
                configure('spider','MaxDepth','3');configure('spider','MaxChildren','10')
            extra_scope=call('spider','view','domainsAlwaysInScope').get('domainsAlwaysInScope',[])
            if any(str(d.get('enabled',True)).lower()=='true' for d in extra_scope):
                raise ValueError('GLOBAL_SPIDER_EXTRA_SCOPE_CONFIGURED')
            call('network','action','addRateLimitRule',description=aid,enabled='true',matchRegex='false',
                matchString=__import__('urllib.parse',fromlist=['urlsplit']).urlsplit(target.target_url).hostname,
                requestsPerSecond=str(b.requests_per_second),groupBy='rule');rate_created=True
            call('pscan','action','setEnabled',enabled='true')
            seed=call('core','action','accessUrl',url=target.target_url,followRedirects='false')
            seed_forms=Forms(target,target.target_url)
            for msg in seed.get('accessUrl',[]) if isinstance(seed,dict) else []:
                if isinstance(msg,dict):seed_forms.feed(msg.get('responseBody','')[:200000])
            seed_metadata={'forms':[{'action':u,'method':m,'parameter_names':list(p)} for u,m,p in sorted(seed_forms.forms)]}
            for component,url in ({} if standard else target.api_imports).items():
                t=self.clock()
                try:
                    params={'endurl':url} if component=='graphql' else {'url':url}
                    if component=='openapi':params.update(hostOverride=target.target_url,contextId=context_id)
                    call(component,'action','importUrl',**params)
                    emit('import_'+component,{'status':'COMPLETE','duration_seconds':self.clock()-t})
                    inventory['capabilities'][component]['executed']=True
                except Exception:emit('import_'+component,{'status':'FAILED','reason':'IMPORT_UNAVAILABLE; raw payload withheld'})
            t=self.clock();stage_deadline=min(deadline,t+b.spider_seconds+8)
            emit('spider',{'status':'RUNNING'})
            sid=str(call('spider','action','scan',url=target.target_url,recurse='true',contextName=aid,subtreeOnly='true')['scan'])
            owned['spider']=sid;api.owned_scans=owned
            status,pct=wait('spider',sid,b.spider_seconds)
            discovered=call('spider','view','results',scanId=sid)['results']
            try:
                spider_details=call('spider','view','fullResults',scanId=sid)
                result['spider_detail_sha256']=sha(json.dumps(spider_details,sort_keys=True))
            except Exception:result['spider_detail_status']='NOT_AVAILABLE'
            emit('spider',{'status':status,'scan_id':sid,'duration_seconds':self.clock()-t,'progress':pct,
                'urls':[sanitized_url(u) for u in discovered if target.contains(u)],'url_count':sum(target.contains(u) for u in discovered)})
            inventory['capabilities']['traditional_spider']['executed']=True
            stage_deadline=deadline
            before_client=set(call('core','view','urls',baseurl=target.target_url)['urls'])
            for component,seconds in [('clientSpider',b.client_seconds),('ajaxSpider',b.ajax_seconds)]:
                cap='client_spider' if component=='clientSpider' else 'ajax_spider'
                if standard:
                    emit(component,{'status':'NOT_RUN_STANDARD','reason':'Intentional efficient discovery; browser functionality remains available in FULL_AUTHORIZED.'});continue
                if target.discovery_profile=='SPIDER' or not inventory['capabilities'][cap]['installed']:
                    emit(component,{'status':'NOT_RUN','reason':'NOT_CONFIGURED_OR_INSTALLED'});continue
                t=self.clock();stage_deadline=min(deadline,t+seconds+8)
                try:
                    guard()
                    if component=='clientSpider':
                        r=call(component,'action','scan',browser='firefox-headless',url=target.target_url,contextName=aid,
                            subtreeOnly='true',scopeCheck='STRICT',maxCrawlDepth='5',pageLoadTime='10',numberOfBrowsers='1')
                        sid=str(r.get('scanId',r.get('scan')))
                        if sid in ('None',''):raise ValueError('No owned client scan id')
                    else:
                        for suffix,value in [('MaxDuration',str(math.ceil(seconds/60))),('NumberOfBrowsers','1'),
                            ('LogoutAvoidance','true'),('RandomInputs','false'),('BrowserId','firefox-headless')]:configure(component,suffix,value)
                        call(component,'action','scan',url=target.target_url,inScope='true',contextName=aid,subtreeOnly='true');sid='owned'
                    owned[component]=sid;api.owned_scans=owned
                    inventory['capabilities'][cap]['executed']=True
                    status,pct=wait(component,sid,seconds)
                    if component=='ajaxSpider':
                        try:ajax_details=call(component,'view','fullResults')
                        except Exception:result['ajax_detail_status']='NOT_AVAILABLE'
                    after=set(call('core','view','urls',baseurl=target.target_url)['urls'])
                    emit(component,{'status':status,'scan_id':sid,'duration_seconds':self.clock()-t,
                        'progress_at_finalization':pct,'reason':None if status=='COMPLETE' else 'OWNED_STAGE_DEADLINE; stopped using independent control deadline',
                        'additional_urls':len({u for u in after-before_client if target.contains(u)})})
                    before_client=after
                except Exception:
                    started=component in owned
                    control_status='NO_OWNED_HANDLE'
                    if started:
                        try:stop_owned(component,owned[component]);control_status='STOP_REQUESTED'
                        except Exception:control_status='STOP_API_FAILED'
                    emit(component,{'status':'PARTIAL' if started else 'NOT_AVAILABLE','duration_seconds':self.clock()-t,
                        'scan_id':owned.get(component),'ownership_state':control_status,
                        'reason':'OWNED_DISCOVERY_INTERRUPTED; late completion is diagnostic only' if started else 'BROWSER_OR_DISCOVERY_API_UNAVAILABLE; no owned job started'})
                stage_deadline=deadline
            # Current discovered context, not Native findings or a fixed five-page list.
            site_urls=call('core','view','urls',baseurl=target.target_url)['urls']
            sites={endpoint(u) for u in site_urls if target.contains(u)}
            result['site_tree']=[{'url':u,'parameters':list(params),'sources':['CURRENT_ZAP_SESSION']} for u,params in sorted(sites)]
            result['unique_endpoints']=len(sites);result['parameter_count']=sum(len(p) for u,p in sites)
            result['discovery_index']=candidate_index(site_urls,target)
            self._passive(call,b.passive_seconds,guard)
            pre_alerts=page_alerts()
            # Preserve completed discovery/passive evidence even if active fails.
            result['findings']=normalize_alerts(pre_alerts,target,aid,now())[0]
            emit('passive_before_active',{'status':'COMPLETE','alerts':len(pre_alerts)})
            policy_name=('standard-' if standard else 'full-')+aid;api.policy_name=policy_name
            strength='LOW' if standard else 'MEDIUM'
            call('ascan','action','addScanPolicy',scanPolicyName=policy_name,alertThreshold='MEDIUM',attackStrength=strength);policy_created=True
            call('ascan','action','disableAllScanners',scanPolicyName=policy_name)
            scanner_ids=(result['standard_policy']['enabled_ids'] if standard else
                [str(s['id']) for s in inventory['active_scanners'] if str(s['id']) not in EXCLUDED])
            if not scanner_ids:raise ValueError('NO_INSTALLED_APPLICABLE_RULES')
            call('ascan','action','enableScanners',ids=','.join(scanner_ids),scanPolicyName=policy_name)
            effective=call('ascan','view','scanners',scanPolicyName=policy_name)['scanners']
            enabled={str(s['id']) for s in effective if str(s.get('enabled')).lower()=='true'}
            if enabled!=set(scanner_ids):raise ValueError('EFFECTIVE_SCANNER_POLICY_MISMATCH')
            result['policy'].update(scan_policy_name=policy_name,enabled_ids=sorted(enabled,key=int),
                excluded={sid:reason for sid,reason in EXCLUDED.items() if sid in {str(s['id']) for s in inventory['active_scanners']}},
                effective_scanners=effective,attack_strength=strength,alert_threshold='MEDIUM')
            before_count=int(call('core','view','numberOfMessages')['numberOfMessages'])
            try:stats_before=stats_values(call('stats','view','stats',keyPrefix='stats.ascan.'))
            except Exception:stats_before={}
            result['mode_before_active']=call('core','view','mode')['mode']
            if result['mode_before_active']!='protect':
                call('core','action','setMode',mode='protect')
            if call('core','view','mode')['mode']!='protect':raise ValueError('PROTECTED_MODE_REQUIRED_AT_DISPATCH')
            t=self.clock();stage_deadline=min(deadline,t+b.active_seconds+8);emit('active',{'status':'RUNNING'})
            # Context-only is the documented full-application operation; it
            # avoids resolving a particular GET seed node after browser discovery.
            sid=str(call('ascan','action','scan',recurse='true',inScopeOnly='true',
                scanPolicyName=policy_name,contextId=context_id)['scan'])
            owned['ascan']=sid;api.owned_scans=owned
            inventory['capabilities']['active_scan']['executed']=True
            status,pct=wait('ascan',sid,b.active_seconds)
            stage_deadline=deadline
            ids=call('ascan','view','messagesIds',scanId=sid)['messagesIds']
            active_alert_ids=call('ascan','view','alertsIds',scanId=sid)['alertsIds']
            try:scan_progress=call('ascan','view','scanProgress',scanId=sid)
            except Exception:scan_progress={'status':'NOT_AVAILABLE'}
            result['active_rule_progress_sha256']=sha(json.dumps(scan_progress,sort_keys=True))
            try:stats_after=stats_values(call('stats','view','stats',keyPrefix='stats.ascan.'))
            except Exception:stats_after={}
            rules=progress_rules(scan_progress)
            report=execution_report(effective,enabled,rules,stats_before,stats_after)
            result['active_rule_execution']=report
            result['active_rule_counter_baseline']=stats_before;result['active_rule_counter_final']=stats_after
            result['actual_executed_rule_ids']=[r['id'] for r in report if r['execution_observed']]
            result['actual_executed_rules_status']='AUTHORITATIVE_PROGRESS_AND_COUNTER_DELTAS; enabled is not executed'
            emit('active',{'status':status,'scan_id':sid,'duration_seconds':self.clock()-t,'progress':pct,
                'request_message_count':len(ids),'message_ids_sha256':sha(str(ids)),
                'message_ids':[str(i) for i in ids],'alert_ids':[str(i) for i in active_alert_ids],
                'history_count_before':before_count,'history_count_after':int(call('core','view','numberOfMessages')['numberOfMessages']),
                'enabled_rule_count':len(enabled),'alert_ids_count':len(active_alert_ids),
                'cancellation_reason':'ACTIVE_STAGE_DEADLINE' if status=='PARTIAL' else None})
            self._passive(call,b.passive_seconds,guard)
            alerts=page_alerts();findings,excluded=normalize_alerts(alerts,target,aid,now(),active_alert_ids,sid)
            result['findings']=findings
            result.update(alerts_excluded_off_scope=excluded,alerts_total=len(findings),
                passive_alerts=sum(f['evidence_source']=='ZAP_PASSIVE' for f in findings),
                active_alerts=sum(f['evidence_source']=='ZAP_ACTIVE' for f in findings),
                risk_distribution=dict(Counter(f['severity'] for f in findings)),
                confidence_distribution=dict(Counter(f['source_confidence'] for f in findings)))
            emit('passive',{'status':'COMPLETE','queue_complete':True,'alerts':result['passive_alerts']})
            inventory['capabilities']['passive_scan']['executed']=True
            stage_deadline=min(deadline,self.clock()+getattr(b,'metadata_seconds',180))
            try:
                result['traffic']=session_index(call,target,guard,seed_metadata,spider_details,ajax_details)
                emit('metadata',{'status':'PARTIAL' if result['traffic']['metadata_truncated'] else 'COMPLETE',
                    'history_messages':result['traffic']['total_history_messages'],'source':result['traffic']['metadata_source']})
            except Exception:
                result['traffic']={'metadata_truncated':True,'metadata_error':'CURRENT_STRUCTURAL_METADATA_UNAVAILABLE; no old metadata substituted'}
                emit('metadata',{'status':'PARTIAL','reason':'CURRENT_STRUCTURAL_METADATA_UNAVAILABLE'})
            stage_deadline=deadline
            result['status']='COMPLETE' if status=='COMPLETE' and not result['traffic']['metadata_truncated'] and all(v['status'] in ('COMPLETE','NOT_RUN','NOT_RUN_STANDARD') for k,v in result['stages'].items() if k in ('spider','clientSpider','ajaxSpider','active','passive')) else 'PARTIAL'
        except Exception as e:
            for stage,data in result['stages'].items():
                if data['status']=='RUNNING':data.update(status='FAILED',reason='CURRENT_STAGE_INTERRUPTED; no historical result substituted')
            result.update(status='PARTIAL' if result['findings'] else 'FAILED',
                error_code='CANCELLED_OR_TIMEOUT' if isinstance(e,TimeoutError) else 'FULL_ZAP_STAGE_FAILED',
                error='Current completed stages preserved; untrusted exception text/payload withheld')
            result['failed_api_operation']=getattr(api,'last_call',None)
            result['api_failure_cause']=getattr(e,'cause_code',None)
        finally:
            if api:
                if standard:cleanup_deadline=min(cleanup_deadline,self.clock()+b.cleanup_seconds)
                cleanup=[]
                if standard and mode_changed:
                    # Prioritize cancellation and SAFE restoration inside the
                    # shared cleanup allowance; optional setting restores follow.
                    if 'ascan' in owned:
                        try:cleanup_call('ascan','action','stop',scanId=owned['ascan'])
                        except Exception:cleanup.append('ASCAN_PRIORITY_STOP_FAILED')
                    try:
                        cleanup_call('core','action','setMode',mode='safe')
                        result['final_zap_mode']=cleanup_call('core','view','mode')['mode'];mode_changed=False
                    except Exception:cleanup.append('SAFE_MODE_PRIORITY_RESTORE_FAILED')
                # Only this job's handles. A bounded cancellation cannot kill shared work.
                for component,sid in owned.items():
                    try:
                        cleanup_call(component,'action','stop',
                            **({} if component=='ajaxSpider' else {'scanId':sid}))
                        if component in ('ascan','spider'):
                            cleanup_call(component,'action','removeScan',scanId=sid)
                    except Exception:cleanup.append(component+'_CLEANUP_FAILED')
                for c,suffix,key,old in reversed(settings):
                    try:cleanup_call(c,'action','setOption'+suffix,**{key:old})
                    except Exception:cleanup.append(c+'_'+suffix+'_RESTORE_FAILED')
                if rate_created:
                    try:cleanup_call('network','action','removeRateLimitRule',description=aid)
                    except Exception:cleanup.append('RATE_RULE_CLEANUP_FAILED')
                if policy_created:
                    try:cleanup_call('ascan','action','removeScanPolicy',scanPolicyName=api.policy_name)
                    except Exception:cleanup.append('POLICY_CLEANUP_FAILED')
                if mode_changed:
                    try:
                        cleanup_call('core','action','setMode',mode='safe')
                        result['final_zap_mode']=cleanup_call('core','view','mode')['mode']
                    except Exception:cleanup.append('SAFE_MODE_RESTORE_FAILED')
                result['cleanup_errors']=cleanup
                if cleanup:result['status']='PARTIAL' if result['findings'] else 'FAILED'
                api.close()
            result.update(completed_at=now(),duration_seconds=max(0,self.clock()-start))
        return result

    def _passive(self,call,seconds,guard):
        deadline=self.clock()+seconds
        while int(call('pscan','view','recordsToScan')['recordsToScan'])!=0:
            guard()
            if self.clock()>=deadline:raise TimeoutError('PASSIVE_QUEUE_TIMEOUT')
            self.pause(.5)

    def _history(self,call,target,active_ids,guard):
        """Compact structural provenance only. Raw headers/bodies never exported."""
        count=int(call('core','view','numberOfMessages')['numberOfMessages'])
        records=[];forms=set();active_ids={str(i) for i in active_ids};omitted=[];interrupted=False
        # One static-resource response can be several MB. Ten bodies in one API
        # response exceeded the control cap in real acceptance. Do not raise it.
        for offset in range(min(count,5000)):
            try:
                guard()
                page=call('core','view','messages',start=str(offset),count='1')['messages']
            except Exception as exc:
                if getattr(exc,'cause_code',None)=='RESPONSE_SIZE_LIMIT' or getattr(exc,'code',None)=='RESPONSE_SIZE_LIMIT':
                    omitted.append({'history_index':offset,'reason':'SINGLE_RECORD_EXCEEDS_CONTROL_RESPONSE_CAP'});continue
                omitted.append({'history_index':offset,'reason':'METADATA_EXPORT_INTERRUPTED; prior metadata retained'})
                interrupted=True;break
            for msg in page:
                first=msg.get('requestHeader','').split('\r\n',1)[0].split(' ')
                if len(first)<3:continue
                method,url=first[0],first[1]
                if not url.startswith(('http://','https://')):
                    url=urljoin(target.target_origin,url)
                if not target.contains(url):continue
                status=msg.get('responseHeader','').split(' ',2)
                status=int(status[1]) if len(status)>1 and status[1].isdigit() else None
                body=msg.get('responseBody','')
                parser=Forms(target,url)
                try:parser.feed(body[:200000]);parser.close()
                except Exception:pass
                forms.update(parser.forms)
                records.append({'message_id':str(msg.get('id')),'url':sanitized_url(url),'method':method,
                    'status_code':status,'source':'ACTIVE_TRAFFIC' if str(msg.get('id')) in active_ids else 'CURRENT_DISCOVERY_TRAFFIC',
                    'response_sha256':sha(body),'body_retained':False})
        return {'total_history_messages':count,'exported_target_messages':len(records),
            'metadata_export_limit':5000,'metadata_truncated':count>5000 or interrupted or bool(omitted),'messages':records,
            'omitted_metadata_records':omitted,
            'unique_forms':[{'action':u,'method':m,'parameter_names':list(p)} for u,m,p in sorted(forms)],
            'unique_form_count':len(forms),'secret_values_retained':False}


class Forms(HTMLParser):
    def __init__(self,target,url):
        super().__init__();self.target=target;self.url=url;self.current=None;self.forms=set()
    def handle_starttag(self,tag,attrs):
        attrs=dict(attrs)
        if tag=='form':
            action=urljoin(self.url,attrs.get('action') or self.url)
            self.current=[sanitized_url(action),attrs.get('method','GET').upper(),set()] if self.target.contains(action) else None
        elif tag in ('input','select','textarea') and self.current and attrs.get('name'):
            self.current[2].add(parameter(attrs['name']))
    def handle_endtag(self,tag):
        if tag=='form' and self.current:
            u,m,p=self.current;self.forms.add((u,m,tuple(sorted(p))));self.current=None


def rule_progress(value):
    """Compatibility summary; detailed authoritative metadata is retained separately."""
    return [{k:r[k] for k in ('id','request_count','status')} for r in progress_rules(value)]
