"""First-class ZAP findings; finding existence is independent of CQI mapping."""
import re
from urllib.parse import urlsplit
from fusion.schema import stable_id
from .model import row,ZAP_RULES
from .privacy import sha,evidence_digest,text
from .target import parameter,sanitized_url,endpoint

RISK={'0':'INFO','1':'LOW','2':'MEDIUM','3':'HIGH','Informational':'INFO','Low':'LOW','Medium':'MEDIUM','High':'HIGH'}
CONF={'0':'False Positive','1':'Low','2':'Medium','3':'High','4':'User Confirmed'}


def normalize_alerts(alerts,target,aid,at,active_ids=(),scan_id=None):
    findings=[];excluded=0;active_ids={str(x) for x in active_ids}
    for a in alerts:
        url=a.get('url','')
        if not target.contains(url):excluded+=1;continue
        plugin=str(a.get('pluginId',a.get('pluginid','')))
        if not re.fullmatch(r'\d{1,8}',plugin):raise ValueError('Invalid scanner identity')
        source='ZAP_ACTIVE' if str(a.get('id')) in active_ids else 'ZAP_PASSIVE'
        risk=str(a.get('riskcode',a.get('risk','')));confidence=str(a.get('confidencecode',a.get('confidence','')))
        severity=RISK.get(risk)
        if severity is None:raise ValueError('Unrecognized scanner severity')
        param=parameter(a.get('param','')) if a.get('param') else None
        method=a.get('method','GET')
        if method not in ('GET','HEAD','POST','OPTIONS','PUT','PATCH','DELETE'):method='UNKNOWN'
        cwe=str(a.get('cweid',''));cwe=cwe if cwe.isdigit() else None
        mapping=ZAP_RULES.get(plugin)
        if plugin in ('10010','10011','10054') and a.get('param')!='MoodleSession':mapping=None
        family='SQLI' if cwe=='89' else 'XSS' if cwe=='79' else 'ZAP-'+plugin
        identity=[family,cwe,endpoint(url),param,method]
        key=stable_id('zap-weakness',identity)
        fid,category,title=mapping or (stable_id('ZAP-'+plugin,identity),'UNMAPPED',text(a.get('alert',a.get('name','ZAP finding '+plugin)))[:240])
        confirmation='FALSE_POSITIVE' if confidence in ('0','False Positive') else 'NOT_CONFIRMED'
        sanitized={'plugin_id':plugin,'alert_name':title,'zap_risk':severity,
            'zap_confidence':CONF.get(confidence,confidence if confidence in CONF.values() else 'Unknown'),
            'url':sanitized_url(url),'normalized_path':urlsplit(sanitized_url(url)).path,
            'parameter':param,'method':method,'cwe':cwe,'wasc':str(a.get('wascid')) if str(a.get('wascid','')).isdigit() else None,
            'attack':evidence_digest(a.get('attack','')),'evidence':evidence_digest(a.get('evidence','')),
            'description':'Current ZAP scanner observation. Successful exploitation is not established.',
            'solution':text(a.get('solution',''))[:2000],
            'reference':'https://www.zaproxy.org/docs/alerts/'+plugin+'/',
            'assessment_id':aid,'session_id':aid,'scan_id':scan_id if source=='ZAP_ACTIVE' else None,
            'cqi_mapping':'MAPPED_EXISTING_CONTROL' if mapping else 'UNMAPPED',
            'original_confidence_not_project_confirmation':True}
        findings.append(row(fid,category,title,'DISMISSED' if confirmation=='FALSE_POSITIVE' else 'FAIL',severity,confirmation,
            source,aid,at,weakness_key=fid if mapping else key,source_rule_id=plugin,
            source_finding_id=stable_id('zap-alert',[aid,source,key,a.get('id')]),
            affected_asset=target.target_url,affected_component='Authorized web application',
            semantic_scope='DAST_OBSERVATION; no successful-exploitation claim',
            source_severity=risk,source_confidence=confidence,url=sanitized_url(url),
            cqi_mapping=sanitized['cqi_mapping'],parameter=param,method=method,zap_details=sanitized,
            evidence=sanitized,recommendation=sanitized['solution'] or 'Review the current scanner evidence and relevant control.',
            explanation=sanitized['description']))
    return findings,excluded
