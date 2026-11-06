"""Separate closed API surface for explicitly authorized DAST sessions."""
from .providers import ZapAPI

VIEWS={
 'core':{'version','mode','numberOfMessages','numberOfAlerts','urls','messages','childNodes'},'alert':{'alerts'},
 'autoupdate':{'installedAddons'},'ascan':{'scanners','scans','status','scanProgress','messagesIds','alertsIds'},
 'pscan':{'scanners','recordsToScan'},'spider':{'scans','status','results','fullResults','domainsAlwaysInScope'},
 'ajaxSpider':{'status','results','fullResults'},'clientSpider':{'status'},
 'stats':{'stats'},
 'context':{'contextList','context','technologyList','includedTechnologyList'},
 'authentication':{'getSupportedAuthenticationMethods'},
 'sessionManagement':{'getSupportedSessionManagementMethods'},
 'network':{'getRateLimitRules','getLocalServers'},
}
ACTIONS={
 'core':{'newSession','setMode','accessUrl'},
 'context':{'newContext','includeInContext','excludeFromContext','setContextInScope'},
 'ascan':{'addScanPolicy','removeScanPolicy','disableAllScanners','enableScanners','scan','stop','removeScan',
  'setOptionThreadPerHost','setOptionDelayInMs','setOptionMaxScanDurationInMins',
  'setOptionMaxRuleDurationInMins','setOptionHandleAntiCSRFTokens','setOptionPersistTemporaryMessages'},
 'pscan':{'setEnabled'},
 'spider':{'scan','stop','removeScan','disableAllDomainsAlwaysInScope','setOptionThreadCount','setOptionMaxDuration',
  'setOptionPostForm','setOptionProcessForm','setOptionLogoutAvoidance','setOptionMaxParseSizeBytes',
  'setOptionParseRobotsTxt','setOptionParseSitemapXml','setOptionMaxDepth','setOptionMaxChildren'},
 'ajaxSpider':{'scan','stop','setOptionMaxDuration','setOptionNumberOfBrowsers','setOptionBrowserId',
  'setOptionLogoutAvoidance','setOptionRandomInputs','setOptionScopeCheck'},
 'clientSpider':{'scan','stop'},
 'network':{'addRateLimitRule','removeRateLimitRule'},
 'openapi':{'importUrl'},'graphql':{'importUrl'},'soap':{'importUrl'},'postman':{'importUrl'},
}


class FullZapAPI:
    def __init__(self, passive_api, target):
        if not isinstance(passive_api,ZapAPI):raise ValueError('Explicit loopback transport required')
        self.transport=ZapAPI(passive_api.origin,passive_api.key)
        self.origin=passive_api.origin;self.target=target
        self.owned_scans={};self.context_name=None;self.context_id=None;self.policy_name=None
    def call(self,component,kind,name,control_deadline=None,**params):
        self.last_call=(component,kind,name)
        surface=VIEWS if kind=='view' else ACTIONS if kind=='action' else {}
        option_read=(kind=='view' and name.startswith('option') and
            'setOption'+name[6:] in ACTIONS.get(component,set()))
        if name not in surface.get(component,set()) and not option_read:raise ValueError('Unapproved full-profile API')
        if kind=='action':
            if name=='setMode' and params!={'mode':'protect'} and params!={'mode':'safe'}:
                raise ValueError('Only protected/safe transitions permitted')
            if name=='newSession' and params:raise ValueError('Only volatile unnamed sessions')
            if name=='accessUrl' and params.get('followRedirects')!='false':raise ValueError('Seed redirects are not followed')
            for key in ('url','endurl'):
                if key in params and not self.target.contains(params[key]):raise ValueError('Off-target API URL')
            if name=='scan':
                if component not in ('ascan','spider','ajaxSpider','clientSpider'):raise ValueError('Unapproved scan')
                if component=='ascan' and (not self.context_id or params.get('contextId')!=self.context_id or params.get('scanPolicyName')!=self.policy_name
                    or params.get('inScopeOnly')!='true' or params.get('postData')):
                    raise ValueError('Active scan requires owned explicit scope and policy')
                if component=='spider' and (params.get('contextName')!=self.context_name or params.get('subtreeOnly')!='true'):
                    raise ValueError('Spider requires owned application context')
                if component in ('clientSpider','ajaxSpider') and (params.get('contextName')!=self.context_name or params.get('subtreeOnly')!='true'):
                    raise ValueError('Browser discovery requires owned application scope')
            if name in ('stop','removeScan'):
                if component not in self.owned_scans or (component!='ajaxSpider' and params.get('scanId')!=self.owned_scans[component]):
                    raise ValueError('Refuse to stop unrelated scan')
            if component=='context' and name=='includeInContext' and params.get('regex')!=self.target.include_regex:
                raise ValueError('Scope expansion rejected')
            if component=='context' and params.get('contextName')!=self.context_name:
                raise ValueError('Only this assessment context may be modified')
            if component=='context' and name=='excludeFromContext' and params.get('regex') not in self.target.exclusions:
                raise ValueError('Unconfigured exclusion')
        if component=='core' and name=='messages':
            if not str(params.get('start','')).isdigit() or params.get('count') not in ('1','10'):raise ValueError('Bounded history pages only')
        if component=='core' and name=='childNodes':
            url=params.get('url','')
            if url!=self.target.target_url.rstrip('/') and not self.target.contains(url):raise ValueError('Off-scope metadata URL')
        if component=='stats' and params!={'keyPrefix':'stats.ascan.'}:raise ValueError('Only active-scan counters permitted')
        return self.transport._fetch(component,kind,name,control_deadline,**params)
    def close(self):self.transport.session.close()
