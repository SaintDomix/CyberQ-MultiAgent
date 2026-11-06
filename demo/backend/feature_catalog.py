"""Reviewed display semantics, traced to frozen extractors; never model inputs.

Counts are per nonempty 10-second window. Ratios use all requests unless the
definition explicitly says otherwise. No descriptions are inferred for unknown keys.
"""

CATALOG = {}


def add(group, unit, definitions, source='src/branch2/features.py:extract', classes=()):
    for name, label, definition in definitions:
        CATALOG[name] = dict(feature=name, label=label, group=group, unit=unit,
            definition=definition, source=source, verified=True, human_readable=True,
            directions=['HIGH', 'LOW'], ratio_to_baseline=unit in ('count', 'requests/s', 'seconds', 'bytes', 'characters'),
            comparison='percentage points' if unit == 'fraction' else 'absolute difference or positive-median ratio',
            formatter='numeric_reference_v1', relevant_classes=list(classes))


add('TRAFFIC_RATE','count', [('request_count','Requests','Number of observed requests')], classes=['REQUEST_BURST_DOS_LIKE'])
add('TRAFFIC_RATE','requests/s', [('request_rate','Request rate','Request count divided by the fixed 10-second window')], classes=['REQUEST_BURST_DOS_LIKE'])
add('TIMING','seconds', [
    ('active_span','Observed activity span','Last minus first request timestamp'),
    ('mean_inter_request','Mean request gap','Mean adjacent timestamp difference; zero for one request'),
    ('min_inter_request','Minimum request gap','Minimum adjacent timestamp difference; zero for one request'),
    ('max_inter_request','Maximum request gap','Maximum adjacent timestamp difference; zero for one request'),
    ('std_inter_request','Request-gap variability','Population standard deviation of adjacent timestamp differences; zero for one request')], classes=['REQUEST_BURST_DOS_LIKE'])
add('PATH_BEHAVIOR','count', [
    ('unique_paths','Distinct request paths','Count of distinct parsed paths; query values excluded'),
    ('resource_breadth','Distinct parent paths','Count of distinct path prefixes before the final slash')], classes=['ENUMERATION_RECONNAISSANCE'])
add('PATH_BEHAVIOR','fraction', [('unique_path_ratio','Distinct-path ratio','Distinct paths divided by requests')], classes=['ENUMERATION_RECONNAISSANCE'])
add('REPETITION','fraction', [
    ('repeated_path_ratio','Repeated-path share','(Requests minus distinct paths) divided by requests'),
    ('path_repetition_ratio','Most-used path share','Maximum requests to one path divided by requests')], classes=['BRUTE_FORCE','SQLI_ATTEMPT'])
add('REPETITION','count', [('max_requests_same_path','Requests to the most-used path','Largest request count for a single parsed path')], classes=['BRUTE_FORCE','SQLI_ATTEMPT'])
semantic_source='src/behavioral_v2/features31.py:extract; src/behavioral_v2/platforms.py:MoodleBehaviorAdapter.map_request'
for prefix,label,categories,group,classes in [
    ('login','Authentication-path','AUTH_LOGIN or AUTH_LOGOUT','AUTH_BEHAVIOR',['BRUTE_FORCE']),
    ('admin','Administrative-path','ADMIN_ACTION','ADMIN_BEHAVIOR',['ADMIN_PROBING']),
    ('ajax','AJAX-service','AJAX_SERVICE','RESOURCE_BEHAVIOR',[]),
    ('api','Application-API','APPLICATION_API','RESOURCE_BEHAVIOR',[])]:
    add(group,'count',[(prefix+'_request_count',label+' requests','Count of requests mapped to '+categories+'; no authentication outcome inferred')],semantic_source,classes)
    add(group,'fraction',[(prefix+'_request_ratio',label+' request share','Requests mapped to '+categories+' divided by all requests')],semantic_source,classes)
for method,label in [('get','GET'),('post','POST'),('other_method','Methods other than GET/POST')]:
    add('METHOD_BEHAVIOR','count',[(method+'_count',label+' requests','Request count for '+label+'; no request-body visibility')])
    add('METHOD_BEHAVIOR','fraction',[(method+'_ratio',label+' share','Request count for '+label+' divided by requests')])
for family,label in [(1,'1xx'),(2,'2xx'),(3,'3xx'),(4,'4xx'),(5,'5xx')]:
    add('STATUS_CODES','count',[(f'status_{family}xx_count',label+' responses','Count with HTTP status in '+label+' family')])
add('STATUS_CODES','fraction', [
    ('redirect_ratio','3xx response share','3xx responses divided by requests; not proof a redirect was followed'),
    ('client_error_ratio','4xx response share','4xx responses divided by requests'),
    ('server_error_ratio','5xx response share','5xx responses divided by requests'),
    ('error_ratio','4xx/5xx response share','4xx and 5xx responses divided by requests')])
add('RESPONSE_SIZE','bytes', [
    ('response_bytes_total','Total observed response bytes','Sum of nonmissing logged response sizes'),
    ('response_bytes_mean','Mean observed response size','Mean of nonmissing logged response sizes; zero if none'),
    ('response_bytes_max','Largest observed response','Maximum nonmissing logged response size; zero if none'),
    ('response_bytes_std','Response-size variability','Population standard deviation of nonmissing sizes; zero if none')])
add('OBSERVABILITY','fraction',[('response_bytes_observed_ratio','Response-size coverage','Fraction with nonmissing logged response bytes')])
add('QUERY_BEHAVIOR','count', [
    ('query_present_count','Requests with a query string','Number with a nonempty query string'),
    ('parameter_count_total','Query parameters','Total parse_qsl pairs, including blank values'),
    ('url_encoded_count','Percent-encoded query triplets','Count of percent plus two hexadecimal characters in raw queries')],classes=['SQLI_ATTEMPT','XSS_ATTEMPT'])
add('QUERY_BEHAVIOR','fraction', [
    ('query_present_ratio','Query-bearing request share','Nonempty-query requests divided by requests'),
    ('url_encoded_ratio','Encoded query-character share','Three times percent-encoded triplet count divided by total raw query length'),
    ('special_character_ratio','Query punctuation share','Non-alphanumeric, non-whitespace characters divided by decoded query characters')],classes=['SQLI_ATTEMPT','XSS_ATTEMPT'])
add('QUERY_BEHAVIOR','characters', [
    ('query_length_mean','Mean raw query length','Mean raw query length across all requests'),
    ('query_length_max','Longest raw query','Maximum raw query length')],classes=['SQLI_ATTEMPT','XSS_ATTEMPT'])
add('QUERY_BEHAVIOR','parameters/request', [('parameter_count_mean','Query parameters per request','Total query pairs divided by all requests')],classes=['SQLI_ATTEMPT'])
for name,label,definition,classes,group in [
    ('quote_count','Query quote characters','Single/double quote count after at most two URL-decode passes',['SQLI_ATTEMPT'],'QUERY_SYNTAX'),
    ('comment_sequence_count','Query comment-like sequences','Count of --, /*, */, or # after query decoding',['SQLI_ATTEMPT'],'QUERY_SYNTAX'),
    ('sql_token_count','SQL-related query indicators','Regex count of SQL keywords or OR numeric-equality patterns; URL query only',['SQLI_ATTEMPT'],'SQL_PATTERNS'),
    ('xss_marker_count','Script/HTML-related query indicators','Regex count of script/svg/img opening tags, javascript: or onerror/onload/onclick assignments; URL query only',['XSS_ATTEMPT'],'XSS_PATTERNS'),
    ('traversal_count','Traversal-like path/query indicators','Count of dot-dot slash/backslash in path plus query after two decode passes',['PATH_TRAVERSAL_ATTEMPT'],'TRAVERSAL_PATTERNS')]:
    add(group,'count',[(name,label,definition+'; lexical evidence, not successful exploitation')],classes=classes)
add('SUSPICIOUS_PATTERNS','fraction',[('suspicious_query_ratio','Lexical-indicator request share','Requests with any quote/comment/SQL/XSS/traversal indicator divided by all requests; can include benign syntax')])
for prefix,plural,field in [('identity','users','authenticated_user_id'),('session','sessions','session_id'),('role','roles','role')]:
    add('OBSERVABILITY','fraction',[(prefix+'_observed_ratio',prefix.title()+' metadata coverage','Fraction with nonmissing optional '+field)])
    add('IDENTITY_METADATA','count',[('unique_'+plural,'Distinct observed '+plural,'Distinct nonmissing optional '+field+' values; no identity inferred')])
    if prefix!='role':
        add('IDENTITY_METADATA','requests/identity',[('requests_per_'+('user' if prefix=='identity' else 'session')+'_mean','Requests per observed '+('user' if prefix=='identity' else 'session'),'Nonmissing '+field+' observations divided by distinct values; zero if none')])
add('IDENTITY_METADATA','fraction',[('privileged_role_request_ratio','Explicit privileged-role share','Requests with explicit administrator/manager role divided by all requests; role never inferred from URL')])
for name,label,definition,group,classes in [
    ('semantic_request_count','Non-asset requests','All requests except STATIC_ASSET; includes UNKNOWN','TRAFFIC_RATE',[]),
    ('asset_request_count','Static-asset requests','STATIC_ASSET requests, including theme resources','RESOURCE_BEHAVIOR',[]),
    ('navigation_count','Canonical navigation requests','Excludes STATIC_ASSET, AJAX_SERVICE, APPLICATION_API and UNKNOWN','NAVIGATION',[]),
    ('auth_request_count','Authentication-path requests','AUTH_LOGIN plus AUTH_LOGOUT; no success/failure inferred','AUTH_BEHAVIOR',['BRUTE_FORCE']),
    ('logout_request_count','Logout-path requests','AUTH_LOGOUT requests','AUTH_BEHAVIOR',[]),
    ('dashboard_request_count','Dashboard requests','DASHBOARD requests','NAVIGATION',[]),
    ('course_view_request_count','Course-view requests','COURSE_VIEW requests','NAVIGATION',[]),
    ('quiz_request_count','Quiz-activity requests','QUIZ_ACTIVITY requests','NAVIGATION',[]),
    ('profile_request_count','Profile requests','PROFILE requests','NAVIGATION',[]),
    ('theme_request_count','Theme-resource requests','Canonical STATIC_ASSET with THEME subtype','RESOURCE_BEHAVIOR',[]),
    ('semantic_unique_path_count','Distinct non-asset paths','Distinct paths among all non-STATIC_ASSET requests','PATH_BEHAVIOR',['ENUMERATION_RECONNAISSANCE'])]:
    add(group,'count',[(name,label,definition)],semantic_source,classes)
add('TRAFFIC_RATE','requests/s',[('semantic_request_rate','Non-asset request rate','Non-STATIC_ASSET request count divided by 10')],semantic_source,['REQUEST_BURST_DOS_LIKE'])
add('RESOURCE_BEHAVIOR','requests/s',[('asset_request_rate','Static-asset request rate','STATIC_ASSET request count divided by 10')],semantic_source)
for name,label,definition,group in [
    ('asset_ratio','Static-asset share','STATIC_ASSET count divided by all requests','RESOURCE_BEHAVIOR'),
    ('semantic_navigation_ratio','Canonical navigation share','Navigation count divided by all requests','NAVIGATION'),
    ('unknown_semantic_ratio','Unmapped semantic share','UNKNOWN count divided by all requests','OBSERVABILITY'),
    ('semantic_unique_path_ratio','Distinct non-asset path ratio','Distinct non-asset paths divided by non-asset requests; zero if none','PATH_BEHAVIOR'),
    ('successful_response_ratio','2xx response share','2xx count divided by all requests; not authentication success','STATUS_CODES')]:
    add(group,'fraction',[(name,label,definition)],semantic_source)


def catalog_entry(name):
    return CATALOG.get(name, dict(feature=name, verified=False, human_readable=False, group='OTHER'))
