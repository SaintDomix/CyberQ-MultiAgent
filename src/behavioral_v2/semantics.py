"""Label-independent Moodle adapter; generic models consume only numerical rows."""
import re
from urllib.parse import urlsplit, unquote

CATEGORIES = ('AUTH_LOGIN', 'AUTH_LOGOUT', 'DASHBOARD', 'COURSE_VIEW',
              'QUIZ_ACTIVITY', 'PROFILE', 'ADMIN', 'AJAX_SERVICE', 'STATIC_ASSET',
              'THEME_RESOURCE', 'APPLICATION_API', 'OTHER_NAVIGATION', 'UNKNOWN')
ASSETS = {'STATIC_ASSET', 'THEME_RESOURCE'}


def classify(path):
    """Exact mounted /moodle rules, ordered specific before general. No query use."""
    p = unquote(urlsplit(path).path).lower()
    if not p.startswith('/moodle/') and p != '/moodle':
        return 'UNKNOWN'
    p = p[len('/moodle'):]
    if p == '/login/index.php': return 'AUTH_LOGIN'
    if p == '/login/logout.php': return 'AUTH_LOGOUT'
    if p.startswith('/lib/ajax/'): return 'AJAX_SERVICE'
    if p.startswith('/theme/'): return 'THEME_RESOURCE'
    if p.startswith('/webservice/') or p.startswith('/api/'): return 'APPLICATION_API'
    if p.startswith('/admin/') or p.startswith('/report/'): return 'ADMIN'
    if p.startswith('/mod/quiz/'): return 'QUIZ_ACTIVITY'
    if p in ('/user/profile.php', '/user/view.php'): return 'PROFILE'
    if p == '/course/view.php': return 'COURSE_VIEW'
    if p in ('/my/', '/my/index.php'): return 'DASHBOARD'
    if (re.search(r'\.(?:css|js|png|jpg|jpeg|gif|svg|ico|woff2?|ttf|map)$', p)
            or p.startswith(('/lib/javascript.php', '/lib/requirejs.php', '/lib/polyfills/'))):
        return 'STATIC_ASSET'
    if p in ('', '/', '/index.php') or p.endswith('.php'):
        return 'OTHER_NAVIGATION'
    return 'UNKNOWN'


def semantic_features(events, seconds=10):
    categories = [classify(e.path) for e in events]
    n = len(events)
    if not n: raise ValueError('Nonempty window required')
    assets = sum(c in ASSETS for c in categories)
    ajax = categories.count('AJAX_SERVICE')
    nav = [e for e, c in zip(events, categories)
           if c not in ASSETS | {'AJAX_SERVICE', 'APPLICATION_API', 'UNKNOWN'}]
    semantic = [e for e, c in zip(events, categories) if c not in ASSETS]
    unique = len({e.path for e in semantic})
    return {k: float(v) for k, v in {
        'semantic_request_count': len(semantic), 'semantic_request_rate': len(semantic)/seconds,
        'asset_request_count': assets, 'asset_request_rate': assets/seconds, 'asset_ratio': assets/n,
        'navigation_count': len(nav), 'semantic_navigation_ratio': len(nav)/n,
        'auth_request_count': sum(c in ('AUTH_LOGIN', 'AUTH_LOGOUT') for c in categories),
        'logout_request_count': categories.count('AUTH_LOGOUT'),
        'dashboard_request_count': categories.count('DASHBOARD'),
        'course_view_request_count': categories.count('COURSE_VIEW'),
        'quiz_request_count': categories.count('QUIZ_ACTIVITY'),
        'profile_request_count': categories.count('PROFILE'),
        'theme_request_count': categories.count('THEME_RESOURCE'),
        'unknown_semantic_ratio': categories.count('UNKNOWN')/n,
        'semantic_unique_path_count': unique,
        'semantic_unique_path_ratio': unique/max(len(semantic), 1),
        'successful_response_ratio': sum(200 <= e.status < 300 for e in events)/n,
    }.items()}
