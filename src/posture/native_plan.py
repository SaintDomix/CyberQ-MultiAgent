"""Finite native read-only request plan, separate from the five-page ZAP policy."""
from dataclasses import dataclass
from .policy import PassivePolicy, TARGET

VERSION = 'branch1-native-safe-plan-1.1'
ORIGIN = 'https://scanner-test.invalid'  # Header value only; never a destination.
PUBLIC_PAGES = ('', 'login/index.php', 'my/', 'course/', 'admin/')
ACCESS_PAGES = ('admin/environment.php', 'report/security/index.php', 'admin/tool/health/')
ARTIFACT_PAGES = ('README.txt', 'lib/upgrade.txt', 'composer.json', 'package.json', 'phpunit.xml.dist', 'Gruntfile.js')
ROOT_EXPOSURES = ('/server-status', '/phpinfo.php', '/.git/HEAD', '/.env', '/composer.lock', '/vendor/composer/installed.json')
DIRECT_GET_URLS = tuple(sorted({TARGET+p for p in PUBLIC_PAGES+ACCESS_PAGES+ARTIFACT_PAGES+
    ('install.php', 'moodledata/', '__security_assessment_nonexistent_7f4a9c')} |
    {'http://192.168.226.132'+p for p in ROOT_EXPOSURES+('/moodledata/',)}))
REDIRECT_ONLY_URLS = (TARGET+'admin/index.php', TARGET+'admin/index.php?lang=en', TARGET+'admin/index.php?cache=1')
HEADER_VARIANTS = (
    ('GET', TARGET, {'Origin':ORIGIN}),
    ('OPTIONS', TARGET, {}),
    ('OPTIONS', TARGET, {'Origin':ORIGIN, 'Access-Control-Request-Method':'POST', 'Access-Control-Request-Headers':'X-Scanner-Test'}),
    ('TRACE', TARGET, {}),
)
# Same four-iteration redirect rule as the accepted client: initial + three hops.
MAX_REDIRECT_HOPS = 3
PLANNED_REQUESTS = len(DIRECT_GET_URLS) + len(HEADER_VARIANTS)
# Plain GET redirects reuse any already collected planned URL. Only these three
# additional reviewed destinations can be new. Four method/header variants may
# each need their own three redirect hops; their responses are never mixed.
REDIRECT_ALLOWANCE = len(REDIRECT_ONLY_URLS) + len(HEADER_VARIANTS)*MAX_REDIRECT_HOPS
MAX_REQUESTS = PLANNED_REQUESTS + REDIRECT_ALLOWANCE
REQUEST_SECONDS = 8
COLLECTOR_SECONDS = 15
BOOKKEEPING_MARGIN_SECONDS = 5
MAX_DURATION_SECONDS = MAX_REQUESTS*REQUEST_SECONDS + COLLECTOR_SECONDS + BOOKKEEPING_MARGIN_SECONDS


def request_plan():
    return [{'method':'GET','url':u,'headers':{}} for u in DIRECT_GET_URLS] + [
        {'method':m,'url':u,'headers':dict(h)} for m,u,h in HEADER_VARIANTS]


def budget():
    return {'version':VERSION, 'planned_unique_requests':PLANNED_REQUESTS,
        'planned_plain_gets':len(DIRECT_GET_URLS), 'method_header_variants':len(HEADER_VARIANTS),
        'redirect_only_destinations':list(REDIRECT_ONLY_URLS), 'max_redirect_hops':MAX_REDIRECT_HOPS,
        'redirect_allowance':REDIRECT_ALLOWANCE, 'max_requests':MAX_REQUESTS,
        'per_request_seconds':REQUEST_SECONDS, 'internal_collector_seconds':COLLECTOR_SECONDS,
        'bookkeeping_margin_seconds':BOOKKEEPING_MARGIN_SECONDS,
        'max_duration_seconds':MAX_DURATION_SECONDS, 'request_plan':request_plan(),
        'cache_scope':'ONE_ANONYMOUS_ASSESSMENT; method + URL + explicit headers; completed responses only',
        'sources':['src/branch1/external.py','src/branch1/external_rules/generic_rules.py',
                   'src/branch1/external_rules/moodle_rules.py','src/branch1/external_rules/cookies.py',
                   'src/branch1/external_rules/tls.py'],
        'internal_http_requests':0, 'zap_policy_unchanged':True}


@dataclass(frozen=True)
class NativeAssessmentPolicy(PassivePolicy):
    version: str = VERSION
    max_requests: int = MAX_REQUESTS
    max_duration_seconds: int = MAX_DURATION_SECONDS

    def __post_init__(self):
        # Reuse every closed safety predicate; only native request/time caps differ.
        values=self.export()
        values.update(max_requests=20,max_duration_seconds=60)
        PassivePolicy(**values)
        if not 1 <= self.max_requests <= MAX_REQUESTS or not 1 <= self.max_duration_seconds <= MAX_DURATION_SECONDS:
            raise ValueError('Native budget exceeds the calculated safe request plan')
