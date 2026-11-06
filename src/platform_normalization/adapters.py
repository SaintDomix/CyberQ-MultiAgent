"""Platform enrichment reuses frozen semantic adapters; generic is the default."""
from typing import Protocol
from pathlib import Path
import hashlib
from urllib.parse import unquote,urlsplit
from behavioral_v2.platforms import GenericHTTPBehaviorAdapter, MoodleBehaviorAdapter, MoodleAuditAdapter,SemanticRequest
from .schema import digest


class ConservativeGenericSemantics(GenericHTTPBehaviorAdapter):
    """Reuse known asset/declared semantics; do not infer navigation from an unknown route."""
    adapter_version = 'generic-web-unknown-fallback-1.0'

    def map_request(self,path,method='GET'):
        result=super().map_request(path,method)
        known=unquote(urlsplit(path).path) in self.routes
        return SemanticRequest('UNKNOWN') if result.category=='OTHER_NAVIGATION' and not known else result


class PlatformAdapter(Protocol):
    platform_id: str
    def identity(self) -> dict: ...
    def semantic_adapter(self): ...
    def capabilities(self) -> dict: ...


class GenericWebPlatformAdapter:
    platform_id = 'generic_web'

    def __init__(self, routes=None):
        self.semantic = ConservativeGenericSemantics(routes)

    def identity(self):
        semantics=self.semantic.identity()
        semantics['source_identity_sha256']=semantics.pop('sha256')
        routes=semantics.pop('routes',{})
        semantics.update(routes_sha256=digest(routes),route_count=len(routes),
            raw_route_configuration_exported=False)
        semantics['metadata_sha256']=digest(semantics)
        return {'adapter_id': 'generic-web-platform-1.0', 'platform_id': self.platform_id,
                'version': '1.0', 'semantics': semantics, 'empirically_validated': False,
                'compatibility_implementation_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}

    def semantic_adapter(self): return self.semantic

    def capabilities(self):
        return {'platform_configuration': False, 'platform_advisories': False,
                'role_enrichment': False, 'reason': 'Generic HTTP telemetry cannot infer platform internals or roles.'}


class MoodleAdapter(GenericWebPlatformAdapter):
    platform_id = 'moodle'

    def __init__(self, mount='/moodle/'):
        self.semantic = MoodleBehaviorAdapter(mount)

    def identity(self):
        return super().identity() | {'adapter_id': 'moodle-compatibility-1.0',
            'empirically_validated': 'Moodle laboratory only; current collector prerequisites still apply',
            'reused_implementations': ['behavioral_v2.platforms.MoodleBehaviorAdapter',
                'behavioral_v2.platforms.MoodleAuditAdapter', 'posture.native.Branch1CurrentProvider',
                'branch1.internal.assess', 'branch1.intelligence.assess', 'branch1.roles.compare']}

    def capabilities(self):
        return {'platform_configuration': True, 'platform_advisories': True, 'role_enrichment': True,
                'reason': 'Implementations exist; requires fresh verified collector/baseline/role evidence, not historical verdicts.'}

    def audit_exporter(self, pseudonym_key): return MoodleAuditAdapter(pseudonym_key)


REGISTRY = {'generic_web': GenericWebPlatformAdapter, 'moodle': MoodleAdapter}


def adapter(platform='generic_web', **config):
    if platform not in REGISTRY: raise ValueError('Platform enrichment adapter not installed; use generic_web with a reviewed mapping')
    return REGISTRY[platform](**config)
