"""Prospectively declared ordinal policy; no fitted/calibrated parameters."""
from dataclasses import dataclass,field,asdict
import math
from fusion.schema import DIMENSIONS
from branch2.live_storage import digest

@dataclass(frozen=True)
class Policy:
    version:str='cqi-evidence-2.0'
    weights:dict=field(default_factory=lambda:{d:1/6 for d in DIMENSIONS})
    severity:dict=field(default_factory=lambda:{'INFO':0.,'LOW':.25,'MEDIUM':.5,'HIGH':.75,'CRITICAL':1.})
    reliability:dict=field(default_factory=lambda:{'CONFIRMED':1.,'VERSION_BASED':.7,'LIKELY':.5,'CONTEXTUAL':.25,'NOT_CONFIRMED':.35})
    partial_weakness:float=.5
    partial_observability:float=.5
    hazard_scale:float=math.log(2)
    compensation_points:float=20.
    missing_control_hazard:float=1.
    behavior:dict=field(default_factory=lambda:{'UNKNOWN_ANOMALY':.4,'ENUMERATION_RECONNAISSANCE':.5,'ADMIN_PROBING':.5,'BRUTE_FORCE':.75,'REQUEST_BURST_DOS_LIKE':.75,'SQLI_ATTEMPT':.75,'XSS_ATTEMPT':.75,'PATH_TRAVERSAL_ATTEMPT':.75})
    disagreement_support:float=.8
    behavior_horizon_seconds:int=300
    posture_max_age_seconds:int=86400

    def __post_init__(self):
        if self.version!='cqi-evidence-2.0':raise ValueError('Unknown policy version')
        if set(self.weights)!=set(DIMENSIONS) or any(not math.isfinite(v) or v<=0 for v in self.weights.values()):raise ValueError('Invalid dimension weights')
        if set(self.severity)!={'INFO','LOW','MEDIUM','HIGH','CRITICAL'}:raise ValueError('Invalid severity mapping')
        if set(self.reliability)!={'CONFIRMED','VERSION_BASED','LIKELY','CONTEXTUAL','NOT_CONFIRMED'}:raise ValueError('Invalid reliability vocabulary')
        if set(self.behavior)!={'UNKNOWN_ANOMALY','ENUMERATION_RECONNAISSANCE','ADMIN_PROBING','BRUTE_FORCE','REQUEST_BURST_DOS_LIKE','SQLI_ATTEMPT','XSS_ATTEMPT','PATH_TRAVERSAL_ATTEMPT'}:raise ValueError('Invalid accepted behavior vocabulary')
        if list(self.severity[k] for k in ('INFO','LOW','MEDIUM','HIGH','CRITICAL'))!=sorted(self.severity.values()):raise ValueError('Severity order')
        for values in (self.severity,self.reliability,self.behavior):
            if any(type(v) not in (int,float) or not math.isfinite(v) or not 0<=v<=1 for v in values.values()):raise ValueError('Invalid ordinal coefficient')
        if any(type(v) not in (int,float) or not math.isfinite(v) for v in (self.compensation_points,self.hazard_scale,self.missing_control_hazard,self.partial_observability,self.partial_weakness,self.disagreement_support)):
            raise ValueError('Nonfinite policy parameter')
        if not 0<=self.compensation_points<=100 or not 0<self.hazard_scale<=2 or not max(self.severity.values())<=self.missing_control_hazard<=2:raise ValueError('Invalid aggregation bound')
        if not 0<self.partial_observability<1 or not 0<self.partial_weakness<1 or not 0<self.disagreement_support<=1:raise ValueError('Invalid partial/support policy')
        if type(self.behavior_horizon_seconds) is not int or self.behavior_horizon_seconds<=0 or self.posture_max_age_seconds<=0:raise ValueError('Invalid temporal bounds')

    def export(self):
        value=asdict(self);return value|{'sha256':digest(value),'parameters_empirically_calibrated':False,'is_probability':False}

def aggregate(qualities,weights,method='guarded_geometric',guard=20):
    """Fixed applicable dimensions; unavailable lower inputs are zero, never dropped."""
    if not qualities:return None
    if any(not math.isfinite(v) or not 0<=v<=100 for v in qualities.values()):raise ValueError('Invalid quality')
    total=math.fsum(weights[d] for d in qualities)
    if method=='arithmetic':return math.fsum(weights[d]*q for d,q in qualities.items())/total
    geometric=0. if any(v==0 for v in qualities.values()) else math.exp(math.fsum(weights[d]*math.log(q/100) for d,q in qualities.items())/total)*100
    if method=='geometric':return geometric
    if method!='guarded_geometric':raise ValueError('Unknown aggregator')
    return min(geometric,min(qualities.values())+guard)
