"""Five specialized deterministic agents. AI inference lives in Behavioral tools.

No LLM request is made or simulated. Each role has an explicit tool allow-list.
"""
from .models import AgentResult


class Specialist:
    agent_id = None
    tools = ()
    dependencies = ()
    responsibility = ''

    def run(self, context):
        outputs=[]
        for name in self.tools:
            outputs.append(context.invoke(self.agent_id,name))
        evidence={ref.ref_id:ref for out in outputs for ref in out.evidence}
        return AgentResult(agent=self.agent_id,summary=outputs[-1].summary,
                           tools_used=list(self.tools),evidence=list(evidence.values()))


class NativeSecurityAgent(Specialist):
    agent_id='native'
    tools=('native.read_baseline','native.map_controls')
    responsibility='Acquire Native through existing authorized posture workflow or explicit saved evidence; preserve findings and map controls.'


class ZapSecurityAgent(Specialist):
    agent_id='zap'
    tools=('zap.read_assessment','zap.check_profile')
    responsibility='Join the same authorized existing posture/ZAP job or inspect explicit saved evidence; verify scope, profile and provenance.'


class BehavioralDetectionAgent(Specialist):
    agent_id='behavioral'
    tools=('behavior.extract_features','behavior.infer','behavior.explain_incidents')
    responsibility='Resolve actual 83-column vectors; run frozen OCSVM/XGBoost; generate native TreeSHAP and incidents.'


class EvidenceVerificationAgent(Specialist):
    agent_id='verification'
    tools=('verify.artifacts','verify.consistency','verify.journal')
    dependencies=('native','zap','behavioral')
    responsibility='Independently verify hashes/provenance, messages/record consistency, freshness, duplication and journal integrity.'


class CybersecurityQualityAgent(Specialist):
    agent_id='quality'
    tools=('quality.evaluate','quality.check_result')
    dependencies=('verification',)
    responsibility='Gate on verification, call unchanged CQI policy and independently check the result against the existing replay API.'


AGENTS=(NativeSecurityAgent,ZapSecurityAgent,BehavioralDetectionAgent,EvidenceVerificationAgent,CybersecurityQualityAgent)


def specifications():
    return [{'agent':'coordinator','tools':[],'dependencies':[],
             'responsibility':'Only dispatch, dependencies, budgets, durable state and final delivery; no security analysis.'}]+[
        {'agent':a.agent_id,'tools':list(a.tools),'dependencies':list(a.dependencies),'responsibility':a.responsibility}
        for a in AGENTS]
