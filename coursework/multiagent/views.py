"""Read-only projections of one persisted full task for existing product pages.

No latest-branch selection, inference, scoring or publication occurs here.
"""
from demo.backend.adapters import finding, observation
from demo.backend.privacy import sanitize


def assessment_view(state):
    tools=state.tool_outputs
    def data(name):return tools[name].data if name in tools else {}
    def refs(name):return [r.model_dump(mode='json') for r in tools[name].evidence] if name in tools else []
    native=data('native.read_baseline').get('rows',[])
    zap=data('zap.read_assessment')
    behavior=data('behavior.extract_features')
    predictions=data('behavior.infer').get('predictions',[])
    incidents=data('behavior.explain_incidents').get('incidents',[])
    members={rid:i['episode_id'] for i in incidents for rid in i['observation_ids']}
    package=behavior.get('model',{}).get('package_id')
    rows=behavior.get('rows',[])
    observations=[observation(p,members,package,features=rows[n]['features'] if n<len(rows) else None).model_dump(mode='json')
                  for n,p in enumerate(predictions)]
    target=zap.get('assessment',{}).get('target') or next((r.get('affected_asset') for r in native),None)
    context={'task_id':state.task_id,'assessment_id':state.task_id,'target':target or 'http://192.168.226.132/moodle/',
        'mode':state.request.mode,'status':state.status,'created_at':state.created_at,'updated_at':state.updated_at,
        'native_refs':refs('native.read_baseline'),'zap_refs':refs('zap.read_assessment'),
        'behavioral_refs':refs('behavior.extract_features'),'behavioral_snapshot':behavior.get('snapshot'),
        'underlying_posture_id':zap.get('assessment',{}).get('assessment_id'),
        'immutable':state.status in ('COMPLETED','FAILED','BLOCKED','TIMED_OUT','LIMIT_EXCEEDED','INTERRUPTED')}
    return sanitize({'schema_version':'coursework-assessment-view-1.0','context':context,
        'native':{'status':state.agents['native'],'findings':[finding(r).model_dump(mode='json') for r in native]},
        'zap':{'status':state.agents['zap'],'assessment':zap.get('assessment'),
               'findings':[finding(r).model_dump(mode='json') for r in zap.get('findings',[])]},
        'behavioral':{'status':state.agents['behavioral'],'observations':observations,'incidents':incidents,
                      'model':behavior.get('model'),'snapshot':behavior.get('snapshot'),
                      'availability':tools['behavior.extract_features'].summary if 'behavior.extract_features' in tools else None},
        'verification':[v.model_dump(mode='json') for v in state.verification],
        'execution':state.branch_executions.get('posture'),'result':state.result})
