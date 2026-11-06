"""Two-level candidate security semantics, with explicit persistence trade-offs."""
from collections import defaultdict
from branch2.events import utc
from branch2.final_pipeline import binary


def episodes(predictions, persistence):
    if persistence not in (1,2,3): raise ValueError('Predeclared persistence grid is 1/2/3')
    grouped=defaultdict(list)
    for p in predictions:
        grouped[(p['run_id'],p.get('client_id'),p.get('user_agent_id'))].append(p)
    result=[]
    for key,rows in sorted(grouped.items(),key=lambda pair:str(pair[0])):
        pending=[]
        def flush():
            if not pending: return
            decision=pending[0]['reconciliation']['decision']
            known=decision not in ('BENIGN','UNKNOWN_ANOMALY','UNCERTAIN')
            state=('KNOWN_THREAT_ATTEMPT_EPISODE' if known else
                   'UNKNOWN_ANOMALY_EPISODE' if decision=='UNKNOWN_ANOMALY' and len(pending)>=persistence else
                   'NOVEL_OBSERVATION' if decision in ('UNKNOWN_ANOMALY','UNCERTAIN') else 'BENIGN')
            result.append({'run_id':key[0],'client_id':key[1],'user_agent_id':key[2],
                'start':pending[0]['window_start'],'end':pending[-1]['window_end'],
                'behavior_class':decision,'state':state,'member_count':len(pending),
                'member_window_starts':[r['window_start'] for r in pending],
                'member_record_ids':[r.get('record_id') for r in pending],
                'alert':state in ('KNOWN_THREAT_ATTEMPT_EPISODE','UNKNOWN_ANOMALY_EPISODE'),
                'model_disagreement_visible':any(r['reconciliation']['model_disagreement'] for r in pending),
                'successful_exploitation_confirmed':False})
        for p in sorted(rows,key=lambda r:(r['window_start'],r['window_end'])):
            if pending and (p['reconciliation']['decision']!=pending[-1]['reconciliation']['decision'] or utc(p['window_start'])!=utc(pending[-1]['window_end'])):
                flush();pending=[]
            pending.append(p)
        flush()
    return result


def episode_metrics(predictions,persistence):
    es=episodes(predictions,persistence)
    groups=defaultdict(list)
    for p in predictions:groups[p['run_id']].append(p)
    ids=sorted(groups)
    # A capture is an independently labelled protocol, not a labelled alert
    # interval. Report any-alert per run, not fabricated episode ground truth.
    result=binary([groups[k][0]['label']!='BENIGN' for k in ids],
                  [any(e['alert'] and e['run_id']==k for e in es) for k in ids])
    result.update(alert_episodes=sum(e['alert'] for e in es),
        benign_alert_episodes=sum(e['alert'] and groups[e['run_id']][0]['label']=='BENIGN' for e in es),
        unit='independent run: any emitted alert episode; true episode intervals unavailable')
    return result


def select_persistence(validation_predictions):
    if not validation_predictions or any(p.get('partition')!='VALIDATION' for p in validation_predictions):
        raise ValueError('Persistence selected only using VALIDATION')
    choices=[{'persistence':n,'validation':episode_metrics(validation_predictions,n)} for n in (1,2,3)]
    # First minimize false-alert BENIGN runs, then maximize attack-run recall,
    # then shortest delay. This may leave persistence=1 if known-pattern false
    # positives dominate; the negative result must remain visible.
    chosen=max(choices,key=lambda c:(-c['validation']['FPR'],c['validation']['recall'] or 0,-c['persistence']))
    return {**chosen,'candidates':choices,'selection_partition':'VALIDATION',
            'selection':'min benign any-alert run FPR; max attack run recall; shortest persistence'}
