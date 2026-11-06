import React from 'react';
import {stamp,human} from '../utils/data.js';
export function AssessmentContext({data,mode,replay,run,assessment,onMode,onReplay,onRun,onAssessment,scenarios=[],onScenario,onReset,lastPoll,compact=false,completenessInPage=false}){
 const selection=data?.selection,status=data?.status;
 const accepted=mode==='ACCEPTED_REPLAY',historical=selection?.historical_selection;
 const completed=(data?.history||[]).filter(j=>['COMPLETE','PARTIAL'].includes(j.status));
 if(assessment&&data?.assessment&&!completed.some(j=>j.assessment_id===assessment))completed.unshift(data.assessment);
 const context=accepted?'ACCEPTED EVIDENCE REPLAY':historical?'HISTORICAL POSTURE':'CURRENT LAB EVIDENCE';
 const profile=selection?.profile||(!accepted?human(selection?.latest_attempt_status||'NO_COMPLETED_CURRENT_POSTURE'):'Loading…');
 const collected=selection?.posture_completed_at||(accepted?status?.as_of:null);
 const controls=<>
 <div className="context-selectors"><label>Evidence view<select aria-label="Evidence view" value={mode} onChange={e=>onMode(e.target.value)}><option value="LIVE_LAB">Current assessment</option><option value="ACCEPTED_REPLAY">Accepted research evidence</option></select></label>
 {!accepted?<label>Posture snapshot<select aria-label="Posture snapshot" value={assessment} onChange={e=>onAssessment(e.target.value)}><option value="">Latest completed evidence · job state separate</option>{completed.map(j=><option key={j.assessment_id} value={j.assessment_id}>{j.assessment_id} · {j.assessment_profile||j.mode} · {j.status}</option>)}</select></label>:<><label>Evaluation set<select aria-label="Evaluation set" value={replay} onChange={e=>onReplay(e.target.value)}><option value="BENIGN_TEST">Blind benign browser evidence</option><option value="ATTACK_HOLDOUT">Controlled attack-pattern holdout</option></select></label><label>Run / session<select aria-label="Run / session" value={run} onChange={e=>onRun(e.target.value)}><option value="">All accepted runs</option>{status?.runtime.available_runs?.map(id=><option key={id}>{id}</option>)}</select></label></>}
 <details className="context-details"><summary>Source details</summary><p>{selection?.assessment_id||(accepted?'Immutable accepted research source':'No completed current posture assessment')}</p><p>{historical?'Historical posture only; Behavioral snapshot not paired.':accepted?'Saved predictions; no new model execution.':human(status?.runtime?.process_state)+' · last observation '+stamp(status?.runtime?.last_observation)}</p><p>Scoring clock: {data?.scientific_cqi?.as_of||'Unavailable'} · {selection?.as_of_semantics}</p><small>Last UI update {lastPoll?.toLocaleTimeString()||'Pending'}. A UI poll is not new evidence.</small></details></div>
 {!accepted&&<small>Failed, interrupted and incomplete attempts remain in Security posture → Assessment history.</small>}
 {accepted&&<div className="replay-shortcuts"><button className="text-button" onClick={onReset}>Reset to all accepted runs</button><small>Resets view selection to the full accepted attack holdout; does not execute replay or change operating mode.</small></div>}
 {accepted&&scenarios.length>0&&<details className="scenario-details"><summary>Explore accepted explanation examples</summary><div className="cell-actions">{scenarios.map(s=><button className="button" key={s.id} onClick={()=>onScenario(s)}>{s.title}</button>)}</div></details>}
 </>;
 return <section className={'assessment-context '+(compact?'compact-context':'')} aria-label="Evidence context">
 <div className="context-primary"><div><strong>{status?.target?.name||'Select evidence context'}</strong><span>{selection?.target||status?.target?.base_url||'Awaiting source'}</span></div>
 <div><span>{context}</span><strong>{accepted?replay==='BENIGN_TEST'?'Blind benign evaluation':'Attack-pattern holdout':human(profile)}</strong></div><div><span>{selection?.posture_completed_at?'Collected':accepted?'Evidence as of':'Collection time'}</span><strong>{collected?stamp(collected):'No completed collection'}</strong></div>{!completenessInPage&&<span className="context-completeness">{human(data?.scientific_cqi?.overall_status||'LEGACY / LOADING').toLowerCase().replace(/^./,c=>c.toUpperCase())}</span>}</div>
 {compact?<details className="context-change"><summary>Change evidence</summary>{controls}</details>:controls}
 </section>;
}
