import React,{useEffect,useState} from 'react';
import {api} from '../api/client.js';

const terminal=new Set(['COMPLETED','FAILED','TIMED_OUT','BLOCKED','LIMIT_EXCEEDED','INTERRUPTED']);
const percent=x=>x==null?'N/A':`${x.toFixed(2)}%`;
export function AgentTable({spec=[],state,compact=false}){
 const distribution=state?.distribution?.all_specialist_calls;
 return <div className="ma-scroll"><table><thead><tr><th>Agent</th>{!compact&&<th>Responsibility</th>}<th>State</th><th>Tools</th><th>Calls</th><th>Share</th></tr></thead><tbody>{spec.map(a=><tr key={a.agent}><th>{a.agent}</th>{!compact&&<td>{a.responsibility}</td>}<td>{state?.agents?.[a.agent]||'PENDING'}</td><td>{a.tools.length}</td><td>{distribution?.counts?.[a.agent]??(a.agent==='coordinator'?0:'—')}</td><td>{percent(distribution?.percentages?.[a.agent])}</td></tr>)}</tbody></table></div>
}
export function AssessmentHeadline({task}){
 const q=task?.result?.cqi,summary=task?.result?.assessment_summary;
 const verification=summary?.verification_status||'Not yet assessed';
 const snapshot=task?.result?.live_snapshot;
 const sourceNote=task?.request?.mode==='OFFLINE_EVIDENCE'?'Historical evidence · source limitations apply':
  snapshot?.session_id?`Captured owned snapshot · session ${snapshot.session_id} · ${summary?.behavior_windows??'unknown'} windows`:
  snapshot?.availability==='UNAVAILABLE'?`Behavioral monitoring unavailable · ${snapshot.reason||'No eligible windows'}`:'Awaiting an owned monitoring snapshot';
 return <div className="ma-headline" aria-label="Final assessment summary">
  <div className="ma-metric ma-score"><span>Final CQI</span><strong>{q?.overall==null?'Unavailable':q.overall.toFixed(4)}<small>{q?.overall!=null?' / 100':''}</small></strong><p>{q?.policy?.version||'Awaiting a completed assessment'} · Not an attack probability</p></div>
  <div className="ma-metric"><span>Evidence verification</span><strong className="ma-verdict" data-status={verification}>{verification}</strong><p>{sourceNote}</p></div>
  <div className="ma-metric"><span>Security summary</span><strong>{summary?`${summary.native_failed_checks} Native failed checks`:'No final findings yet'}</strong><p>{summary?`${summary.zap_findings} ZAP findings · ${summary.behavior_windows} behavioral windows · ${summary.incidents} incidents`:'Findings appear only after the actual workflow completes.'}</p></div>
 </div>;
}
export function TaskEvidence({task,events=[],compact=false,onNavigate,technical=false}){
 if(!task)return <p>No task selected. Run a coordinated saved-evidence task.</p>;
 const calls=events.filter(e=>e.event==='tool.started'||e.event==='tool.failed'||e.event==='tool.completed');
 const refs=[...new Map(Object.values(task.outputs||{}).flatMap(o=>o.evidence||[]).map(r=>[r.ref_id,r])).values()];
 const q=task.result?.cqi,d=task.distribution,summary=task.result?.assessment_summary;
 const historical=task.request.mode==='OFFLINE_EVIDENCE';
 return <>
  <p className="ma-task-meta"><strong>Task:</strong> <code>{task.task_id}</code> · <strong>{task.status}</strong> · {task.request.mode} · {task.steps}/{task.request.max_steps} tool attempts</p>
  {task.failure&&<div className="alert" role="alert">{task.failure.code}: {task.failure.message} · No successful cybersecurity assessment.</div>}
  <p role="status">{task.status==='COMPLETED'?(historical?'Workflow completed: historical reanalysis with limitations. This is not a current live assessment.':task.result?.assessment_outcome==='TEST_ONLY_LIVE_INTEGRATION'?'TEST-ONLY local fixture integration; no live laboratory operation was tested.':'Assessment completed using the bounded application-owned monitoring snapshot.'):terminal.has(task.status)?'Workflow stopped. See errors and trace.':'Dependency workflow is running.'}</p>
  {!technical&&<AssessmentHeadline task={task}/>}
  <details className="ma-panel ma-limitations" open={!!task.failure}><summary>Source limitations and operating restrictions</summary>
  {task.warnings?.map((w,i)=><p key={i} className="ma-warning">{w}</p>)}
  {task.result?.warnings?.map((w,i)=><p key={i} className="ma-warning">{w}</p>)}
  </details>
  {!technical&&<><h2>CQI D1–D6 · existing implementation</h2>
  {q?<><p>Overall: {q.overall==null?'Unavailable':q.overall.toFixed(4)} · {q.policy.version} · Not an attack probability · Consistency: {task.result.consistency_with_existing_cqi}</p><div className="ma-scroll"><table><thead><tr><th>Dimension</th><th>Score</th><th>Status</th></tr></thead><tbody>{q.dimensions.map(v=><tr key={v.dimension_id||v.dimension}><td>{v.dimension_id||v.dimension} {v.name}</td><td>{v.score==null?'Unavailable':v.score.toFixed(4)}</td><td>{v.status}</td></tr>)}</tbody></table></div></>:<p>No final CQI result available.</p>}
  {!compact&&summary&&<><h2>Security findings and verification</h2><p>Native: {summary.native_findings} checks, {summary.native_failed_checks} failed. ZAP: {summary.zap_findings} findings ({summary.zap_scope}). Behavioral: {summary.behavior_windows} windows, {summary.incidents} incidents. Verification: <strong>{summary.verification_status}</strong>.</p>
  <div className="ma-scroll"><table><thead><tr><th>Source</th><th>Finding</th><th>State</th><th>Evidence strength</th></tr></thead><tbody>{summary.findings_preview.slice(0,compact?4:10).map((f,i)=><tr key={i}><td>{f.source}</td><td>{f.finding_id} · {f.title}</td><td>{f.status} · {f.severity}</td><td>{f.confirmation}</td></tr>)}</tbody></table></div></>}
  {!compact&&task.result?.live_snapshot&&<details><summary>Monitoring session and captured boundaries</summary><pre>{JSON.stringify(task.result.live_snapshot,null,2)}</pre></details>}
  </>}
  {!compact&&<><h2>Measured calls</h2>
  <p>All specialist attempts: {d?.all_specialist_calls?.denominator??0}. Tools: {d?.tool_only?.denominator??0}. LLM: {d?.llm_only?.denominator??0} (share N/A when zero). Maximum share: {percent(d?.max_specialist_percent)}. 40% requirement: {d?.within_40_percent==null?'N/A':d.within_40_percent?'PASS':'FAIL'}.</p>
  <p>Coordinator domain calls: {d?.coordinator_tool_calls??0} · Dispatches: {d?.coordinator_dispatches??0} · Final / failure routes: {task.messages?.filter(m=>m.sender==='coordinator'&&['FINAL','FAILURE'].includes(m.kind)).length||0}.</p>
  <details><summary>Separate tool-only and LLM-only distributions</summary><pre>{JSON.stringify({tool_only:d?.tool_only,llm_only:d?.llm_only},null,2)}</pre></details>
  <h2>Verification outcomes</h2><div className="ma-scroll"><table><thead><tr><th>Subject</th><th>Outcome</th><th>Reason</th></tr></thead><tbody>{(task.verification||[]).map((v,i)=><tr key={i}><td>{v.subject}</td><td>{v.status}</td><td>{v.reasons.join(' · ')}</td></tr>)}</tbody></table></div>
  <details className="ma-panel"><summary>Structured JSON message trace ({task.messages?.length||0})</summary><pre>{JSON.stringify(task.messages,null,2)}</pre></details>
  <details className="ma-panel"><summary>Real tool invocation log ({calls.filter(c=>c.event==='tool.started').length} attempts)</summary><pre>{JSON.stringify(calls,null,2)}</pre></details>
  <details className="ma-panel"><summary>Evidence references ({refs.length})</summary><pre>{JSON.stringify(refs,null,2)}</pre></details>
  </>}
  {compact&&onNavigate&&<button className="button" onClick={()=>onNavigate('multiagent')}>Detailed results, JSON messages and logs</button>}
  <p><a className="button ma-export" href={`/api/multiagent/tasks/${task.task_id}/export`} target="_blank" rel="noreferrer">Export verified audit trail</a></p>
 </>;
}
export function assessmentPageData(base,view,task){
 if(!base||!view||!task||view.context.task_id!==task.task_id||terminal.has(task.status)&&view.context.updated_at!==task.updated_at)return null;
 const q=task.result?.cqi;
 return {...base,full_assessment:view.context,
  status:{...base.status,mode:task.request.mode==='LIVE_LAB'?'LIVE_LAB':'ACCEPTED_REPLAY',
   source_label:'Selected full-assessment snapshot · '+task.task_id,source_generation:task.updated_at,
   observation_count:view.behavioral.observations.length,incident_count:view.behavioral.incidents.length,
   runtime:{...base.status.runtime,last_observation:view.behavioral.observations.at(-1)?.window_end||null}},
  selection:{assessment_id:task.task_id,target:view.context.target,profile:task.request.zap_profile,full_assessment:true},
  posture:[...view.native.findings,...view.zap.findings],observations:view.behavioral.observations,
  incidents:view.behavioral.incidents,model:view.behavioral.model||base.model,
  assessment:view.zap.assessment,latest_execution:view.execution||null,
  scientific_cqi:q||{behavioral:{available:false}},cqi:null};
}
const selectionKey='cyberquality.full-assessment';
function savedSelection(){try{return localStorage.getItem(selectionKey)||''}catch{return ''}}
export function useFullAssessment(enabled=true){
 const [spec,setSpec]=useState(null),[task,setTask]=useState(null),[events,setEvents]=useState([]),[recent,setRecent]=useState([]),[view,setView]=useState(null),[official,setOfficial]=useState(null),[selectedId,setSelectedId]=useState(savedSelection),[error,setError]=useState(''),[submitting,setSubmitting]=useState(false);
 function select(id){setSelectedId(id);setTask(null);setView(null);setEvents([]);try{localStorage.setItem(selectionKey,id)}catch{}}
 useEffect(()=>{if(!enabled)return;let active=true;Promise.all([api('multiagent/spec'),api('multiagent/tasks'),api('multiagent/official')]).then(([s,r,o])=>{if(!active)return;setSpec(s);setRecent(r.items);setOfficial(o);setSelectedId(old=>old||o.task_id||r.items[0]?.task_id||'')}).catch(e=>{if(active)setError(e.message)});return()=>{active=false}},[enabled]);
 useEffect(()=>{if(!enabled||!selectedId)return;let active=true,timer;
  try{localStorage.setItem(selectionKey,selectedId)}catch{}
  async function poll(){try{const [next,log,v,o]=await Promise.all([api(`multiagent/tasks/${selectedId}`),api(`multiagent/tasks/${selectedId}/events`),api(`multiagent/tasks/${selectedId}/assessment`),api('multiagent/official')]);if(!active)return;setTask(next);setEvents(log.items);setView(v);setOfficial(o);setRecent(old=>old.map(t=>t.task_id===next.task_id?{...t,status:next.status}:t));setError('');if(!terminal.has(next.status)||v.context.updated_at!==next.updated_at)timer=setTimeout(poll,1000)}catch(e){if(active)setError(e.message)}}
  poll();return()=>{active=false;clearTimeout(timer)};
 },[selectedId,enabled]);
 async function start(request){setSubmitting(true);setError('');try{const next=await api('multiagent/tasks',{method:'POST',headers:{'Content-Type':'application/json','X-Product-Control':'1'},body:JSON.stringify({...request,request_id:crypto.randomUUID()})});select(next.task_id);setTask(next);setRecent(old=>[next,...old].slice(0,20))}catch(e){setError(e.message)}finally{setSubmitting(false)}}
 return {spec,task,events,recent,view,official,selectedId,select,start,error,busy:submitting||!!task&&(!terminal.has(task.status)||view?.context.updated_at!==task.updated_at)};
}
export function FullAssessmentContext({workspace,source='ASSESSMENT',onSource}){
 const {task,recent,selectedId,select,official}=workspace;
 return <div className="assessment-context full-assessment-context" data-assessment-id={selectedId||''}>
 <div className="context-primary"><div><strong>Selected Full Assessment</strong><p><code>{selectedId||'None selected'}</code> · {task?.status||'No task'} · {task?.request?.mode||'—'}</p><p>{workspace.view?.context?.target||'Moodle laboratory'}</p></div>
 <label>Assessment <select aria-label="Selected Full Assessment" value={selectedId} onChange={e=>select(e.target.value)}><option value="">Select assessment</option>{recent.map(t=><option key={t.task_id} value={t.task_id}>{t.task_id} · {t.status}</option>)}</select></label>
 {onSource&&<label>Displayed branch results<select aria-label="Displayed branch results" value={source} onChange={e=>onSource(e.target.value)}><option value="ASSESSMENT">Selected full-assessment snapshot</option><option value="LIVE_LAB">Latest standalone / active live monitoring</option><option value="ACCEPTED_REPLAY">Accepted historical research baseline</option></select></label>}</div>
 {source==='ASSESSMENT'?<p>Branch results below belong only to this assessment. Standalone work cannot change its saved CQI.</p>:<p>Standalone / research results are separate from the selected full assessment and its official Overall CQI.</p>}
 {official?.task_id&&official.task_id!==selectedId&&<p>Last valid Overall CQI: {official.cqi.overall.toFixed(4)} · <code>{official.task_id}</code> · {official.completed_at}. This is not the selected attempt’s CQI. <button className="text-button" onClick={()=>select(official.task_id)}>View last valid assessment</button></p>}
 </div>;
}
export default function MultiAgent({compact=false,onNavigate,workspace}){
 const local=useFullAssessment(!workspace),w=workspace||local;
 const {spec,task,events,error,busy}=w;
 const [scenario,setScenario]=useState('attack_replay'),[mode,setMode]=useState('OFFLINE_EVIDENCE'),[fresh,setFresh]=useState(true),[savedPosture,setSavedPosture]=useState(''),[profile,setProfile]=useState('STANDARD');
 return <section className="multiagent"><div className="ma-page-heading"><span className="ma-eyebrow">CYBERQUALITY · {compact?'FULL ASSESSMENT':'AGENT EXECUTION'}</span><h2>{compact?'Full cybersecurity assessment':'Multi-Agent execution and audit'}</h2></div>
 {compact&&<><div className="alert">{mode==='OFFLINE_EVIDENCE'?'OFFLINE EVIDENCE ONLY':'LIVE_LAB · authorization and exclusive ownership required'} · No LLM calls are simulated. Live access requires a verified lab lease; monitoring never starts automatically.</div>
 <div className="ma-controls"><label>Operating mode<select aria-label="Assessment operating mode" value={mode} disabled={busy} onChange={e=>setMode(e.target.value)}><option>OFFLINE_EVIDENCE</option><option>LIVE_LAB</option></select></label>
 {mode==='OFFLINE_EVIDENCE'?<label>Scenario<select aria-label="Multi-Agent scenario" value={scenario} disabled={busy} onChange={e=>setScenario(e.target.value)}>{(spec?.scenarios||['attack_replay']).map(s=><option key={s}>{s}</option>)}</select></label>:<><label>ZAP profile<select value={profile} onChange={e=>setProfile(e.target.value)}>{['STANDARD','PASSIVE_BASELINE','FULL_AUTHORIZED'].map(s=><option key={s}>{s}</option>)}</select></label><label><span><input type="checkbox" checked={fresh} onChange={e=>setFresh(e.target.checked)}/> Request fresh Native/ZAP</span></label>{!fresh&&<label>Explicit saved coursework posture ID<input value={savedPosture} onChange={e=>setSavedPosture(e.target.value)}/></label>}</>}
 <button className="button ma-primary" onClick={()=>w.start({scenario,mode,zap_profile:profile,fresh_posture:fresh,...(!fresh&&mode==='LIVE_LAB'?{posture_assessment_id:savedPosture}:{})})} disabled={busy||!spec}>{busy?'Running full assessment…':'Run Full Assessment'}</button></div></>}
 {error&&<div role="alert" className="alert">{error}</div>}
 {compact&&onNavigate&&<nav className="ma-operations" aria-label="Independent security operations">{[['posture','Native Security Posture / ZAP profiles'],['monitoring','Behavioral monitoring controls'],['multiagent','Agent messages and logs']].map(([page,title])=><button className="button" key={page} onClick={()=>onNavigate(page)}>{title}</button>)}</nav>}
 <div className="ma-agent-progress" aria-label="Actual agent execution states">{(spec?.agents||[]).filter(a=>!compact||['native','zap','behavioral','verification','quality'].includes(a.agent)).map(a=><span key={a.agent} data-state={task?.agents?.[a.agent]||'PENDING'}><b>{a.agent}</b>{task?.agents?.[a.agent]||'PENDING'}</span>)}</div>
 {compact?<TaskEvidence task={task} events={events} compact onNavigate={onNavigate}/>:<><AgentTable spec={spec?.agents} state={task}/><TaskEvidence task={task} events={events} technical/><details className="ma-panel"><summary>Shared task state, dependencies and limits</summary><pre>{JSON.stringify(task,null,2)}</pre></details><details className="ma-panel"><summary>Agent specifications and registered tools</summary><pre>{JSON.stringify(spec,null,2)}</pre></details></>}
 </section>;
}
