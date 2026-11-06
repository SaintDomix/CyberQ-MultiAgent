import React,{useEffect,useState} from 'react';
import {api} from '../api/client.js';
import {Badge,Card,Table,Empty} from './UI.jsx';
import {DetailDrawer} from './DetailDrawer.jsx';
import {human,stamp} from '../utils/data.js';

export const executionBusy=e=>['QUEUED','RUNNING','CANCELLATION_REQUESTED'].includes(e?.status);

export function PostureExecution({execution,readOnly=false,ZapActiveEvidence}){
 const [pending,setPending]=useState(false),[notice,setNotice]=useState(''),[error,setError]=useState(null);
 const id=execution?.assessment_id;
 useEffect(()=>{setNotice('');setError(null)},[id,execution?.status]);
 async function cancel(){
  if(readOnly||!execution?.cancellation?.eligible||pending)return;
  setPending(true);setError(null);
  try{const result=await api('posture/assessments/'+encodeURIComponent(id)+'/cancel',{method:'POST',headers:{'X-Product-Control':'1'}});
   setNotice(result.status==='CANCELLATION_REQUESTED'?'Cancellation requested. Awaiting the existing worker’s final state.':human(result.status));
  }catch(e){setError(e.message)}finally{setPending(false)}
 }
 return <Card title="Latest operational execution" sub="Independent of the immutable evidence selected above" extra={<Badge>{human(execution?.status||'NOT_ASSESSED')}</Badge>}>
 {!id?<p>No operational assessment attempt is available. Accepted research evidence is separate.</p>:<>
 <p className="source-label">{id}</p><p>{execution.target} · {execution.assessment_profile||execution.mode}</p>
 <p>Started {stamp(execution.started_at)} · Completed {execution.completed_at?stamp(execution.completed_at):'Not completed'}</p>
 <Table headers={['Provider / stage','Actual state','Reason']} rows={Object.entries(execution.provider_statuses||{}).map(([name,status])=>[human(name),status,human(execution.provider_reasons?.[name]||'')])}/>
 <p>Repository Active Validation: {execution.active_validation_status||'Not reported'}.</p>
 {(execution.error||execution.reason_code)&&<p role="status">{execution.error||human(execution.reason_code)}</p>}
 {executionBusy(execution)&&<p className="note">A new start is blocked while this execution is queued or running. Viewing historical evidence does not affect it.</p>}
 {['RUNNING','QUEUED'].includes(execution.status)&&<><button className="button" onClick={cancel} disabled={readOnly||pending||!!notice||!execution.cancellation?.eligible}>Request cancellation of owned assessment</button>
 <p className="muted">{readOnly?'Read-only preview: cancellation is disabled.':execution.cancellation?.eligible?'Explicit action for '+id+'. The selected snapshot is preserved.':human(execution.cancellation?.reason||'NO_OWNED_RUNNING_ASSESSMENT')}</p></>}
 {notice&&<p role="status">{notice}</p>}{error&&<p role="alert" className="alert">{error}</p>}
 {ZapActiveEvidence&&<ZapActiveEvidence current={execution} allowCancel={false}/>}
 <details><summary>Execution metadata and provenance</summary><pre>{JSON.stringify(execution,null,2)}</pre></details>
 </>}
 </Card>;
}

export function PostureHistory({onAssessment,generation}){
 const [offset,setOffset]=useState(0),[page,setPage]=useState(null),[error,setError]=useState(null),[attempt,setAttempt]=useState(null);
 useEffect(()=>{let active=true;api('product/history?limit=25&offset='+offset).then(v=>{if(active){setPage(v);setError(null)}}).catch(e=>{if(active)setError(e.message)});return()=>{active=false}},[offset,generation]);
 async function inspect(id){try{setAttempt(await api('product/executions/'+encodeURIComponent(id)))}catch(e){setError(e.message)}}
 return <><Card title="Complete assessment attempt history" sub="Completed, partial, failed and interrupted attempts retain their actual states">
 {error&&<p role="alert" className="alert">{error}</p>}{!page?<Empty message="Loading immutable attempt history…"/>:<>
 <Table headers={['Assessment','Target / profile','State / time','Inspect']} rows={page.items.map(j=>[j.assessment_id,<span>{j.target}<small>{j.assessment_profile||j.mode}</small></span>,<span>{j.status}<small>{stamp(j.completed_at||j.started_at)}</small></span>,<span className="cell-actions">{['COMPLETE','PARTIAL'].includes(j.status)&&<button className="text-button" onClick={()=>onAssessment?.(j.assessment_id)}>View immutable snapshot</button>}<button className="text-button" onClick={()=>inspect(j.assessment_id)}>Inspect attempt</button></span>])}/>
 <div className="pagination"><span>{page.total?offset+1:0}–{Math.min(offset+page.items.length,page.total)} of {page.total} attempts</span><button disabled={!offset} onClick={()=>setOffset(n=>Math.max(0,n-25))}>Previous attempts</button><button disabled={offset+25>=page.total} onClick={()=>setOffset(n=>n+25)}>Next attempts</button></div></>}
 </Card>{attempt&&<DetailDrawer title="Assessment attempt" onClose={()=>setAttempt(null)}><Badge>{attempt.status}</Badge><p className="source-label">{attempt.assessment_id}</p><p>{attempt.target} · {attempt.assessment_profile}</p><p>{attempt.error||attempt.reason_code||'Original attempt state and metadata retained.'}</p><p>Inspecting this record does not select it as completed CQI evidence.</p><pre>{JSON.stringify(attempt,null,2)}</pre></DetailDrawer>}</>;
}
