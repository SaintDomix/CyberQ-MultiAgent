import React,{useEffect,useState} from 'react';
import {api} from '../api/client.js';
import {Badge,Card} from './UI.jsx';

const reasons={READ_ONLY_PREVIEW:'Operational controls are disabled in this read-only preview.',
 LIVE_LAB_REQUIRED:'The operational backend must be in LIVE_LAB mode.',
 MODEL_INTEGRITY_FAILED:'Model integrity could not be verified; monitoring start is blocked.',
 APACHE_SOURCE_UNREADABLE:'The Apache log is missing or unreadable by the application account.'};

export function MonitoringControlPanel({data,state,busy=false,error,feedback,onAction}){
 const known=state?.schema_version==='monitor-control-1.0',running=known&&state.process_running===true;
 const label=running?'Running':known&&state.process_running===false?'Stopped':'Unknown';
 const liveView=data.status.mode==='LIVE_LAB',preview=data.preview_read_only;
 const start=known&&state.start_available===true&&liveView&&!preview;
 const stop=known&&state.stop_available===true&&running&&!preview;
 return <Card title="Monitoring controls" sub="Actual application-owned process · independent of the saved observations below" className="monitoring-controls">
 <div className="cell-actions"><span role="status" aria-label="Monitoring status">Monitoring: <Badge tone={running?'benign':''}>{label}</Badge></span>
 {running?<button className="button" disabled={busy||!stop||!onAction} onClick={()=>onAction('stop')}>{busy?'Stopping…':'Stop Monitoring'}</button>:
 <button className="button" disabled={busy||!start||!onAction} onClick={()=>onAction('start')}>{busy?'Starting…':'Start Monitoring'}</button>}</div>
 <p className="muted">These controls manage only the monitor owned by this application. Saved observations and their timestamps do not establish live monitoring.</p>
 {preview?<p className="muted">{reasons.READ_ONLY_PREVIEW}</p>:!liveView?<p className="muted">Select LIVE evidence to start monitoring. Accepted replay remains saved evidence.</p>:
 state?.unavailable_reason&&<p className="muted">{reasons[state.unavailable_reason]||'Monitoring start is unavailable; inspect System & Evidence.'}</p>}
 {!known&&!error&&<p className="muted">Checking the lifecycle controller; operations are disabled until its status is verified.</p>}
 {(error||state?.last_error)&&<p className="alert" role="alert">{error||state.last_error}</p>}
 {feedback&&<p role="status">{feedback}</p>}
 </Card>;
}

export function MonitoringControls({data,onControl,controlBusy}){
 const [state,setState]=useState(null),[error,setError]=useState(null),[actionError,setActionError]=useState(null),[feedback,setFeedback]=useState(null),[pending,setPending]=useState(false);
 async function read(){const value=await api('runtime/control');
  if(value.schema_version!=='monitor-control-1.0'||![true,false,null].includes(value.process_running))throw Error('Monitoring status could not be verified.');return value;}
 useEffect(()=>{let active=true,timer;
  async function poll(){try{const value=await read();if(active){setState(value);setError(null)}}catch(e){if(active){setState(null);setError(e.message)}}if(active)timer=setTimeout(poll,2500)}
  poll();return()=>{active=false;clearTimeout(timer)};
 },[]);
 async function act(name){if(pending||controlBusy||!onControl)return;setPending(true);setActionError(null);setFeedback(null);
  try{const outcome=await onControl(name);if(!outcome?.ok)throw Error(outcome?.error||'Monitoring operation could not be verified.');
   setState(await read());setFeedback(name==='start'?'Start request completed. Monitoring status was refreshed.':'Stop request completed. Saved observations are preserved.');
  }catch(e){setActionError(e.message);try{setState(await read())}catch{setState(null)}}finally{setPending(false)}
 }
 return <MonitoringControlPanel data={data} state={state} busy={pending||controlBusy} error={actionError||error} feedback={feedback} onAction={onControl?act:null}/>;
}
