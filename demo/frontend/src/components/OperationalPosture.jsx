import React,{useEffect,useState} from 'react';
import {api} from '../api/client.js';
import {Badge,Card,Table,Empty} from './UI.jsx';
import {PostureWorkspace} from './PostureWorkspace.jsx';
import {stamp,format} from '../utils/data.js';
const isDast=mode=>['STANDARD','FULL_AUTHORIZED'].includes(mode);

export function ScannerStatus({initial=null,onRetained=null}){
 const [value,setValue]=useState(initial),[error,setError]=useState(null);
 useEffect(()=>{let active=true,t;async function poll(){try{const v=await api('scanners/zap/status');if(active){setValue(v);setError(null)}}catch(e){if(active)setError(e.message)}if(active)t=setTimeout(poll,2500)}poll();return()=>{active=false;clearTimeout(t)}},[]);
 return <Card title="External scanner / OWASP ZAP" sub={isDast(value?.mode)?`${value.mode.replaceAll('_',' ')} DAST · protected application context`:'PASSIVE BASELINE ONLY · ACTIVE SCANNER: DISABLED'}>
 {error&&<p role="alert">{error} · Scanner status is not current; retained evidence is historical.</p>}{value?<><div className="badges"><Badge>Runtime: {value.runtime_status??value.status}</Badge><Badge>Readiness: {(value.assessment_readiness??'POLICY_BLOCKED').replaceAll('_',' ')}</Badge><Badge>{isDast(value.mode)?'ACTIVE SCANNER: CONTROLLED '+value.mode.replaceAll('_',' '):'ACTIVE SCANNER: DISABLED'}</Badge></div><p>Version: {value.version??'Unavailable'} · Current run: {value.latest_attempt_status??value.assessment_state??'NONE'} · Fresh alerts: {value.fresh_alerts_in_current_run??value.alerts_count??0}</p>
 {value.session_lifecycle==='NEW_UNNAMED_SESSION_ON_START'&&<p className="method-note">Each assessment creates and verifies a fresh isolated session in the owned ZAP runtime. Saved historical snapshots are preserved.</p>}
 {value.latest_attempt_reason==='FRESH_SESSION_REQUIRED'&&<p className="method-note">This historical attempt required a fresh session. New assessments now create one automatically when the owned runtime is ready.</p>}
 <p className="muted">{value.target} · Authenticated coverage: NOT_VALIDATED</p>
 {value.last_successful_assessment?<><h3>Last successful ZAP assessment</h3><div className="badges"><Badge>COMPLETE</Badge><Badge>{value.last_successful_assessment.integrity_status}</Badge><Badge>{value.last_successful_assessment.alert_count} alerts</Badge></div><p className="mono">{value.last_successful_assessment.assessment_id}</p><p>{stamp(value.last_successful_assessment.completed_at)} · Mapped: {value.last_successful_assessment.mapped_count} · Unmapped: {value.last_successful_assessment.unmapped_count}</p><p className="method-note">Retained from last successful ZAP assessment; not counted as fresh evidence in current CQI.</p>{onRetained&&<button className="text-button" onClick={onRetained}>Inspect retained ZAP evidence</button>}</>:<p>No successful ZAP assessment is available.</p>}</>:<Empty message="Loading scanner reachability and fresh-session readiness."/>}
 </Card>
}

const visibleStatus=f=>f.category==='UNMAPPED'&&f.evidence_sources?.includes('OWASP_ZAP')?'UNMAPPED ZAP RULE':f.status==='NOT_REEVALUATED'?'NOT CHECKED IN THIS RUN':f.status;
const sourceLabels=f=>(f.evidence_sources??[]).map(v=>v==='NATIVE_POSTURE'?'NATIVE':v==='OWASP_ZAP'?'ZAP PASSIVE':v==='ZAP_ACTIVE'?'ZAP ACTIVE':v==='ZAP_PASSIVE'?'ZAP PASSIVE':v);

export function ZapActiveEvidence({current,allowCancel=true}){
 const v=current?.zap_active_summary;
 if(isDast(current?.mode))return <FullZapSummary current={current} allowCancel={allowCancel}/>;
 return <Card title="ZAP Active" sub="Independent fourth evidence stage · explicit reviewed rule policy">
 <div className="badges"><Badge>{current?.zap_active_status??'NOT_RUN'}</Badge><Badge>ZAP_ACTIVE</Badge></div>
 <h4>SUMMARY</h4><p>{v?.reason_code?.replaceAll('_',' ')??'No current active stage result'}</p>
 <p>No approved scanners means no active scan is sent. This is not a successful active scan or proof that the target is secure. Native, ZAP Passive and repository Active Validation remain separate.</p>
 {v&&<><p>Current candidates: {v.selected_url_count??0} · Parameters: {v.selected_parameter_count??0} · Enabled rules: {v.enabled_scanner_ids?.length??0} · Rejected rules: {v.rejected_scanner_count??'Unavailable'}</p>
 <p>Fresh active alerts: {v.alerts_produced??0} · Mapped: {v.alerts_mapped??0} · Unmapped: {v.alerts_unmapped??0}</p>
 <details><summary>TECHNICAL · active policy / budget / provenance</summary><p>No historical alert is reused. No new CQI penalty is assigned without reviewed fresh evidence.</p><pre>{JSON.stringify(v,null,2)}</pre></details></>}
 </Card>
}

export function FullZapSummary({current,allowCancel=true}){
 const z=current?.zap_execution,progress=current?.zap_progress??{},active=z?.stages?.active??progress.ascan??progress.active;
 const missing=['QUEUED','RUNNING'].includes(current?.status)?'Pending':'Unavailable';
 return <Card title={`OWASP ZAP · ${(current?.assessment_profile??current?.mode??'FULL_AUTHORIZED').replaceAll('_',' ')}`} sub="Current application discovery and independent security findings">
 <p>Target: {current?.target} · Context: {current?.assessment_id} · Mode: {z?.zap_mode??missing} · Authentication: NOT_CONFIGURED</p>
 <Table headers={['Stage','Status','Current evidence']} rows={['spider','clientSpider','ajaxSpider','passive','active','metadata'].map(k=>{const v=k==='active'?active:z?.stages?.[k]??progress[k];return [k,v?.status??'NOT_RUN',`${v?.url_count??v?.additional_urls??v?.request_message_count??v?.request_count??v?.alerts??'—'} · ${v?.reason??(k==='active'&&v?.progress!=null?`Progress ${v.progress}%`:v?.progress??'')}`]})}/>
 <p>Installed active rules: {z?.inventory?.active_scanners?.length??missing} · Enabled: {z?.policy?.enabled_ids?.length??missing} · Active messages: {active?.request_message_count??active?.request_count??missing}</p>
 <p>Passive findings: {z?.passive_alerts??missing} · Active findings: {z?.active_alerts??missing} · Current endpoints: {z?.unique_endpoints??missing} · Parameters: {z?.parameter_count??missing}</p>
 <p>Rules observed executing: {z?.actual_executed_rule_ids?.length??missing} · Enabled does not mean executed. Zero alerts from an incomplete scan do not establish absence of vulnerabilities.</p>
 {z?.active_rule_execution&&<details><summary>Per-rule execution evidence</summary><Table headers={['Rule','Execution evidence','Requests','Alerts','Status']} rows={z.active_rule_execution.map(r=>[`${r.id} · ${r.name}`,r.execution_state,r.request_count??'Not exposed',r.alerts??'Not exposed',r.status??'Not observed'])}/></details>}
 <p>ZAP-only findings appear in the primary findings list. CQI UNMAPPED does not mean that a security finding is absent.</p>
 {z&&<details><summary>TECHNICAL · policy, capabilities and stage provenance</summary><pre>{JSON.stringify({policy:z.policy,standard_policy:z.standard_policy,capabilities:z.inventory?.capabilities,stages:z.stages,cleanup:z.cleanup_errors},null,2)}</pre></details>}
 {allowCancel&&current?.status==='RUNNING'&&<button onClick={()=>api('posture/assessments/'+current.assessment_id+'/cancel',{method:'POST',headers:{'X-Product-Control':'1'}})}>CANCEL OWNED ASSESSMENT</button>}
 </Card>
}

export function ActiveEvidence({finding}){
 const v=finding.active_validation;
 const labels={CONFIRMED:'ACTIVE CONFIRMED',NOT_CONFIRMED:'ACTIVE NOT CONFIRMED',NOT_APPLICABLE:'ACTIVE N/A',NOT_AVAILABLE:'ACTIVE UNAVAILABLE',NOT_RUN:'ACTIVE NOT RUN'};
 return <div><Badge>{v?labels[v.status]??'ACTIVE UNAVAILABLE':'ACTIVE NOT RUN'}</Badge>
 {v&&<details><summary>Active validation evidence</summary><h4>SUMMARY</h4>
 <p>Finding: {finding.status}. Active evidence does not replace this finding or change CQI.</p>
 <p>{v.reason}</p><p>NOT_CONFIRMED means insufficient corroborating evidence from this bounded check; it does not mean false positive or PASS.</p>
 <h4>TECHNICAL EVIDENCE</h4><p>Validator: {v.validator_id??'Not applicable'} · Requests: {v.request_count??'Unknown'} · Support: {v.support_level??'Not assessed'}</p>
 <p>Current assessment: {v.assessment_id} · Score effect: NONE · No successful exploitation confirmed.</p>
 <pre>{JSON.stringify(v.results??[v],null,2)}</pre></details>}</div>
}

export function RetainedZap({initial=null,onClose}){
 const [value,setValue]=useState(initial),[error,setError]=useState(null);
 useEffect(()=>{let active=true;api('scanners/zap/findings?view=retained').then(v=>{if(active)setValue(v)}).catch(e=>{if(active)setError(e.message)});return()=>{active=false}},[]);
 return <Card title="RETAINED ZAP EVIDENCE" sub="Display/history only; excluded from current canonical findings and current CQI" extra={<button onClick={onClose}>Back to current posture</button>}>
 <p>Retained from last successful ZAP assessment; not counted as fresh evidence in current CQI.</p><p className="mono">{value?.assessment_id??'No successful ZAP assessment'}</p>{error&&<p role="alert">{error}</p>}
 <Table headers={['Finding','Result','Source / assessment','Evidence / remediation']} rows={(value?.items??[]).map(f=>[f.title,<Badge>{visibleStatus(f)}</Badge>,<span><Badge>RETAINED ZAP EVIDENCE</Badge><small>{f.assessment_id}</small></span>,<details><summary>Inspect retained evidence</summary><p>{f.remediation}</p><pre>{JSON.stringify(f.evidence_summary,null,2)}</pre></details>])}/>
 </Card>
}

function LegacyOperationalPosture({data,onEvidence,Research,initialCurrent=null,initialFindings=[]}){
 const [targetURL,setTargetURL]=useState('http://192.168.226.132/moodle/'),[profile,setProfile]=useState('STANDARD'),[authorized,setAuthorized]=useState(false);
 const [tab,setTab]=useState('current'),[current,setCurrent]=useState(initialCurrent),[rows,setRows]=useState(initialFindings),[historical,setHistorical]=useState(null),[error,setError]=useState(null),[busy,setBusy]=useState(false);
 const [baselineDetail,setBaselineDetail]=useState(null);
 const [status,setStatus]=useState('ALL'),[source,setSource]=useState('ALL'),[dimension,setDimension]=useState('ALL'),[severity,setSeverity]=useState('ALL');
 useEffect(()=>{let active=true,t;async function poll(){try{const [a,f,h]=await Promise.all([api('posture/assessments/latest'),api('posture/findings?view=current&limit=200'),api('posture/findings?view=historical&limit=200')]);if(active){setCurrent(a);setRows(f.items);setHistorical(h.items);setError(null)}}catch(e){if(active)setError(e.message)}if(active)t=setTimeout(poll,2500)}poll();return()=>{active=false;clearTimeout(t)}},[]);
 async function assess(){setBusy(true);try{const j=await api('posture/assessments',{method:'POST',headers:{'Content-Type':'application/json','X-Product-Control':'1'},body:JSON.stringify({target_id:profile!=='PASSIVE_BASELINE'?'configured-target':'moodle-local',mode:profile,zap_enabled:true,target_url:targetURL,authorized})});setCurrent(j);setError(null)}catch(e){setError(e.message)}finally{setBusy(false)}}
 const selected=rows.filter(f=>(status==='ALL'||(status==='UNMAPPED'?visibleStatus(f)==='UNMAPPED ZAP RULE':status==='NOT_REEVALUATED'?visibleStatus(f)==='NOT CHECKED IN THIS RUN':f.status===status))&&(dimension==='ALL'||f.dimension===dimension)&&(severity==='ALL'||f.severity===severity)&&(source==='ALL'||(source==='MULTI_SOURCE'?f.multi_source:f.evidence_sources.includes(source))));
 const baseline=historical??(data.status.posture_scope==='RESEARCH_BASELINE'?data.posture:[]);
 if(tab==='retained')return <RetainedZap onClose={()=>setTab('current')}/>;
 return <><div className="tabs"><button className={tab==='current'?'active':''} onClick={()=>setTab('current')}>CURRENT POSTURE</button><button className={tab==='historical'?'active':''} onClick={()=>setTab('historical')}>RESEARCH BASELINE / HISTORY</button></div>
 {error&&<div className="alert" role="alert">{error} · Retained values are not a newly completed assessment.</div>}
 {tab==='historical'?<><p className="method-note">Immutable accepted historical evidence. This is not a newly executed assessment.</p><Research data={{...data,posture:baseline,status:{...data.status,posture_counts:baseline.reduce((a,f)=>({...a,[f.status]:(a[f.status]||0)+1}),{})}}} onEvidence={id=>setBaselineDetail(baseline.find(f=>f.finding_id===id)||null)}/>
 {baselineDetail&&<Card title={'RESEARCH BASELINE · '+baselineDetail.finding_id}><button className="text-button" onClick={()=>setBaselineDetail(null)}>Close detail</button><p>{baselineDetail.description}</p><p>{baselineDetail.remediation}</p><pre>{JSON.stringify({status:baselineDetail.status,evidence:baselineDetail.evidence_summary,provenance:baselineDetail.provenance},null,2)}</pre></Card>}</>:<>
 <Card title="CURRENT OPERATIONAL POSTURE" sub="A new execution creates an immutable snapshot; historical findings are never recycled" extra={<button className="button" disabled={busy||current?.status==='RUNNING'||(profile!=='PASSIVE_BASELINE'&&!authorized)} onClick={assess}>RUN POSTURE ASSESSMENT</button>}>
 <div className="filters"><label>Target URL <input aria-label="Authorized target URL" value={targetURL} onChange={e=>setTargetURL(e.target.value)} /></label><label>Assessment profile <select aria-label="Assessment profile" value={profile} onChange={e=>setProfile(e.target.value)}><option value="STANDARD">STANDARD — Recommended for normal assessment</option><option value="FULL_AUTHORIZED">FULL_AUTHORIZED — Deep comprehensive ZAP assessment</option><option value="PASSIVE_BASELINE">PASSIVE_BASELINE — Restricted passive assessment</option></select></label><label><input type="checkbox" checked={authorized} onChange={e=>setAuthorized(e.target.checked)} /> I am authorized to assess this application</label></div><p>{profile==='STANDARD'?'STANDARD performs fresh Native, Passive, repository validation and selected ZAP Active checks.':profile==='FULL_AUTHORIZED'?'FULL_AUTHORIZED is a deep comprehensive ZAP assessment and may take significantly longer.':'PASSIVE_BASELINE uses the preserved restricted passive profile.'}</p><p>Authentication: Anonymous · Verified authenticated ZAP session NOT_CONFIGURED.</p><p>Current target: {current?.target??'Not yet assessed'} · Profile: {current?.assessment_profile??current?.mode??'Not yet assessed'}</p><div className="badges"><Badge>{current?.status??'LOADING'}</Badge><Badge>COVERAGE: {current?.coverage?.status??'NOT ASSESSED'}</Badge><Badge>{isDast(current?.mode)?`ZAP ${current.mode.replaceAll('_',' ')} + NATIVE VALIDATION`:'ZAP PASSIVE + BOUNDED SAFE VALIDATION'}</Badge></div>
 <p>Active validation: {current?.active_validation_status??'NOT RUN'} · Requests: {current?.active_validation_summary?.budget?.actual_requests??'—'} / {current?.active_validation_summary?.budget?.planned_requests??'—'} planned · CQI effect: NONE</p>
 <p className="mono">Assessment: {current?.assessment_id??'Not yet executed'}</p><p>Started: {current?.started_at?stamp(current.started_at):'Unavailable'} · Completed: {current?.completed_at?stamp(current.completed_at):'Unavailable'}</p>
 <Table headers={['Provider','Execution state','Fresh evidence']} rows={Object.entries(current?.provider_statuses||{}).map(([k,v])=>[k==='native'?'Branch1 / Native':isDast(current?.mode)?'OWASP ZAP DAST':'OWASP ZAP Passive',<span>{v}<small>{current?.provider_reasons?.[k]?.replaceAll('_',' ')}</small></span>,k==='native'?`${current?.native_checks_rerun?.length??0} checks executed · ${current?.fresh_finding_counts?.native??current?.raw_finding_counts?.native??0} fresh findings`:`${['COMPLETE','PARTIAL'].includes(v)?(current?.raw_finding_counts?.zap??0):0} fresh alerts`])}/>
 <div className="badges">{[['Fresh Native findings',current?.fresh_finding_counts?.native??current?.raw_finding_counts?.native],['Fresh ZAP findings',['COMPLETE','PARTIAL'].includes(current?.provider_statuses?.zap)?current?.raw_finding_counts?.zap:0],['Canonical findings',current?.canonical_finding_count],['Deduplicated',current?.deduplicated_count],['Multi-source',current?.multi_source_count],['Not checked in this run',current?.coverage?.not_checked_in_run??rows.filter(f=>visibleStatus(f)==='NOT CHECKED IN THIS RUN').length],['Unmapped ZAP rules',current?.coverage?.unmapped_zap_rules]].map(([k,v])=><Badge key={k}>{k}: {v??'—'}</Badge>)}</div>
 <p>NOT CHECKED IN THIS RUN — Historical result is intentionally not reused. Authenticated ZAP coverage NOT_VALIDATED.</p>
 {current?.current_posture_cqi&&<><p>Current posture-only CQI: {format(current.current_posture_cqi.overall,2)} · PARTIAL · Unavailable dimensions: {current.current_posture_cqi.dimensions.filter(d=>d.score==null).map(d=>d.dimension_id).join(', ')}</p><p className="method-note">{current.current_posture_cqi.policy.comparison_caution} D6 requires current behavioral evidence.</p></>}
 {current?.before_after?.before!=null&&<p>Previous posture-only CQI: {format(current.before_after.before,2)} → {format(current.before_after.after,2)} (delta {format(current.before_after.delta,2)}). {current.before_after.interpretation}</p>}
 </Card>
 <ScannerStatus onRetained={()=>setTab('retained')}/>
 <ZapActiveEvidence current={current}/>
 {rows.length>0&&current?.assessment_id&&rows[0].assessment_id!==current.assessment_id&&<p className="method-note">Showing the retained completed snapshot {rows[0].assessment_id}. Latest attempt {current.assessment_id} is {current.status}; these are not newly completed results.</p>}
 <Card title="Canonical current findings" sub="One reviewed control penalty; all native/ZAP evidence sources retained">
 <p className="muted">Showing {rows.length} canonical rows (up to 200); complete paginated results are available through the Posture API.</p>
 <div className="filters"><select aria-label="Current finding status" value={status} onChange={e=>setStatus(e.target.value)}>{['ALL','FAIL','PARTIAL','PASS','DISMISSED','NOT_REEVALUATED','UNMAPPED','NOT_APPLICABLE'].map(v=><option key={v} value={v}>{v==='NOT_REEVALUATED'?'NOT CHECKED IN THIS RUN':v==='UNMAPPED'?'UNMAPPED ZAP RULE':v}</option>)}</select><select aria-label="Current finding source" value={source} onChange={e=>setSource(e.target.value)}>{['ALL','NATIVE_POSTURE','OWASP_ZAP','ZAP_PASSIVE','ZAP_ACTIVE','MULTI_SOURCE'].map(v=><option key={v} value={v}>{v==='NATIVE_POSTURE'?'NATIVE':v==='OWASP_ZAP'?'ZAP':v==='MULTI_SOURCE'?'NATIVE + ZAP':v}</option>)}</select><select aria-label="Current finding dimension" value={dimension} onChange={e=>setDimension(e.target.value)}>{['ALL','D1','D2','D3','D4','D5'].map(v=><option key={v}>{v}</option>)}</select><select aria-label="Current finding severity" value={severity} onChange={e=>setSeverity(e.target.value)}>{['ALL','CRITICAL','HIGH','MEDIUM','LOW','INFO'].map(v=><option key={v}>{v}</option>)}</select></div>
 <Table headers={['Finding / scope','Control / dimension','Result','Evidence sources','Severity / confidence','Evidence / remediation']} rows={selected.map(f=>[
 <span>{f.finding_id}<small>CURRENT · {f.assessment_id}</small><small>{f.created_at?stamp(f.created_at):'Not observed'}</small></span>,<span>{f.title}<small>{f.dimension??'UNMAPPED'} · {f.affected_component}</small></span>,<span><Badge>{visibleStatus(f)}</Badge><ActiveEvidence finding={f}/>{visibleStatus(f)==='NOT CHECKED IN THIS RUN'&&<small>Historical result is intentionally not reused. {f.prerequisite_reason}</small>}{visibleStatus(f)==='UNMAPPED ZAP RULE'&&<small>Observed by ZAP but not mapped to a CQI control; excluded from scoring.</small>}{f.source_status_conflict&&<small>SOURCE DISAGREEMENT · review retained member results</small>}</span>,<span>{sourceLabels(f).map(s=><Badge key={s}>{s}</Badge>)}{f.validation_sources?.includes('ACTIVE_VALIDATION')&&<Badge>ACTIVE VALIDATION</Badge>}<small>{f.multi_source?'MULTI-SOURCE · ':''}{f.dedup_rule}</small></span>,<span>{f.severity??'NOT PROVIDED'}<small>{f.source_confidence??f.confirmation} · not probability</small></span>,<details><summary>Inspect evidence / remediation</summary><p>{f.description}</p><p>{f.remediation}</p><p>CWE: {f.cwe??f.zap_details?.cwe??'Unavailable'} · Rule: {f.source_rule_id??'Native'}</p>{f.zap_details&&<><h4>ZAP FINDING</h4><p>Target: {f.zap_details.normalized_path} · Parameter: {f.parameter??'None'} · Method: {f.method??'Unavailable'}</p><p>ZAP risk: {f.zap_details.zap_risk} · ZAP confidence: {f.zap_details.zap_confidence} · CQI mapping: {f.cqi_mapping??'UNMAPPED'}</p><p>A valid security finding remains visible when CQI mapping is UNMAPPED. Scanner evidence is not successful-exploitation proof.</p></>}<pre>{JSON.stringify({evidence:f.evidence_summary,provenance:f.provenance},null,2)}</pre></details>])}/>
 </Card><p className="method-note">Scanner finding ≠ proven exploitability. Missing checks are not PASS. Current CQI uses current posture + current behavior in LIVE_LAB; ACCEPTED_REPLAY retains research CQI.</p>
 </>}
 </>
}

export function OperationalPosture(props){return props.data?.scientific_cqi?<PostureWorkspace {...props} ActiveEvidence={ActiveEvidence} ScannerStatus={ScannerStatus} ZapActiveEvidence={ZapActiveEvidence} RetainedZap={RetainedZap}/>:<LegacyOperationalPosture {...props}/>;}
