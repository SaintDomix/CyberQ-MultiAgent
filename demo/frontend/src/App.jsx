import React,{useEffect,useState} from 'react';
import {api,control} from './api/client.js';
import {Badge,Icon,Empty} from './components/UI.jsx';
import {navigation,evidenceQuery} from './utils/product.js';
import {AssessmentContext} from './components/AssessmentContext.jsx';
import {Pages,Explanation,EvidencePanel} from './pages/ProductPages.jsx';
import MultiAgent,{useFullAssessment,FullAssessmentContext,assessmentPageData} from './components/MultiAgent.jsx';

export function Navigation({page,onSelect}){return <nav aria-label="Main navigation">{navigation.map(([id,title,icon])=><button key={id} aria-label={title} className={page===id?'active':''} aria-current={page===id?'page':undefined} onClick={()=>onSelect(id)}><Icon name={icon}/><span>{title}</span>{page===id&&<i/>}</button>)}</nav>}
export function ErrorBanner({message,stale=false}){return <div className="alert" role="alert">{message}{stale&&' Displayed snapshot is stale; awaiting a successful update.'}</div>}
export function DemoScenarios({items,onSelect,onReset}){return <div className="demo-scenarios"><span>ACCEPTED EVIDENCE REPLAY</span>{items.map(s=><button key={s.id} onClick={()=>onSelect(s)}>{s.title}</button>)}<button onClick={onReset}>Reset to full accepted replay</button></div>}
export default function App(){
 const full=useFullAssessment(),[branchView,setBranchView]=useState('ASSESSMENT');
 const [page,setPage]=useState('overview'),[mode,setMode]=useState('ACCEPTED_REPLAY'),[replay,setReplay]=useState('ATTACK_HOLDOUT'),[run,setRun]=useState(''),[assessment,setAssessment]=useState(''),[data,setData]=useState(null),[research,setResearch]=useState(null),[error,setError]=useState(null),[researchError,setResearchError]=useState(null),[selected,setSelected]=useState(null),[evidence,setEvidence]=useState(null),[busy,setBusy]=useState(false),[lastPoll,setLastPoll]=useState(null);
 const [selectedBack,setSelectedBack]=useState(null),[evidenceBack,setEvidenceBack]=useState(null),[previewOnly,setPreviewOnly]=useState(false);
 useEffect(()=>{setBranchView('ASSESSMENT')},[full.selectedId]);
 const [scenarios,setScenarios]=useState([]),[finalReport,setFinalReport]=useState(null);
 useEffect(()=>{let active=true;api('health').then(v=>{if(active){setPreviewOnly(v.preview_read_only===true);if(['LIVE_LAB','ACCEPTED_REPLAY'].includes(v.mode))setMode(v.mode)}}).catch(()=>{});api('demo/scenarios').then(v=>{if(active)setScenarios(v.items)}).catch(()=>{});api('report/final').then(v=>{if(active)setFinalReport(v)}).catch(()=>{});return()=>{active=false}},[]);
 const query=evidenceQuery(mode,replay,run);
 const boundQuery=query+(assessment&&mode==='LIVE_LAB'?'&assessment_id='+encodeURIComponent(assessment):'');
 async function load(){try{const v=await api('product/assessment?'+boundQuery);
  if(v.schema_version!=='product-assessment-3.0'||v.scientific_cqi?.policy?.version!=='cqi-evidence-2.0')throw Error('Invalid product evidence contract; no score substituted.');
  return {...v.snapshot,scientific_cqi:v.scientific_cqi,selection:v.selection,comparison:v.comparison,history:v.history,history_total:v.history_total,latest_execution:v.latest_execution,behavior_summary:v.behavior_summary,assessment:v.assessment,closure_review:v.closure_review,preview_read_only:v.preview_read_only};
 }catch(e){if(e.status!==404||assessment)throw e;return {...await api('application/snapshot?'+query),legacy_only:true};}}

 useEffect(()=>{let active=true,timer,sourceId;setData(null);setSelected(null);setEvidence(null);setError(null);
  async function poll(){try{const value=await load();if(active){const nextSource=value.selection?.assessment_id||query,unchanged=sourceId===nextSource;sourceId=nextSource;setData(value);setError(null);setLastPoll(new Date());setSelected(old=>old&&unchanged?value.observations.find(o=>o.observation_id===old.observation_id)||old:null)}}catch(e){if(active)setError(e.message)}if(active)timer=setTimeout(poll,2500)}
  poll();return()=>{active=false;clearTimeout(timer)};
 },[boundQuery]);
 useEffect(()=>{let active=true;api('model/evaluation').then(v=>{if(active){setResearch(v);setResearchError(null)}}).catch(e=>{if(active)setResearchError(e.message)});return()=>{active=false}},[]);
 async function action(name){setBusy(true);try{const result=await control(name);const value=await load();setData(value);setError(null);return {ok:true,result}}catch(e){setError(e.message);return {ok:false,error:e.message}}finally{setBusy(false)}}
 function changeMode(next){setRun('');setAssessment('');setMode(next)}
 async function inspect(id,back=null){try{if(['posture','monitoring'].includes(page)&&branchView==='ASSESSMENT'){
  const item=full.view?.behavioral.observations.find(o=>o.observation_id===id);
  if(item){setEvidence({type:'OBSERVATION',data:item,assessment_id:full.selectedId});return;}
  throw Error('Evidence is not referenced by the selected full assessment.');
 }const sourceKey=data?.selection?.historical_selection?'assessment_id':'expected_assessment_id';const q=query+(mode==='LIVE_LAB'&&data?.selection?.assessment_id?'&'+sourceKey+'='+encodeURIComponent(data.selection.assessment_id):'');const v=await api((data?.legacy_only?'evidence/':'product/evidence/')+encodeURIComponent(id)+'?'+q);if(back&&v.type==='OBSERVATION'){setSelected(v.data);setSelectedBack(()=>back);return;}if(selected){const old=selected;setSelected(null);setEvidenceBack(()=>()=>setSelected(old))}else if(back)setEvidenceBack(()=>back);setEvidence(v)}catch(e){setError(e.message);if(back)back();}}
 function resetReplay(){setReplay('ATTACK_HOLDOUT');setRun('');setSelected(null);setEvidence(null);}
 function selectObservation(o,back=null){setSelected(o);setSelectedBack(()=>back)}
 function closeObservation(){setSelected(null);if(selectedBack)selectedBack();setSelectedBack(null)}
 function closeEvidence(){setEvidence(null);if(evidenceBack)evidenceBack();setEvidenceBack(null)}
 const displayData=data?{...data,preview_read_only:data.preview_read_only||previewOnly}:null;
 const unified=['overview','posture','monitoring','multiagent'].includes(page);
 const branchData=unified&&branchView==='ASSESSMENT'?assessmentPageData(displayData,full.view,full.task):displayData;
 function showBranch(value){setBranchView(value);if(value!=='ASSESSMENT')changeMode(value);setSelected(null);setEvidence(null)}
 const Page=Pages[page],status=data?.status,live=status?.runtime.process_running===true;
 const EvidenceContainer=page==='overview'?'details':'div';
 return <div className="app ux-candidate"><aside className="sidebar"><div className="brand"><div className="brand-mark"><Icon name="posture" size={25}/></div><div><strong>CyberQuality</strong><span>SECURITY ASSESSMENT</span></div></div><div className="sidebar-caption">ASSESSMENT WORKSPACE</div><Navigation page={page} onSelect={setPage}/><div className="sidebar-bottom"><span className={'status-dot '+(error?'offline':'')}/><div><strong>{error?'Service unavailable':live?'Monitoring process running':'Evidence service connected'}</strong><small>Evidence &amp; methods in Model &amp; research</small></div></div></aside>
 <div className="workspace"><header className="topbar"><span className="breadcrumb">Security intelligence <Icon name="chevron" size={13}/>{navigation.find(n=>n[0]===page)[1]}</span><div className="topbar-right">{(data?.preview_read_only||previewOnly)&&<span className="preview-indicator">Read-only preview · actions disabled</span>}{status?.model_integrity&&status.model_integrity!=='VERIFIED'&&<Badge tone="attempt">Model integrity failed</Badge>}</div></header><main className={unified?'unified-assessment':''}>
 <div className={'page-header '+(page==='overview'?'overview-heading':'')}><div><h1>{page==='overview'?'Security quality overview':navigation.find(n=>n[0]===page)[1]}</h1></div></div>
 {!unified&&<AssessmentContext compact completenessInPage={['overview','quality'].includes(page)} data={displayData} mode={mode} replay={replay} run={run} assessment={assessment} onMode={changeMode} onReplay={v=>{setRun('');setReplay(v)}} onRun={setRun} onAssessment={setAssessment} scenarios={scenarios} lastPoll={lastPoll} onReset={resetReplay} onScenario={s=>{setReplay(s.replay);setRun(s.run_id);setSelected(null);setEvidence(null);setPage('monitoring')}}/>}
 {error&&<ErrorBanner message={error} stale={!!data}/>} {status?.last_error&&<div className="alert" role="status">{status.last_error}</div>}
 {data?.legacy_only&&<div className="alert" role="status">LEGACY POLICY VIEW · fusion-cqi-1.1. CQI v2 product integration is unavailable on this backend. No v1 value is labelled v2.</div>}
 {unified&&<FullAssessmentContext workspace={full} source={['posture','monitoring'].includes(page)?branchView:'ASSESSMENT'} onSource={['posture','monitoring'].includes(page)?showBranch:null}/>}
 {(page==='overview'||page==='multiagent')&&<MultiAgent workspace={full} compact={page==='overview'} onNavigate={setPage}/>}
 {['posture','monitoring'].includes(page)?branchData?<Page data={branchData} onNavigate={setPage} onSelect={selectObservation} onEvidence={inspect} onControl={action} controlBusy={busy} onAssessment={id=>{setBranchView('LIVE_LAB');setMode('LIVE_LAB');setAssessment(id)}} onStandaloneResult={job=>{setBranchView('LIVE_LAB');setMode('LIVE_LAB');setAssessment(job.assessment_id)}}/>:<Empty message={full.error||'Select a full assessment or explicitly choose standalone / historical results.'}/>:!['overview','multiagent'].includes(page)&&(data?<Page data={displayData} research={research} researchError={researchError} finalReport={finalReport} onNavigate={setPage} onSelect={selectObservation} onEvidence={inspect} onControl={action} controlBusy={busy} onAssessment={id=>{setMode('LIVE_LAB');setAssessment(id);setPage('posture')}}/>:<Empty message={error||'Loading verified application evidence…'}/>)}
 <footer>Cybersecurity Quality · Research Console<span>Methods, limitations and provenance: Model &amp; research</span></footer>
 </main></div>{selected&&<Explanation observation={selected} onClose={closeObservation} onBack={selectedBack?closeObservation:null} onEvidence={()=>inspect(selected.observation_id)}/>} {evidence&&<EvidencePanel evidence={evidence} onClose={closeEvidence} onBack={evidenceBack?closeEvidence:null}/>}</div>
}
