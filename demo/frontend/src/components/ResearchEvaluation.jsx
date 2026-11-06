import React,{useEffect,useState} from 'react';
import {api} from '../api/client.js';
import {Card,Badge,Table,Empty,Tabs} from './UI.jsx';
import {format,human} from '../utils/data.js';
const count=v=>v?`${v.count}/${v.total}`:'Unavailable';
const percent=v=>Number.isFinite(v)?(100*v).toFixed(2)+'%':'Unavailable';
const names={A:'One-Class SVM',B:'Local Outlier Factor',C:'Isolation Forest'};
export function NoveltyComparison({benchmark:b}){if(!b)return <Empty message="Accepted novelty comparison unavailable. No substitute results are displayed."/>;
 return <><Card title="Novelty detection — controlled comparison" sub="Same 83 features, split, scaling, XGBoost classifier and episode policy">
 <p className="research-scope">Accepted Moodle laboratory evidence · {b.pipelines.A.benign.runs} benign sessions · {b.pipelines.A.attack.runs} controlled attack runs</p>
 <div className="benchmark-axis"><span>Attack-window novelty recall</span><span>0 — 100%</span></div>
 <div className="benchmark-bars" role="img" aria-label="Novelty recall comparison, full scale from zero to one hundred percent">{Object.entries(b.pipelines).map(([id,p])=><div key={id} className="benchmark-row"><strong>{names[id]}</strong><div className="track"><i style={{width:100*p.attack.novelty_window_recall.rate+'%'}}/></div><span>{count(p.attack.novelty_window_recall)} · {percent(p.attack.novelty_window_recall.rate)}</span></div>)}</div>
 <Table headers={['Accepted metric','OCSVM','LOF','Isolation Forest']} rows={[
 ['Benign window false positives',...Object.values(b.pipelines).map(p=>count(p.benign.window_fpr))],['False-incident sessions',...Object.values(b.pipelines).map(p=>count(p.benign.false_incident_sessions))],['Strict anomaly + correct class',...Object.values(b.pipelines).map(p=>count(p.attack.strict_end_to_end_recall))],['Production reconciled attack runs',...Object.values(b.pipelines).map(p=>count(p.attack.production_run_recall))]]}/>
 <div className="selection-result"><Badge>{b.decision.decision}</Badge><p>Neither alternative reduced observed benign false positives. Both lost novelty and strict combined recall. Production reconciliation remains a separate result: confident known patterns can retain detection despite novelty misses.</p></div>
 <details><summary>Per-class recall, uncertainty and replacement gate</summary><Table headers={['Class / attack windows','OCSVM novelty / strict','LOF novelty / strict','IF novelty / strict']} rows={Object.entries(b.pipelines.A.per_class).map(([label,v])=>[human(label)+' · '+v.windows,Object.values(b.pipelines).map(p=>p.per_class[label]).map(c=>count(c.novelty)+' / '+count(c.strict_end_to_end))].flat())}/><p>Two runs per class. Wilson intervals are descriptive; windows within runs are correlated.</p><pre>{JSON.stringify({gate:b.decision,intervals:Object.fromEntries(Object.entries(b.pipelines).map(([id,p])=>[id,{novelty:p.attack.novelty_window_recall,benign:p.benign.window_fpr}]))},null,2)}</pre></details>
 <p className="source-label">Source: {b.source}/pipeline_results.json · HASH VERIFIED</p>
 </Card></>;
}
export function ClassificationEvaluation({benchmark:b}){const [scope,setScope]=useState('all_evaluation');if(!b)return <Empty message="Accepted XGBoost evaluation unavailable."/>;const c=b.classification[scope],order=b.classification.class_order;
 const labels={ADMIN_PROBING:'ADMIN',BENIGN:'BENIGN',BRUTE_FORCE:'BRUTE',ENUMERATION_RECONNAISSANCE:'ENUM',PATH_TRAVERSAL_ATTEMPT:'PATH',REQUEST_BURST_DOS_LIKE:'BURST',SQLI_ATTEMPT:'SQLI',XSS_ATTEMPT:'XSS'};
 return <Card title="Known-pattern classification — XGBoost" sub="One fixed classifier shared by all three novelty variants">
 <div className="filters"><label>Evaluation scope<select aria-label="Classification evaluation scope" value={scope} onChange={e=>setScope(e.target.value)}><option value="all_evaluation">Combined benign + attack evidence</option><option value="attack_only">Attack holdout only</option></select></label></div>
 <div className="research-measures"><span><strong>{c.correct}/{c.support}</strong> correctly classified windows</span><span><strong>{percent(c.accuracy)}</strong> accuracy</span><span><strong>{format(c.macro_F1,5)}</strong> macro-F1</span></div>
 <p>Attack-run majority-class correctness: {count(b.pipelines.A.attack.classifier_correct_runs)}. Classifier scores are uncalibrated; classification is not proof of successful exploitation.</p>
 <div className="table-scroll confusion-matrix"><table><caption>Confusion matrix · exact counts · rows are true classes; columns are predicted classes</caption><thead><tr><th>True ↓ / predicted →</th>{order.map(x=><th key={x}><abbr title={human(x)}>{labels[x]}</abbr></th>)}</tr></thead><tbody>{c.confusion_matrix.map((row,i)=><tr key={order[i]}><th scope="row">{human(order[i])}</th>{row.map((n,j)=><td key={j} style={{background:n?`rgba(152,185,232,${Math.min(.6,.1+n/20)})`:undefined}}>{n}</td>)}</tr>)}</tbody></table></div>
 <details><summary>Per-class precision, recall, F1 and support</summary><Table headers={['Class','Precision','Recall','F1','Windows']} rows={order.map(label=>{const v=c.per_class[label];return[human(label),v.support?format(v.precision,5):'Not supported',v.support?format(v.recall,5):'Not supported',v.support?format(v['f1-score'],5):'Not supported',v.support]})}/></details>
 <p className="source-label">Source: {b.source}/confusion_matrix.json · Macro-F1 uses {c.macro_labels.length} supported true classes.</p>
 </Card>;
}
export function ResearchEvaluation({data,research,researchError,Legacy,onNavigate,initialBenchmark=null}){
 const [tab,setTab]=useState('novelty'),[benchmark,setBenchmark]=useState(initialBenchmark),[error,setError]=useState(null);
 useEffect(()=>{let active=true;if(!initialBenchmark)api('research/benchmark').then(v=>{if(v.version!=='accepted-benchmark-projection-1.0')throw Error('Unsupported benchmark contract');if(active)setBenchmark(v)}).catch(e=>{if(active)setError(e.message)});return()=>{active=false}},[]);
 return <><Card title="Behavioral v2 · accepted research model" sub="OCSVM + XGBoost · 83 features · 10-second windows" extra={<Badge>{data.model.integrity}</Badge>}><p>Unknown-anomaly persistence: {data.model.persistence}. Confident supported known patterns retain their frozen reconciliation semantics.</p></Card>
 <Tabs label="Scientific evaluation" value={tab} onChange={setTab} items={[["novelty","Novelty comparison"],["classification","Classification"],["accepted","Accepted v1/v2 evidence"],["methods","Methods & provenance"]]}/>

 {error&&<div className="alert" role="alert">{error}</div>}{!benchmark&&!error&&<p role="status">Loading hash-verified scientific comparison…</p>}
 <div hidden={tab!=='novelty'}><NoveltyComparison benchmark={benchmark}/></div>
 <div hidden={tab!=='classification'}><ClassificationEvaluation benchmark={benchmark}/></div>
 <div hidden={tab!=='accepted'}><p className="method-note">Paired architecture comparison on accepted evidence. This is distinct from the controlled novelty-detector experiment.</p><Legacy data={data} research={research} researchError={researchError}/></div>
 <div hidden={tab!=='methods'}><Card title="From telemetry to interpreted episodes"><div className="flow-strip"><span>10-second window</span><span>→ 83 frozen features</span><span>→ preprocessing</span><span>→ OCSVM + XGBoost</span><span>→ reconciliation</span><span>→ episodes</span></div><p>Novelty detects departures from the benign reference. XGBoost labels known patterns. UNKNOWN persistence and confident known-pattern decisions follow the saved model policy; every detection does not require two windows.</p><button className="button" onClick={()=>onNavigate?.('monitoring')}>Inspect original observation explanations</button><details><summary>Model identity, cutoffs, labels and source hashes</summary><pre>{JSON.stringify(data.model,null,2)}</pre></details><details><summary>Controlled experiment configuration and provenance</summary><pre>{JSON.stringify(benchmark?{root:benchmark.root_sha256,config:benchmark.config,splits:benchmark.splits,pipelines:benchmark.pipelines,score_semantics:benchmark.score_semantics}:null,null,2)}</pre></details></Card></div>
 <div className="research-limit">Limited laboratory support: six benign sessions; two attack runs per class. No population-level significance or equal-LMS-accuracy claim. <details><summary>Validation scope and limitations</summary><ul>{(data.model.limitations||[]).map(x=><li key={x}>{x}</li>)}</ul>{benchmark?.limitations.map(x=><p key={x}>{x}</p>)}</details></div>
 </>;
}
