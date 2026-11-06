import {test,after} from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {createServer} from 'vite';
import React from 'react';
import {renderToStaticMarkup} from 'react-dom/server';
const body=JSON.parse(await readFile(process.env.MULTIAGENT_TEST_PAYLOAD||'../../runtime/coursework/assignment4/ui-task.json','utf8'));
const server=await createServer({configFile:false,cacheDir:'../../runtime/coursework/frontend/test-cache',server:{middlewareMode:true,hmr:false,ws:false,watch:null},appType:'custom'});
after(()=>server.close());
const {TaskEvidence,AgentTable,default:MultiAgent,FullAssessmentContext,assessmentPageData}=await server.ssrLoadModule('/src/components/MultiAgent.jsx');
const render=(Component,props)=>renderToStaticMarkup(React.createElement(Component,props));
test('actual task renders CQI, JSON messages, calls, evidence and limitations',()=>{
 const html=render(TaskEvidence,{task:body.state,events:body.events});
 for(const text of [body.state.task_id,'HISTORICAL','25.00%','N/A','Verification outcomes','PARTIAL','Structured JSON message trace','Real tool invocation log','Evidence references','cqi-evidence-2.0'])assert.ok(html.includes(text),text);
 assert.ok(!html.includes('undefined'));assert.ok(html.includes('not a current live assessment'));
});
test('failed task cannot render a successful assessment or CQI',()=>{
 const failed={...body.state,status:'FAILED',result:null,failure:{code:'EVIDENCE_REJECTED',message:'Evidence invalid'}};
 const html=render(TaskEvidence,{task:failed,events:[]});
 assert.ok(html.includes('No successful cybersecurity assessment'));assert.ok(html.includes('No final CQI result available'));
 assert.ok(!html.includes('Workflow completed:'));
});
test('zero-call locked task shows N/A rather than an invented percentage',()=>{
 const locked={...body.state,status:'BLOCKED',result:null,distribution:{all_specialist_calls:{denominator:0},tool_only:{denominator:0},llm_only:{denominator:0},max_specialist_percent:null,within_40_percent:null}};
 const html=render(TaskEvidence,{task:locked,events:[]});assert.ok(html.includes('Maximum share: N/A'));assert.ok(html.includes('40% requirement: N/A'));
});
test('all five specialist rows plus Coordinator are data driven',()=>{
 const spec=['coordinator','native','zap','behavioral','verification','quality'].map(agent=>({agent,responsibility:'role',tools:[]}));
 const html=render(AgentTable,{spec,state:body.state});
 for(const agent of spec)assert.ok(html.includes(agent.agent));assert.ok(html.includes('COMPLETED'));
});
test('initial view states the lab lock and offers the coordinated action',()=>{
 const html=render(MultiAgent,{compact:true});assert.ok(html.includes('OFFLINE EVIDENCE ONLY'));assert.ok(html.includes('Run Full Assessment'));
 assert.ok(html.includes('Assessment operating mode'));assert.ok(html.includes('LIVE_LAB'));
 assert.ok(html.includes('disabled=""'));assert.ok(html.includes('No LLM calls are simulated'));
});

test('compact dashboard uses real findings, verification and six CQI dimensions',()=>{
 const html=render(TaskEvidence,{task:body.state,events:body.events,compact:true,onNavigate:()=>{}});
 assert.ok(html.includes('Security summary'));
 assert.ok(html.includes('Detailed results, JSON messages and logs'));
 assert.ok(html.includes('Evidence verification'));assert.ok(!html.includes('Verification outcomes'));
 for(const d of body.state.result.cqi.dimensions)assert.ok(html.includes(d.dimension_id));
});
test('independent security pages remain linked without running a task',()=>{
 const html=render(MultiAgent,{compact:true,onNavigate:()=>{}});
 for(const text of ['Independent security operations','Native Security Posture / ZAP profiles','Behavioral monitoring controls','Agent messages and logs'])assert.ok(html.includes(text));
});

test('all four pages render the same full-assessment identity and exact branch data',async()=>{
 const products=JSON.parse(await readFile(process.env.PRODUCT_TEST_PAYLOAD,'utf8'));
 const base=products.attack,task=body.state,view=body.assessment_view;
 assert.ok(view,'Export real persisted branch projection first');
 const data=assessmentPageData(base,view,task);
 assert.equal(data.full_assessment.task_id,task.task_id);
 assert.deepEqual(data.observations,view.behavioral.observations);
 assert.deepEqual(data.scientific_cqi,task.result.cqi);
 const workspace={task,view,selectedId:task.task_id,recent:[task],select(){},official:null};
 for(const page of ['Overview','Security Posture','Behavioral Monitoring','Multi-Agent']){
  const html=render(FullAssessmentContext,{workspace});
  assert.ok(html.includes(`data-assessment-id="${task.task_id}"`),page);
 }
 assert.equal(assessmentPageData(base,view,{...task,task_id:'ma-other'}),null);
 assert.equal(assessmentPageData(base,{...view,context:{...view.context,updated_at:'older'}},task),null);
});
test('Overview and Multi-Agent keep summary and technical responsibilities separate',()=>{
 const workspace={spec:{agents:[]},task:body.state,events:body.events,recent:[],busy:false,error:''};
 const overview=render(MultiAgent,{compact:true,workspace});
 const technical=render(MultiAgent,{workspace});
 assert.ok(overview.includes('Run Full Assessment'));assert.ok(overview.includes('Final CQI'));
 assert.ok(!overview.includes('Structured JSON message trace'));
 assert.ok(!overview.includes('Real tool invocation log'));
 assert.ok(!technical.includes('Run Full Assessment'));assert.ok(!technical.includes('Final CQI'));
 assert.ok(technical.includes('Structured JSON message trace'));assert.ok(technical.includes('Real tool invocation log'));
});
test('last valid CQI is explicitly separate from a blocked selected attempt',()=>{
 const task={...body.state,task_id:'ma-blocked',status:'BLOCKED',result:null};
 const html=render(FullAssessmentContext,{workspace:{task,selectedId:task.task_id,recent:[task],select(){},official:{task_id:body.state.task_id,completed_at:body.state.updated_at,cqi:body.state.result.cqi}}});
 assert.ok(html.includes('Last valid Overall CQI'));assert.ok(html.includes('not the selected attempt'));
 assert.ok(html.includes(body.state.task_id));assert.ok(html.includes('ma-blocked'));
});
test('selected Posture and Monitoring render their persisted full-assessment branches',async()=>{
 const products=JSON.parse(await readFile(process.env.PRODUCT_TEST_PAYLOAD,'utf8'));
 const data=assessmentPageData(products.attack,body.assessment_view,body.state);
 const {Posture,Monitoring}=await server.ssrLoadModule('/src/pages/ProductPages.jsx');
 const posture=render(Posture,{data,onAssessment(){}});
 const monitoring=render(Monitoring,{data,onSelect(){},onEvidence(){}});
 assert.ok(posture.includes(body.state.task_id));assert.ok(posture.includes('Full assessment'));
 assert.ok(posture.includes(body.assessment_view.native.findings[0].finding_id));
 assert.ok(monitoring.includes(body.state.task_id));
 assert.ok(monitoring.includes('Monitoring controls'));assert.ok(monitoring.includes('Behavioral observations'));
 assert.ok(!posture.includes('No completed current posture'));
});
