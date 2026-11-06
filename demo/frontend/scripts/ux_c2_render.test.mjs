import {test,after} from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {execFileSync} from 'node:child_process';
import {createServer} from 'vite';
import React from 'react';
import {renderToStaticMarkup} from 'react-dom/server';
const body=process.env.UX_CLARITY_PAYLOAD?await readFile(process.env.UX_CLARITY_PAYLOAD,'utf8'):execFileSync('../../.venv/bin/python',['-B','../../scripts/export_ux_fixture.py'],{encoding:'utf8',maxBuffer:12*1024*1024,env:{...process.env,PYTHONDONTWRITEBYTECODE:'1',OPENBLAS_NUM_THREADS:'1'}});
const p=JSON.parse(body),server=await createServer({server:{middlewareMode:true,hmr:false,ws:false,watch:null},appType:'custom'});
after(async()=>server.close());
const c=await server.ssrLoadModule('/src/components/CqiPresentation.jsx'),ctx=await server.ssrLoadModule('/src/components/AssessmentContext.jsx'),pages=await server.ssrLoadModule('/src/pages/ProductPages.jsx'),posture=await server.ssrLoadModule('/src/components/PostureWorkspace.jsx'),execution=await server.ssrLoadModule('/src/components/PostureExecution.jsx'),evidence=await server.ssrLoadModule('/src/utils/evidence.js');
const render=(C,props={})=>renderToStaticMarkup(React.createElement(C,props));
test('actual patch root selects HIGH member with its own title and verification, not first LOW member',()=>{
 const data=p.attack,root=data.scientific_cqi.contributors.find(r=>r.root_id==='MOODLE_PATCH_LEVEL');assert.equal(root.members[0].severity,'LOW');
 const before=JSON.stringify(root),r=evidence.representativeForRoot(root,data.posture),member=data.posture.find(f=>f.finding_id===r.finding_id);
 assert.equal(r.severity,'HIGH');assert.equal(r.title,member.title);assert.equal(r.confirmation,member.confirmation);assert.equal(before,JSON.stringify(root));
});
test('unscored PASS/unsupported severe member never replaces supported weakness',()=>{
 const root={root_id:'fixture',members:[{finding_id:'pass',severity:'CRITICAL',hazard:0},{finding_id:'weak',severity:'HIGH',confirmation:'LIKELY',hazard:.3}]};
 const r=evidence.representativeForRoot(root,[{finding_id:'weak',title:'Actual high member',severity:'HIGH',confirmation:'LIKELY'}]);assert.equal(r.title,'Actual high member');assert.equal(r.confirmation,'LIKELY');
});
test('Overview has one gauge, actual coverage, secondary conservative result and collapsed six dimensions',()=>{
 const html=render(c.EvidenceOverview,{data:p.benign,onNavigate:()=>{},onEvidence:()=>{}});
 for(const s of ['Quality of assessed controls','49.73','51.75%','0.19','conditional','Evidence completeness','Dimensions and evidence completeness','Inspect D5','Inspect D6'])assert.ok(html.includes(s),s);
 assert.equal((html.match(/class="gauge"/g)||[]).length,1);assert.ok(html.includes('<details class="overview-dimension-details">'));assert.ok(!html.includes('Suggested next steps'));
});
test('Overview discloses unavailable D5 and D6 without declaring insecurity',()=>{
 const data=structuredClone(p.benign);for(const d of data.scientific_cqi.dimensions.filter(d=>['D5','D6'].includes(d.dimension_id)))d.status='INSUFFICIENT_EVIDENCE';
 const html=render(c.EvidenceGaps,{q:data.scientific_cqi});for(const s of ['D5: insufficient internal server evidence','D6: trustworthy relevant telemetry unavailable','does not by itself prove insecurity'])assert.ok(html.includes(s));
});
test('compact context closes selection controls, names source, provides view-only reset',()=>{
 const html=render(ctx.AssessmentContext,{data:p.benign,compact:true,mode:'ACCEPTED_REPLAY',replay:'BENIGN_TEST',run:'',onReset:()=>{}});
 for(const s of ['ACCEPTED EVIDENCE REPLAY','<details class="context-change">','Reset to all accepted runs','does not execute replay'])assert.ok(html.includes(s),s);
});
test('failed LIVE state never inherits accepted-baseline label or completion timestamp',()=>{
 const data={...p.benign,assessment:null,selection:{latest_attempt_status:'FAILED'},history:[]};
 const html=render(ctx.AssessmentContext,{data,mode:'LIVE_LAB',assessment:''});assert.ok(html.includes('Failed'));assert.ok(html.includes('No completed collection'));assert.ok(!html.includes('Accepted research baseline'));
});
test('source dropdown selects completed evidence only, full attempt history remains separate',()=>{
 const data={...p.benign,history:[{assessment_id:'bad',status:'FAILED'},{assessment_id:'good',status:'PARTIAL',mode:'STANDARD'}]};
 const html=render(ctx.AssessmentContext,{data,mode:'LIVE_LAB',assessment:''});assert.ok(html.includes('value="good"'));assert.ok(!html.includes('value="bad"'));assert.ok(html.includes('Assessment history'));
});
test('legacy view preserves six dimensions, contributors and sensitivity navigation',()=>{
 const html=render(pages.LegacyQuality,{data:p.attack,onEvidence:()=>{}});for(const s of ['Legacy CQI · fusion-cqi-1.1','Why this score','Sensitivity &amp; policy','Contributors and root-condition grouping','D5','D6'])assert.ok(html.includes(s),s);
 assert.ok(render(c.EvidenceQuality,{data:p.attack,Fusion:()=>null,Legacy:pages.LegacyQuality}).includes('Legacy CQI v1'));
});
for(const status of ['QUEUED','RUNNING','COMPLETE','PARTIAL','FAILED','INTERRUPTED'])test('latest execution displays real '+status+' independent of selected snapshot',()=>{
 const e={assessment_id:'new-'+status,status,assessment_profile:'STANDARD',target:'http://fixture.invalid/',provider_statuses:{native:'COMPLETE',zap:status},error:status==='FAILED'?'Fixture failure':null,cancellation:{eligible:status==='RUNNING'}};
 const html=render(execution.PostureExecution,{execution:e});assert.ok(html.includes('new-'+status));assert.ok(html.includes('Independent of the immutable evidence'));assert.equal(html.includes('Request cancellation'),['QUEUED','RUNNING'].includes(status));
});
test('preview disables owned cancellation while fake deployable state permits explicit request',()=>{
 const e={assessment_id:'fake',status:'RUNNING',cancellation:{eligible:true}};
 assert.ok(render(execution.PostureExecution,{execution:e,readOnly:true}).includes('disabled=""'));assert.ok(!render(execution.PostureExecution,{execution:e}).includes('disabled=""'));
});
test('profiles are discoverable and running job blocks duplicate start',()=>{
 const data={...p.benign,status:{...p.benign.status,mode:'LIVE_LAB'},latest_execution:{assessment_id:'new',status:'RUNNING'},preview_read_only:false};
 const html=render(posture.PostureWorkspace,{data});for(const s of ['New assessment · STANDARD / FULL / Passive','FULL_AUTHORIZED','PASSIVE_BASELINE','View progress and cancellation'])assert.ok(html.includes(s),s);
 assert.ok(html.includes('disabled=""'));assert.ok(execution.executionBusy(data.latest_execution));
});
test('summary rendering does not mutate scoring, predictions or grouping',()=>{
 const before=JSON.stringify(p.attack);render(c.EvidenceOverview,{data:p.attack,onNavigate:()=>{},onEvidence:()=>{}});render(c.Contributors,{data:p.attack,onEvidence:()=>{}});assert.equal(before,JSON.stringify(p.attack));
});

test('same finding ID in multiple source members cannot mix a LOW title into HIGH evidence',()=>{
 const root={root_id:'same-control',members:[{finding_id:'SAME',source_id:'high-source',severity:'HIGH',confirmation:'CONFIRMED',hazard:.6}]};
 const r=evidence.representativeForRoot(root,[{finding_id:'canonical',member_evidence_ids:['high-source','low-source'],evidence_summary:{members:[{finding_id:'SAME',evidence_id:'low-source',finding_type:'Low source title'},{finding_id:'SAME',evidence_id:'high-source',finding_type:'High source title'}]}}]);
 assert.equal(r.title,'High source title');assert.equal(r.severity,'HIGH');assert.equal(r.evidence_id,'high-source');
});
