import {test,after} from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {execFileSync} from 'node:child_process';
import {createServer} from 'vite';
import React from 'react';
import {renderToStaticMarkup} from 'react-dom/server';
let body;
if(process.env.UX_CLARITY_PAYLOAD)body=await readFile(process.env.UX_CLARITY_PAYLOAD,'utf8');
else {try{body=execFileSync('../../.venv/bin/python',['-B','../../scripts/export_ux_fixture.py'],{encoding:'utf8',maxBuffer:12*1024*1024,
 env:{...process.env,PYTHONDONTWRITEBYTECODE:'1',OPENBLAS_NUM_THREADS:'1',OMP_NUM_THREADS:'1'}})}catch(e){throw Error('Read-only fixture export failed: '+(e.code||e.status)+'; an explicit UX_CLARITY_PAYLOAD file is also supported.')}}
const p=JSON.parse(body);
const server=await createServer({server:{middlewareMode:true,hmr:false,ws:false,watch:null},appType:'custom'});
after(async()=>server.close());
const c=await server.ssrLoadModule('/src/components/CqiPresentation.jsx');
const research=await server.ssrLoadModule('/src/components/ResearchEvaluation.jsx');
const posture=await server.ssrLoadModule('/src/components/PostureWorkspace.jsx');
const pages=await server.ssrLoadModule('/src/pages/ProductPages.jsx');
const app=await server.ssrLoadModule('/src/App.jsx');
const render=(component,props={})=>renderToStaticMarkup(React.createElement(component,props));
test('original gauge is the focal conditional score with inseparable coverage and conservative label',()=>{
 const html=render(c.QualityHero,{q:p.benign.scientific_cqi});for(const s of ['class="gauge"','Observed-evidence quality — conditional','49.73','51.75%','0.19','Conservative policy result','zero result does not establish zero protection'])assert.ok(html.includes(s),s);
 assert.ok(!html.includes('quality-triplet'));
});
test('unavailable D5/D6 are not replaced by numeric zero quality',()=>{
 const q=structuredClone(p.benign.scientific_cqi);for(const d of q.dimensions.filter(d=>['D5','D6'].includes(d.dimension_id))){d.conditional_quality=null;d.coverage=0;d.status='INSUFFICIENT_EVIDENCE';}
 const html=render(c.DimensionSummary,{q,onSelect:()=>{}});assert.ok((html.match(/Unavailable/g)||[]).length>=2);assert.ok(!html.includes('NaN'));assert.ok(html.includes('Inspect D6'));
});
test('three novelty pipelines render source counts and distinct reconciliation metric',()=>{
 const html=render(research.NoveltyComparison,{benchmark:p.benchmark});for(const s of ['65/68','41/68','3/68','63/68','40/68','1/33','0/6','14/14','KEEP_OCSVM','0 — 100%','pipeline_results.json'])assert.ok(html.includes(s),s);
});
test('classification matrix uses all exact source counts and eight accepted class names',()=>{
 const html=render(research.ClassificationEvaluation,{benchmark:p.benchmark});
 assert.ok(html.includes('99/101'));assert.ok(html.includes('98.02%'));assert.ok(html.includes('0.97727'));assert.ok(html.includes('rows are true classes'));
 assert.equal((html.match(/<abbr/g)||[]).length,8);assert.ok(html.includes('SQLI ATTEMPT'));assert.ok(!html.includes('successful attack probability'));
});
test('all seven pages preserve functional rendering and a source version',()=>{
 for(const [name,Page] of Object.entries(pages.Pages)){
  const html=render(Page,{data:p.attack,research:p.research,onNavigate:()=>{},onEvidence:()=>{},onSelect:()=>{}});
  assert.ok(html.length>400,name);assert.ok(!html.includes('undefined'),name);
 }
 const nav=render(app.Navigation,{page:'posture',onSelect:()=>{}});assert.equal((nav.match(/<button/g)||[]).length,7);assert.ok(nav.includes('aria-label="Behavioral monitoring"'));
});
test('view selection no longer calls operational mode endpoint',async()=>{
 const source=await readFile('src/App.jsx','utf8');assert.ok(!source.includes('await selectMode'));assert.ok(source.includes('if(e.status!==404||assessment)throw e'));
});
test('posture preserves category, legacy ZAP-source and unmapped selectors',()=>{
 const html=render(posture.PostureWorkspace,{data:p.benign});
 for(const s of ['Finding category','Unmapped ZAP rule','value="OWASP_ZAP"','Finding severity','Finding source','Finding dimension'])assert.ok(html.includes(s),s);
});
test('history view shows unpaired D6 and comparison limits',()=>{
 const data=structuredClone(p.benign);data.selection.historical_selection=true;data.scientific_cqi.behavioral.available=false;
 const html=render(c.BehaviorSummary,{data,onNavigate:()=>{}});assert.ok(html.includes('D6 is unavailable'));assert.ok(html.includes('Current incidents are not substituted'));
});
test('numeric explanations and SHAP are still available beneath the summary',()=>{
 const o=p.attack.observations.find(o=>o.xgb_label==='SQLI_ATTEMPT');
 const html=render(pages.Explanation,{observation:o,onClose:()=>{},onEvidence:()=>{}});
 for(const s of ['Summary','Important factors','Observed','Benign TRAIN median','Technical details','XGBoost attribution','Raw feature values','uncalibrated'])assert.ok(html.includes(s),s);
 assert.ok(!html.includes('successful SQL injection'));
});
test('new UI keeps model data immutable and disclosure does not rewrite predictions',()=>{
 const before=JSON.stringify(p.attack);render(pages.Overview,{data:p.attack,onNavigate:()=>{},onEvidence:()=>{}});assert.equal(before,JSON.stringify(p.attack));
});
