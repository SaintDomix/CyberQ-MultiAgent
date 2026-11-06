import {test,after} from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {createServer} from 'vite';
import React from 'react';
import {renderToStaticMarkup} from 'react-dom/server';
const p=JSON.parse(await readFile(process.env.UX_CLARITY_PAYLOAD||'/tmp/ux_c2_payload.json','utf8'));
const server=await createServer({server:{middlewareMode:true,hmr:false,ws:false,watch:null},appType:'custom'});after(()=>server.close());
const context=await server.ssrLoadModule('/src/components/AssessmentContext.jsx'),app=await server.ssrLoadModule('/src/App.jsx'),e=await server.ssrLoadModule('/src/utils/evidence.js'),posture=await server.ssrLoadModule('/src/components/PostureWorkspace.jsx');
const render=(C,props={})=>renderToStaticMarkup(React.createElement(C,props));
test('shared product chrome removes redundant branding without changing seven destinations',()=>{
 const html=render(app.default);assert.ok(html.includes('CyberQuality'));assert.ok(!html.includes('EVIDENCE → CONTEXT'));assert.ok(!html.includes('MOODLE LAB · RESEARCH'));assert.ok(!html.includes('Accepted model verified'));assert.equal((html.match(/aria-label="(?:Overview|Security posture|Behavioral monitoring|Incidents|Cybersecurity quality|Model &amp; research|System &amp; evidence)"/g)||[]).length,7);
});
test('context has compact discoverable view-only selectors and truthful replay timestamp semantics',()=>{
 const html=render(context.AssessmentContext,{data:p.benign,mode:'ACCEPTED_REPLAY',replay:'BENIGN_TEST',compact:true,completenessInPage:true});
 for(const text of ['Change evidence','Evidence as of','Blind benign evaluation','ACCEPTED EVIDENCE REPLAY','Reset to all accepted runs'])assert.ok(html.includes(text),text);
 assert.ok(!html.includes('PARTIAL_EVIDENCE'));assert.ok(!html.includes('Start monitoring'));assert.ok(!html.includes('Stop monitoring'));assert.ok(!html.includes('Run Security Posture'));
});
test('other pages retain explicit completeness and model evidence remains in its destination',()=>{
 const html=render(context.AssessmentContext,{data:p.benign,mode:'ACCEPTED_REPLAY',replay:'BENIGN_TEST',compact:true});assert.ok(html.includes('Partial evidence'));
});
test('failed HTTPS control is described as observed HTTP, without claiming HTTPS is unavailable',()=>{
 const f={finding_id:'TLS-001',title:'HTTPS enabled',status:'FAIL',severity:'HIGH',description:'The assessed target is served over unencrypted HTTP.'},before=JSON.stringify(f);
 assert.equal(e.findingDisplayTitle(f),'Assessed target uses unencrypted HTTP');assert.equal(JSON.stringify(f),before);assert.equal(f.severity,'HIGH');
});
test('display change requires explicit evidence, never infers from URL or FAIL alone',()=>{
 assert.equal(e.findingDisplayTitle({finding_id:'TLS-001',title:'HTTPS enabled',status:'FAIL',url:'http://example.test/'}),'HTTPS enabled');
 assert.equal(e.findingDisplayTitle({finding_id:'TLS-001',title:'HTTPS enabled',status:'PASS',observed_value:'Target uses HTTP'}),'HTTPS enabled');
 assert.equal(e.findingDisplayTitle({finding_id:'unrelated',title:'HTTPS enabled',status:'FAIL',observed_value:'Target uses HTTP'}),'HTTPS enabled');
});
test('root uses same source member and preserves original control label for technical evidence',()=>{
 const root={root_id:'transport',members:[{finding_id:'TLS-001',source_id:'http-source',severity:'HIGH',confirmation:'CONFIRMED',status:'FAIL',hazard:.75}]};
 const r=e.representativeForRoot(root,[{finding_id:'TLS-001',title:'HTTPS enabled',member_evidence_ids:['http-source'],evidence_summary:{members:[{evidence_id:'http-source',finding_type:'HTTPS enabled',observed_value:'Target uses HTTP'}]}}]);
 assert.equal(r.title,'Assessed target uses unencrypted HTTP');assert.equal(r.source_title,'HTTPS enabled');assert.equal(r.severity,'HIGH');assert.equal(r.confirmation,'CONFIRMED');assert.equal(r.hazard,.75);
});
test('posture result title improves without removing source evidence or inspection path',()=>{
 const data=structuredClone(p.benign);data.posture.unshift({finding_id:'TLS-001',title:'HTTPS enabled',status:'FAIL',severity:'HIGH',confirmation:'CONFIRMED',description:'The assessed target is served over unencrypted HTTP.'});
 const html=render(posture.PostureWorkspace,{data});assert.ok(html.includes('Assessed target uses unencrypted HTTP'));assert.ok(html.includes('Inspect finding'));assert.ok(html.includes('FULL_AUTHORIZED'));
});
test('view selector code has no runtime or mode-transition call',async()=>{
 const s=await readFile('src/components/AssessmentContext.jsx','utf8');assert.ok(!s.includes('fetch('));assert.ok(!s.includes('control('));assert.ok(!s.includes('selectMode('));
});
