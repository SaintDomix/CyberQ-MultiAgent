import {test,after} from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {createServer} from 'vite';
import React from 'react';
import {renderToStaticMarkup} from 'react-dom/server';
const path=process.env.LIVE_EXPLANATION_PAYLOAD;
if(!path)throw new Error('Set LIVE_EXPLANATION_PAYLOAD to the actual accept_live_explainability.py API receipt');
const payload=JSON.parse(await readFile(path,'utf8'));
assert.equal(payload.mode,'LIVE_LAB');assert.equal(payload.all_current_vectors_verified,true);
const server=await createServer({server:{middlewareMode:true,hmr:false,ws:false,watch:null},appType:'custom'});
const pages=await server.ssrLoadModule('/src/pages/ProductPages.jsx');
after(async()=>{await server.close()});
const render=o=>renderToStaticMarkup(React.createElement(pages.Explanation,{observation:o,onClose:()=>{},onEvidence:()=>{}}));
for(const state of ['BENIGN','UNKNOWN_ANOMALY'])test('actual LIVE API '+state+' renders the existing drawer',()=>{
 const o=payload.observations.find(o=>o.reconciled_label===state);assert.ok(o);
 const html=render(o);
 assert.ok(html.includes('Model observation explained'));
 assert.ok(html.includes(state==='BENIGN'?'WHY DOES THIS WINDOW APPEAR NORMAL?':'WHY WAS THIS WINDOW FLAGGED?'));
 assert.ok(!html.includes('Human-readable interpretation unavailable'));
 for(const text of ['Observed','Benign TRAIN median','Technical details','OCSVM','uncalibrated class score','LIVE_JOURNAL_WINDOW_ROW'])assert.ok(html.includes(text));
 assert.ok(html.includes(o.explanation.provenance.feature_evidence.vector_sha256));
 assert.ok(html.includes('83/83'));
});
test('actual SQLI-classified UNKNOWN stays distinct from a known attempt',()=>{
 const o=payload.observations.find(o=>o.reconciled_label==='UNKNOWN_ANOMALY');
 assert.equal(o.xgb_label,'SQLI_ATTEMPT');
 assert.ok(o.xgb_score<o.explanation.classification.accepted_confidence_threshold);
 const html=render(o);assert.ok(html.includes('No known attack class was established'));
 assert.ok(html.includes('SQLI ATTEMPT'));assert.ok(html.includes('0.80 threshold'));
});
test('missing-SHAP UI fixture still renders real anomaly factors',()=>{
 const o=structuredClone(payload.observations.find(o=>o.reconciled_label==='UNKNOWN_ANOMALY'));
 o.explanation.shap={status:'NOT_REQUESTED',top_features:[]};
 o.explanation.evidence_quality.shap_status='NOT_REQUESTED';
 const html=render(o);assert.ok(html.includes('SHAP NOT AVAILABLE FOR THIS LIVE OBSERVATION'));
 assert.ok(html.includes('WHY WAS THIS WINDOW FLAGGED?'));assert.ok(!html.includes('Human-readable interpretation unavailable'));
});
test('a genuinely absent vector displays its concrete reason',()=>{
 const o=structuredClone(payload.observations[0]);delete o.explanation.anomaly;
 o.explanation.evidence_quality.reason_code='FEATURE_VECTOR_NOT_RETAINED';
 assert.ok(render(o).includes('FEATURE_VECTOR_NOT_RETAINED'));
});
