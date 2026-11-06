import {test,after} from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {createServer} from 'vite';
import React from 'react';
import {renderToStaticMarkup} from 'react-dom/server';
const payload=JSON.parse(await readFile('../../outputs/normalization/task2c_03/capability_acceptance.json','utf8'));
const server=await createServer({server:{middlewareMode:true,hmr:false,ws:false,watch:null},appType:'custom'});
const c=await server.ssrLoadModule('/src/components/IngestionDiagnostics.jsx');
after(async()=>{await server.close()});
const render=(component,props={})=>renderToStaticMarkup(React.createElement(component,props));
test('compact diagnostics view is offline and preserves an empty state',()=>{
 const html=render(c.IngestionDiagnostics);
 for(const text of ['Telemetry ingestion diagnostics','no training or network scan','Auto-detect','Optional declarative field mapping','No data is stored'])assert.ok(html.includes(text));
 assert.ok(html.includes('disabled=""'));
});
test('generic rich source exposes real compatibility and capability denominator',()=>{
 const html=render(c.IngestionResult,{value:payload.sources.GENERIC_RICH_FIXTURE});
 for(const text of ['13/20 (65.0%)','BEHAVIORAL_COMPATIBLE_WITH_OPTIONAL_CONTEXT_MISSING','generic_web','canonical-web-security-event-1.0','NOT_APPLICABLE','NOT_AVAILABLE','equal accuracy'])assert.ok(html.includes(text));
});
test('partial telemetry explicitly blocks inference instead of asserting benign',()=>{
 const html=render(c.IngestionResult,{value:payload.sources.GENERIC_PARTIAL_FIXTURE});
 assert.ok(html.includes('BEHAVIORAL_INSUFFICIENT_TELEMETRY'));
 assert.ok(html.includes('9/20 (45.0%)'));
 assert.ok(html.includes('no model verdict generated'));
 assert.ok(!html.includes('BENIGN'));
});
test('advanced fields show mapping and provenance without raw canonical events',()=>{
 const html=render(c.IngestionResult,{value:payload.sources.GENERIC_RICH_FIXTURE});
 assert.ok(html.includes('<summary>Mapping, missing fields and technical provenance</summary>'));
 assert.ok(html.includes('mapping_sha256'));
 assert.ok(!html.includes('item=4')&&!html.includes('FixtureAgent/1.0'));
});
