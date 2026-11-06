import {test,after} from 'node:test';
import assert from 'node:assert/strict';
import {createServer} from 'vite';
import React from 'react';
import {renderToStaticMarkup} from 'react-dom/server';
const server=await createServer({server:{middlewareMode:true,hmr:false,ws:false,watch:null},appType:'custom'});
after(()=>server.close());
const {MonitoringControlPanel}=await server.ssrLoadModule('/src/components/MonitoringControls.jsx');
const state={schema_version:'monitor-control-1.0',process_running:false,start_available:true,stop_available:false};
const data={status:{mode:'LIVE_LAB'}};
const render=props=>renderToStaticMarkup(React.createElement(MonitoringControlPanel,{data,state,onAction:()=>{},...props}));
test('stopped controller has a visible enabled start and explains retained evidence',()=>{
 const html=render();assert.ok(html.includes('Stopped'));assert.ok(html.includes('Start Monitoring'));
 assert.ok(!html.includes('disabled=""'));assert.ok(html.includes('Saved observations'));assert.ok(!html.includes('Stop Monitoring'));
});
test('owned running monitor has stop only and cannot offer a duplicate start',()=>{
 const html=render({state:{...state,process_running:true,start_available:false,stop_available:true}});
 assert.ok(html.includes('Running'));assert.ok(html.includes('Stop Monitoring'));assert.ok(!html.includes('Start Monitoring'));assert.ok(!html.includes('disabled=""'));
});
test('unknown status fails closed',()=>{
 const html=render({state:null});assert.ok(html.includes('Unknown'));assert.ok(html.includes('disabled=""'));assert.ok(!html.includes('Stopped'));
});
test('replay selection cannot start live monitoring',()=>{
 const html=render({data:{status:{mode:'ACCEPTED_REPLAY'}}});assert.ok(html.includes('disabled=""'));assert.ok(html.includes('Select LIVE evidence'));
});
test('preview keeps operational controls disabled',()=>{
 const html=render({data:{...data,preview_read_only:true}});assert.ok(html.includes('disabled=""'));assert.ok(html.includes('read-only preview'));
});
test('busy operation prevents duplicate clicks',()=>{
 const html=render({busy:true});assert.ok(html.includes('Starting…'));assert.ok(html.includes('disabled=""'));
});
test('operation feedback and errors are accessible',()=>{
 const html=render({error:'Fixture operation refused',feedback:'Saved observations are preserved.'});assert.ok(html.includes('role="alert"'));assert.ok(html.includes('Fixture operation refused'));assert.ok(html.includes('Saved observations are preserved.'));
});
test('missing source reason is visible and does not become PASS',()=>{
 const html=render({state:{...state,start_available:false,unavailable_reason:'APACHE_SOURCE_UNREADABLE'}});assert.ok(html.includes('Apache log is missing or unreadable'));assert.ok(html.includes('disabled=""'));
});
