import React,{useState} from 'react';
import {api} from '../api/client.js';
import {Card,Badge} from './UI.jsx';

export function IngestionResult({value}){
 if(!value)return <p className="muted">Inspect a small sample to see actual format, field coverage and compatibility. No data is stored and no scanner or model is started.</p>;
 const c=value.capabilities;
 return <><div className="badges"><Badge>{value.state}</Badge><Badge>{c.behavioral.state}</Badge></div>
 <p>Platform: {c.adapter.platform_id} · Adapter: {c.adapter.adapter_id} · Format: {value.detection.format??'Mapping required'}</p>
 <p>Schema: {value.canonical_schema_version} · {value.quality.parsed_records}/{value.quality.input_records} records parsed · {value.quality.rejected_records} rejected.</p>
 <p>Capability coverage: {c.coverage.available}/{c.coverage.denominator} ({c.coverage.percentage.toFixed(1)}%). {c.coverage.meaning}</p>
 <p className="note">{c.behavioral.reason} Compatibility does not establish equal accuracy on another LMS.</p><details><summary>Capabilities, applicability and missing prerequisites</summary>
 <ul>{Object.entries(c.capabilities).filter(([,v])=>v.state!=='AVAILABLE').map(([k,v])=><li key={k}>{k}: {v.state} — {v.reason}</li>)}</ul></details>
 <details><summary>Mapping, missing fields and technical provenance</summary><pre>{JSON.stringify({mapping:value.mapping,quality:value.quality,source:value.source,adapter:c.adapter},null,2)}</pre></details></>;
}

export function IngestionDiagnostics({readOnly=false}){
 const [example,setExample]=useState(false),[dependencies,setDependencies]=useState(null);
 const [text,setText]=useState(''),[format,setFormat]=useState(''),[platform,setPlatform]=useState('generic_web'),[mapping,setMapping]=useState('{}'),[value,setValue]=useState(null),[error,setError]=useState(''),[busy,setBusy]=useState(false);
 async function inspect(){setExample(false);setBusy(true);setError('');setValue(null);try{
  const response=await fetch('/api/ingestion/inspect',{method:'POST',headers:{'Content-Type':'application/json','X-Product-Control':'1'},body:JSON.stringify({text,format:format||null,platform,mapping:JSON.parse(mapping)})});
  if(!response.ok)throw new Error('Source or mapping could not be inspected; check declared format and field types.');
  setValue(await response.json());
 }catch(e){setError(e instanceof SyntaxError?'Mapping must be a JSON object.':e.message)}finally{setBusy(false)}}
 return <Card title="Telemetry ingestion diagnostics" sub="Canonical normalization · offline sample only · no training or network scan">
 <div className="filters"><label>Source platform <select value={platform} onChange={e=>setPlatform(e.target.value)}><option value="generic_web">Generic web</option><option value="moodle">Moodle compatibility</option></select></label><label>Telemetry format <select value={format} onChange={e=>setFormat(e.target.value)}>{['','apache','nginx','json','jsonl','csv'].map(v=><option key={v} value={v}>{v||'Auto-detect'}</option>)}</select></label></div>
 <label>Small telemetry sample (do not paste credentials)<textarea aria-label="Telemetry sample" rows={4} maxLength={500000} value={text} onChange={e=>setText(e.target.value)}/></label>
 <details><summary>Optional declarative field mapping</summary><textarea aria-label="Field mapping JSON" rows={3} maxLength={10000} value={mapping} onChange={e=>setMapping(e.target.value)}/></details>
 <button className="button" disabled={readOnly||busy||!text.trim()} onClick={inspect}>{busy?'Inspecting…':'Inspect telemetry'}</button>
 <button className="text-button" onClick={async()=>{try{const v=await api('research/normalization-example');setValue(v.value);setExample(true);setError('')}catch(e){setError(e.message)}}}>Inspect accepted generic example</button>{readOnly&&<p className="muted">READ-ONLY PREVIEW · new sample inspection is disabled; accepted fixture remains available.</p>}
 {error&&<p className="alert" role="alert">{error}</p>}<>{example&&<Badge>ACCEPTED GENERIC FIXTURE · not newly supplied telemetry</Badge>}<IngestionResult value={value}/></><details><summary>Full canonical schema and feature dependencies</summary><button className="text-button" onClick={async()=>{try{setDependencies(await api('ingestion/schema'))}catch(e){setError(e.message)}}}>Load dependency specification</button>{dependencies&&<pre>{JSON.stringify(dependencies,null,2)}</pre>}</details></Card>;
}
