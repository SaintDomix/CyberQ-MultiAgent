import {test,after} from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {createServer} from 'vite';
import React from 'react';
import {renderToStaticMarkup} from 'react-dom/server';
const payload=JSON.parse(await readFile(process.env.PRODUCT_TEST_PAYLOAD||'/tmp/product_api_test_payload.json','utf8'));
const server=await createServer({server:{middlewareMode:true,hmr:false,ws:false,watch:null},appType:'custom'});
const pages=await server.ssrLoadModule('/src/pages/ProductPages.jsx');
const app=await server.ssrLoadModule('/src/App.jsx');
after(async()=>{await server.close()});
const readable=await server.ssrLoadModule('/src/components/BehaviorExplanation.jsx');
test('normal observation receives evidence-based normal heading and uncalibrated score',()=>{
 const o=payload.benign.observations.find(o=>o.reconciled_label==='BENIGN');
 const html=render(readable.BehaviorExplanation,{observation:o});
 for(const text of ['WHY DOES THIS WINDOW APPEAR NORMAL?','BENIGN','UNCALIBRATED','83/83','Observation ≠ incident'])assert.ok(html.includes(text));
 assert.ok(!html.includes('WHY WAS THIS WINDOW FLAGGED?'));
});
test('SQLI and burst classifications have distinct actual explanatory evidence',()=>{
 const examples=['SQLI_ATTEMPT','REQUEST_BURST_DOS_LIKE'].map(label=>payload.attack.observations.find(o=>o.xgb_label===label));
 const html=examples.map(observation=>render(readable.BehaviorExplanation,{observation}));
 assert.notEqual(html[0],html[1]);assert.ok(html[0].includes('SQLI ATTEMPT'));
 assert.ok(html[1].includes('REQUEST BURST DOS LIKE'));
 for(const o of examples)for(const f of o.explanation.classification.factors)assert.ok(render(readable.BehaviorExplanation,{observation:o}).includes(f.human_text.replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('>','&gt;')));
});
test('disagreement and isolated suppression do not imply an incident',()=>{
 const o=payload.benign.observations.find(o=>o.reconciled_label==='UNKNOWN_ANOMALY');
 const html=render(readable.BehaviorExplanation,{observation:o});
 assert.ok(html.includes('MODEL DISAGREEMENT'));assert.ok(html.includes('no known class is asserted'));
 assert.ok(html.includes('Observation ≠ incident'));
});
test('SHAP and raw feature reference remain under technical details',()=>{
 const html=render(pages.Explanation,{observation:payload.attack.observations[0],onClose:()=>{}});
 assert.ok(html.includes('<summary>Technical details</summary>'));assert.ok(html.includes('Raw feature values, benign reference and provenance'));
 assert.ok(html.includes('XGBoost attribution'));assert.ok(html.includes('raw model margin'));
});
test('episode interpretation aggregates linked windows as one existing episode',()=>{
 const incident=payload.attack.incidents.find(e=>e.observation_count>1);
 const html=render(readable.IncidentExplanation,{incident});
 assert.ok(html.includes('one existing episode'));assert.ok(html.includes('UNKNOWN persistence=2'));
 assert.ok(html.includes('Observation ≠ incident'));assert.ok(!html.includes('successful exploitation detected'));
});
test('legacy record without human explanation degrades to technical view',()=>{
 const o=structuredClone(payload.attack.observations[0]);delete o.explanation.anomaly;
 assert.ok(render(readable.BehaviorExplanation,{observation:o}).includes('Technical evidence remains below'));
});
test('uncertain observation is labelled without forcing a known incident',()=>{
 const o=structuredClone(payload.attack.observations.find(o=>o.xgb_label==='SQLI_ATTEMPT'));
 o.reconciled_label='UNCERTAIN';o.explanation.anomaly.verdict='NORMAL';
 o.explanation.summary='Classifier evidence is insufficient for a confident reconciled class.';
 const html=render(readable.BehaviorExplanation,{observation:o});
 assert.ok(html.includes('WHY IS THIS WINDOW UNCERTAIN?'));
 assert.ok(html.includes('SQLI ATTEMPT'));assert.ok(html.includes('insufficient'));
});
const render=(Component,props={})=>renderToStaticMarkup(React.createElement(Component,{data:payload.attack,research:payload.research,onSelect:()=>{},onEvidence:()=>{},onNavigate:()=>{},...props}));
for(const [name,Page] of Object.entries(pages.Pages))test(name+' page renders accepted API evidence',()=>{const html=render(Page);assert.ok(html.length>500);assert.ok(!html.includes('undefined'))});
test('navigation retains existing destinations and adds Multi-Agent',()=>{const html=render(app.Navigation,{page:'incidents',onSelect:()=>{}});assert.equal((html.match(/<button/g)||[]).length,8);assert.ok(html.includes('aria-current="page"'));assert.ok(html.includes('Model &amp; research'));assert.ok(html.includes('Multi-Agent'))});
test('model page displays exact locked research metrics from payload',()=>{const html=render(pages.Model);for(const v of [payload.research.benign.candidate.novelty.window_FPR,payload.research.benign.model_v1.novelty.window_FPR,payload.research.attack.candidate.reconciled.window_recall,payload.research.attack.model_v1.reconciled.window_recall])assert.ok(html.includes((v*100).toFixed(2)+'%'));assert.ok(html.includes(payload.attack.model.package_id));assert.ok(html.includes('limited statistical support'))});
test('isolated anomaly is an observation, not an incident',()=>{const o=payload.benign.observations.find(o=>o.presentation_state==='SUPPRESSED_ISOLATED_ANOMALY');assert.ok(o);const html=render(pages.Monitoring,{data:{...payload.benign,observations:[o]}});assert.ok(html.includes('SUPPRESSED ISOLATED ANOMALY'));assert.ok(html.includes('OBSERVATION ONLY'));assert.ok(!html.includes('INCIDENT MEMBER'))});
test('empty live state does not invent a CQI or an incident',()=>{
 // A workstation may already have a valid current posture snapshot. This is
 // an explicit empty presentation fixture, independent of that retained state.
 const empty={...payload.empty,cqi:null,observations:[],incidents:[]};
 assert.ok(render(pages.Quality,{data:empty}).includes('CQI unavailable'));
 assert.ok(render(pages.Incidents,{data:empty}).includes('No incident episodes'));
});
test('backend failure explicitly marks retained data stale',()=>{const html=render(app.ErrorBanner,{message:'Backend unavailable',stale:true});assert.ok(html.includes('role="alert"'));assert.ok(html.includes('snapshot is stale'))});
test('missing SHAP remains unavailable',()=>{const o=structuredClone(payload.attack.observations[0]);o.explanation.shap={status:'UNAVAILABLE',top_features:[]};const html=render(pages.Explanation,{observation:o,onClose:()=>{}});assert.ok(html.includes('Explainability unavailable for this record'));assert.ok(html.includes('not causal attribution'))});
test('production HTML has no external CDN scripts or styles',async()=>{const html=await readFile('dist/index.html','utf8');assert.ok(!/(?:src|href)=["']https?:/.test(html));assert.ok(html.includes('/assets/'))});
test('demo scenarios explicitly label replay and provide reset',()=>{const html=render(app.DemoScenarios,{items:[{id:'A',title:'A · Normal benign'},{id:'B',title:'B · Known attempt'},{id:'C',title:'C · Suppressed UNKNOWN observation'}],onSelect:()=>{},onReset:()=>{}});assert.ok(html.includes('ACCEPTED EVIDENCE REPLAY'));assert.ok(html.includes('Reset to full accepted replay'));assert.equal((html.match(/<button/g)||[]).length,4)});
test('final v2 report and historical baseline links are distinct',()=>{const html=render(pages.System,{finalReport:{available:true,markdown_url:'/reports/behavioral-v2.md',json_url:'/reports/behavioral-v2.json'}});assert.ok(html.includes('Open final v2 report'));assert.ok(html.includes('/reports/behavioral-v2.md'));assert.ok(html.includes('Historical accepted Model v1'));assert.ok(html.includes('/report.html'))});

const operational=await server.ssrLoadModule('/src/components/OperationalPosture.jsx');
test('STANDARD is the selected recommended default and deep scan remains explicit',()=>{
 const html=render(operational.OperationalPosture,{Research:()=>null});
 assert.ok(html.includes('value="STANDARD" selected=""'));
 for(const v of ['Recommended for normal assessment','Deep comprehensive ZAP assessment','FULL_AUTHORIZED','PASSIVE_BASELINE'])assert.ok(html.includes(v));
 assert.ok(html.includes('STANDARD performs fresh Native, Passive, repository validation and selected ZAP Active'));
});
test('STANDARD identifies intentional browser non-execution without calling it failure',()=>{
 const html=render(operational.FullZapSummary,{current:{mode:'STANDARD',assessment_profile:'STANDARD',zap_execution:{policy:{id:'zap-standard-1.0'},stages:{clientSpider:{status:'NOT_RUN_STANDARD'},ajaxSpider:{status:'NOT_RUN_STANDARD'},active:{status:'COMPLETE',request_message_count:25}},active_alerts:1,passive_alerts:2}}});
 for(const v of ['OWASP ZAP · STANDARD','NOT_RUN_STANDARD','zap-standard-1.0','COMPLETE'])assert.ok(html.includes(v));
});
test('full authorized target input and explicit authorization are primary controls',()=>{
 const html=render(operational.OperationalPosture,{Research:()=>null});
 for(const v of ['Authorized target URL','FULL_AUTHORIZED','I am authorized','Anonymous'])assert.ok(html.includes(v));
 assert.ok(html.includes('disabled=""'));
});
test('ZAP-only vulnerability appears as FAIL in the primary list with unmapped CQI',()=>{
 const html=render(operational.OperationalPosture,{Research:()=>null,initialCurrent:{mode:'FULL_AUTHORIZED',status:'PARTIAL'},initialFindings:[{finding_id:'ZAP-SQLI',title:'SQL Injection',status:'FAIL',severity:'HIGH',category:'UNMAPPED',evidence_sources:['ZAP_ACTIVE'],cqi_mapping:'UNMAPPED',parameter:'id',method:'GET',zap_details:{zap_risk:'HIGH',zap_confidence:'Medium',normalized_path:'/course/view.php'},evidence_summary:{},provenance:{}}]});
 for(const v of ['SQL Injection','ZAP ACTIVE','>FAIL<','HIGH','CQI mapping: UNMAPPED','Medium'])assert.ok(html.includes(v));
});
test('full ZAP summary distinguishes stages, enabled rules and actual messages',()=>{
 const html=render(operational.FullZapSummary,{current:{mode:'FULL_AUTHORIZED',target:'https://school.example/',status:'PARTIAL',assessment_id:'fixture',zap_execution:{zap_mode:'protected',inventory:{active_scanners:[{}]},policy:{enabled_ids:['40018']},stages:{spider:{status:'COMPLETE',url_count:10},active:{status:'PARTIAL',request_message_count:50}},active_alerts:1,passive_alerts:2,unique_endpoints:10,parameter_count:3}}});
 for(const v of ['FULL AUTHORIZED','protected','COMPLETE','PARTIAL','50','Enabled: 1'])assert.ok(html.includes(v));
});
test('rule execution and metadata are explicit and never equated with enabled',()=>{
 const html=render(operational.FullZapSummary,{current:{mode:'FULL_AUTHORIZED',zap_execution:{actual_executed_rule_ids:['40018'],active_rule_execution:[{id:'40018',name:'SQL Injection',execution_state:'EXECUTED',request_count:17,alerts:0,status:'Complete'},{id:'40012',name:'XSS',execution_state:'NOT_OBSERVED',request_count:null,status:null}],stages:{active:{status:'PARTIAL',progress:'19'},metadata:{status:'COMPLETE'}}}}});
 for(const v of ['Rules observed executing: 1','Enabled does not mean executed','Per-rule execution evidence','NOT_OBSERVED','Not exposed','metadata','incomplete scan'])assert.ok(html.includes(v));
});
test('current ascan progress takes precedence over the initial active stage entry',()=>{
 const html=render(operational.FullZapSummary,{current:{mode:'FULL_AUTHORIZED',zap_progress:{active:{status:'RUNNING'},ascan:{status:'RUNNING',progress:'31',request_count:'5249'}}}});
 assert.ok(html.includes('Progress 31%'));assert.ok(html.includes('Active messages: 5249'));
});
test('ZAP Active no-op is visibly unavailable, never a successful empty scan',()=>{
 const html=render(operational.ZapActiveEvidence,{current:{zap_active_status:'NOT_AVAILABLE',zap_active_summary:{reason_code:'NO_REVIEWED_SAFE_SCANNERS',selected_url_count:3,selected_parameter_count:0,enabled_scanner_ids:[],rejected_scanner_count:53,alerts_produced:0,alerts_mapped:0,alerts_unmapped:0}}});
 for(const text of ['ZAP Active','NOT_AVAILABLE','NO REVIEWED SAFE SCANNERS','not a successful active scan','TECHNICAL','ZAP_ACTIVE','Enabled rules: 0'])assert.ok(html.includes(text));
});
test('ZAP Active never fabricates prior active results in an older snapshot',()=>{
 const html=render(operational.ZapActiveEvidence,{current:{}});
 assert.ok(html.includes('NOT_RUN'));assert.ok(html.includes('No current active stage result'));
});
test('active evidence separates finding FAIL from a non-confirming result',()=>{
 const html=render(operational.ActiveEvidence,{finding:{status:'FAIL',active_validation:{status:'NOT_CONFIRMED',assessment_id:'current-fixture',validator_id:'sql_injection',request_count:4,support_level:'LIKELY',reason:'Repeatable differential; exploitability unproven',results:[]}}});
 for(const label of ['ACTIVE NOT CONFIRMED','Finding: FAIL','SUMMARY','TECHNICAL EVIDENCE','does not mean false positive or PASS','Score effect: NONE'])assert.ok(html.includes(label));
});
test('active badge covers direct-control N/A and missing prerequisite states',()=>{
 assert.ok(render(operational.ActiveEvidence,{finding:{status:'FAIL',active_validation:{status:'NOT_APPLICABLE',reason:'Direct header evidence',request_count:0}}}).includes('ACTIVE N/A'));
 assert.ok(render(operational.ActiveEvidence,{finding:{status:'PARTIAL',active_validation:{status:'NOT_AVAILABLE',reason:'Verified role sessions required',request_count:0}}}).includes('ACTIVE UNAVAILABLE'));
});
test('ready owned ZAP explains automatic fresh-session creation without losing history',()=>{
 const html=render(operational.ScannerStatus,{initial:{runtime_status:'AVAILABLE',assessment_readiness:'READY',version:'2.17.0',latest_attempt_status:'COMPLETE',fresh_alerts_in_current_run:1,session_lifecycle:'NEW_UNNAMED_SESSION_ON_START'}});
 for(const text of ['Runtime: AVAILABLE','READY','Each assessment creates and verifies a fresh isolated session','Saved historical snapshots are preserved'])assert.ok(html.includes(text));
});
test('dynamic posture provides a real control and separate baseline tab',()=>{
 const html=render(operational.OperationalPosture,{Research:()=>null});
 for(const label of ['CURRENT POSTURE','RESEARCH BASELINE / HISTORY','RUN POSTURE ASSESSMENT','NOT CHECKED IN THIS RUN','UNMAPPED ZAP RULE','PASSIVE BASELINE ONLY'])assert.ok(html.includes(label));
 assert.ok(!html.includes('All 40'));
});
test('current provider progress renders actual state and missing coverage',()=>{
 const html=render(operational.OperationalPosture,{Research:()=>null,initialCurrent:{assessment_id:'fixture-current',status:'RUNNING',provider_statuses:{native:'RUNNING',zap:'UNAVAILABLE'},coverage:{status:'PARTIAL',not_reevaluated:9}}});
 assert.ok(html.includes('fixture-current'));assert.ok(html.includes('RUNNING'));assert.ok(html.includes('UNAVAILABLE'));assert.ok(html.includes('PARTIAL'));
});
test('current multi-source finding renders member evidence without an exploit claim',()=>{
 const html=render(operational.OperationalPosture,{Research:()=>null,initialFindings:[{finding_id:'HDR-002',assessment_id:'current-fixture',title:'CSP',dimension:'D1',status:'FAIL',evidence_sources:['NATIVE_POSTURE','OWASP_ZAP'],multi_source:true,dedup_rule:'REVIEWED_CONTROL_EQUIVALENCE_MAX',severity:'MEDIUM',confirmation:'NOT_CONFIRMED',source_status_conflict:true,evidence_summary:{members:['native','zap']},provenance:{assessment_id:'current-fixture'}}]});
 assert.ok(html.includes('>NATIVE<'));assert.ok(html.includes('>ZAP PASSIVE<'));assert.ok(html.includes('MULTI-SOURCE'));assert.ok(html.includes('SOURCE DISAGREEMENT'));assert.ok(html.includes('proven exploitability'));
});
test('scanner unavailable state exposes no active-scan button',()=>{
 const html=render(operational.ScannerStatus,{initial:{status:'UNAVAILABLE',version:null,assessment_state:'NOT_RUN',authenticated_coverage:'NOT_VALIDATED',target:'authorized-fixture'}});
 assert.ok(html.includes('UNAVAILABLE'));assert.ok(html.includes('ACTIVE SCANNER: DISABLED'));assert.ok(!html.includes('<button'));
});
test('current CQI is labelled separately from frozen research CQI',()=>{
 const value=structuredClone(payload.attack);value.cqi.policy.assessment_scope='CURRENT_CQI';value.cqi.policy.coverage='PARTIAL';
 const html=render(pages.Quality,{data:value});assert.ok(html.includes('CURRENT_CQI'));assert.ok(html.includes('PARTIAL'));
});
test('reachable used ZAP displays readiness and retains last successful evidence',()=>{
 const html=render(operational.ScannerStatus,{initial:{runtime_status:'AVAILABLE',assessment_readiness:'FRESH_SESSION_REQUIRED',version:'2.17.0',latest_attempt_status:'SKIPPED',latest_attempt_reason:'FRESH_SESSION_REQUIRED',fresh_alerts_in_current_run:0,last_successful_assessment:{assessment_id:'successful-fixture',completed_at:'2026-10-16T03:46:16Z',status:'COMPLETE',alert_count:28,mapped_count:12,unmapped_count:16,integrity_status:'HASH_VERIFIED'}}});
 for(const v of ['Runtime: AVAILABLE','FRESH SESSION REQUIRED','SKIPPED','28 alerts','successful-fixture','HASH_VERIFIED','not counted as fresh evidence in current CQI'])assert.ok(html.includes(v));
 assert.ok(!html.includes('Runtime: UNAVAILABLE'));
});
test('retained ZAP inspection is explicitly history and never labelled current',()=>{
 const html=render(operational.RetainedZap,{initial:{assessment_id:'retained-fixture',items:[{title:'CSP',status:'FAIL',assessment_id:'retained-fixture',evidence_sources:['OWASP_ZAP'],evidence_summary:{structural:true}}]},onClose:()=>{}});
 assert.ok(html.includes('RETAINED ZAP EVIDENCE'));assert.ok(html.includes('retained-fixture'));assert.ok(html.includes('excluded from current canonical findings'));assert.ok(!html.includes('<small>CURRENT'));
});
test('missing native checks and fresh unmapped ZAP rules have distinct explanations',()=>{
 const common={assessment_id:'fixture',title:'Fixture',severity:null,confirmation:'NOT_TESTED',evidence_summary:{},provenance:{},status:'NOT_REEVALUATED'};
 const html=render(operational.OperationalPosture,{Research:()=>null,initialFindings:[{...common,finding_id:'FS-001',category:'Server-side Configuration',evidence_sources:['NATIVE_POSTURE'],prerequisite_reason:'Collector permission required'},{...common,finding_id:'ZAP-9999',category:'UNMAPPED',evidence_sources:['OWASP_ZAP']}]});
 for(const v of ['NOT CHECKED IN THIS RUN','Historical result is intentionally not reused','Collector permission required','UNMAPPED ZAP RULE','Observed by ZAP but not mapped to a CQI control; excluded from scoring'])assert.ok(html.includes(v));
});
