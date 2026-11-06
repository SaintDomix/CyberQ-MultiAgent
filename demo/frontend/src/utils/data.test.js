import {test} from 'node:test';import assert from 'node:assert/strict';
import {format,kind,recommendationPriority} from './data.js';
test('missing values stay unavailable',()=>{assert.equal(format(null),'—');assert.equal(format(0),'0.00');});
test('attempts remain patterns',()=>{assert.equal(kind('SQLI_ATTEMPT'),'attempt');assert.equal(kind('UNKNOWN_ANOMALY'),'anomaly');});
test('priority derives from linked evidence',()=>{assert.equal(recommendationPriority({evidence_ids:['x']},[{contribution:.5,representative_evidence:{evidence_id:'x'}}]),.5);});

test('non-representative members retain root contribution',()=>{assert.equal(recommendationPriority({evidence_ids:['member']},[{contribution:.75,member_evidence_ids:['representative','member']}]),.75);});

import {controlState,predictionDelta,currentSelection,recoveredMode} from './live.js';
test('live controls prevent duplicate or overlapping jobs',()=>{const s=controlState({jobs:{live:{status:'RUNNING'}}});assert.equal(s.running,true);assert.equal(s.full,false);assert.equal(s.posture,false);assert.equal(s.live,false)});
test('idle target can run posture or saved-model monitoring',()=>{const s=controlState({state:'IDLE'});assert.equal(s.full,true);assert.equal(s.posture,true);assert.equal(s.live,true)});
test('prediction counts use actual same-session deltas only',()=>{assert.equal(predictionDelta({session_id:'a',prediction_count:4},{session_id:'a',prediction_count:6}),2);assert.equal(predictionDelta({session_id:'a',prediction_count:4},{session_id:'b',prediction_count:6}),0)});
test('selected prediction is preserved and missing selection selects latest',()=>{const rows=[{sequence:1},{sequence:2}];assert.equal(currentSelection(1,rows),1);assert.equal(currentSelection(null,rows),2);assert.equal(currentSelection(4,[]),null)});
test('browser reload reveals existing jobs without starting new ones',()=>{assert.equal(recoveredMode({jobs:{live:{status:'RUNNING'}}}),'LIVE_LAB');assert.equal(recoveredMode({jobs:{live:{status:'STOPPED'}}}),'ACCEPTED_REPLAY');assert.equal(recoveredMode(null),'ACCEPTED_REPLAY')});
