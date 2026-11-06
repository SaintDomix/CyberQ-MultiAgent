import {test} from 'node:test';
import assert from 'node:assert/strict';
import {navigation,stateTone,evidenceQuery,currentIncidents,featureBars} from './product.js';
test('seven existing pages plus the coursework Multi-Agent page',()=>{assert.equal(navigation.length,8);assert.equal(new Set(navigation.map(n=>n[0])).size,8);assert.deepEqual(navigation.slice(0,7).map(n=>n[0]),['overview','posture','monitoring','incidents','quality','model','system']);assert.equal(navigation[7][0],'multiagent')});
test('suppressed observation remains visually distinct from known attempt',()=>{assert.equal(stateTone('SUPPRESSED_ISOLATED_ANOMALY'),'uncertain');assert.equal(stateTone('KNOWN_ATTEMPT'),'attempt');assert.equal(stateTone('DISMISSED'),'blue')});
test('mode and run selection are encoded, never shell arguments',()=>{const q=evidenceQuery('LIVE_LAB','ATTACK_HOLDOUT','a&password=x');assert.equal(new URLSearchParams(q).get('run_id'),'a&password=x')});
test('active episodes require actual selected observation membership',()=>{assert.equal(currentIncidents({incidents:[{observation_ids:['a']},{observation_ids:['old']}],cqi:{active_behavioral_impact:{selected_observation_ids:['a']}}}).length,1)});
test('feature bars preserve sign and handle zero contributions',()=>{assert.equal(featureBars([{feature:'f',contribution:0}])[0].width,0);const f=featureBars([{contribution:-2},{contribution:1}]);assert.equal(f[0].contribution,-2);assert.equal(f[1].width,50)});
