"""M3C synthetic offline acceptance; writes only temporary artifacts."""
import copy
import hashlib
import json
import subprocess
import sys
import tempfile
from datetime import datetime,timedelta,timezone
from pathlib import Path
from unittest import TestCase
from unittest.mock import patch
from html.parser import HTMLParser
from test_fusion import finding,prediction
from src.fusion.schema import dumps
from src.reporting.assessment import assess,verify_inventory,inventory
from src.reporting.acceptance import check_acceptance
from src.reporting.render_html import render_html
from scripts.run_end_to_end import main

BASELINE='2026-01-01T00:03:02+00:00'
SQLI='2026-01-01T00:10:52+00:00'


class EndToEndTests(TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)
        self.protected=self.root/'protected';self.protected.mkdir()
        self.inputs={k:self.protected/name for k,name in [('branch1','posture.json'),('branch2','predictions.jsonl'),('model_manifest','package_manifest.json'),('live_acceptance','acceptance.json')]}
        manifest={'version':'branch2-model-package-1.0','complete_parallel_package':True,
            'files_sha256':{k:'a'*64 for k in ('feature_schema.json','isolation_forest.joblib','xgboost.json','reconciliation.json')}}
        self.inputs['model_manifest'].write_text(dumps(manifest))
        mh=hashlib.sha256(self.inputs['model_manifest'].read_bytes()).hexdigest()
        rows=[];start=datetime(2026,1,1,tzinfo=timezone.utc)
        patterns=[('BENIGN',i*10) for i in range(13)]+[('UNKNOWN_ANOMALY',130),('UNKNOWN_ANOMALY',140),('UNKNOWN_ANOMALY',170)]+[('SQLI_ATTEMPT',600+i*10) for i in range(5)]
        for seq,(decision,offset) in enumerate(patterns,1):
            rows.append(prediction(seq,decision=decision,emitted=(start+timedelta(seconds=offset+12)).isoformat(),
                window_start=(start+timedelta(seconds=offset)).isoformat(),window_end=(start+timedelta(seconds=offset+10)).isoformat(),
                client_id='fixture-client',user_agent_id='fixture-agent',session_id='fixture-session',run_id='fixture-live',
                source_file='/var/log/apache2/access.log',source_path='/var/log/apache2/access.log',source_device=1,source_inode=2,
                source_byte_ranges=[{'start':seq*10,'end':seq*10+10,'sha256':'d'*64}],source_sha256='c'*64,
                model_id=mh,schema_sha256='b'*64,feature_schema_version='dataset-v2-features-1.0'))
        self.inputs['branch2'].write_text('\n'.join(dumps(r) for r in rows)+'\n')
        acceptance={'acceptance':'PASS','training_performed':False,'model_id':mh,'schema_sha256':'b'*64,
            'live_integrity':{'predictions':21,'unique_record_ids':21,'duplicates':0,'sequence_holes':[]}}
        self.inputs['live_acceptance'].write_text(dumps(acceptance))
        posture=[finding('transport'),finding('identity',category='Authentication & Session'),finding('exposure',category='Exposure'),
            finding('ADV-MSA-26-0031',category='Patch & Vulnerability Intelligence',confirmation='VERSION_BASED',finding_type='SQL injection risk'),
            finding('hardening',category='Server-side Configuration')]
        self.inputs['branch1'].write_text(dumps(posture))

    def run_assessment(self,name='out',comparison=True,**kwargs):
        return assess(**self.inputs,out=self.root/name,baseline_as_of=BASELINE if comparison else None,
                      sqli_as_of=SQLI if comparison else None,protected_roots=[self.protected],**kwargs)

    def test_assessment_structure(self):
        a=self.run_assessment()['assessment']
        for key in ('schema_version','platform_metadata','assessment_scope','cqi','dimensions','top_risk_drivers','behavioral_episodes','correlations','coverage','recommendations','limitations','provenance','model_package_identity'):self.assertIn(key,a)
        self.assertEqual(len(a['dimensions']),6)

    def test_semantics(self):
        a=self.run_assessment()['assessment']
        for key in ('cqi_is_probability','weights_are_empirically_calibrated','successful_exploitation_confirmed','training_performed'):self.assertIs(a[key],False)

    def test_top_risk_order(self):
        drivers=self.run_assessment()['assessment']['top_risk_drivers']
        self.assertEqual(drivers,sorted(drivers,key=lambda d:(-d['contribution'],d['cluster_id'])))
        self.assertTrue(all('representative_evidence' in x for x in drivers))

    def test_one_episode_five_source_windows(self):
        es=self.run_assessment()['assessment']['behavioral_episodes']
        self.assertEqual(len(es),1);self.assertEqual(es[0]['member_count'],5)
        self.assertEqual(len(es[0]['member_source_record_ids']),5);self.assertEqual(es[0]['contribution'],.75)
        self.assertEqual(es[0]['semantic_scope'],'ATTEMPT_PATTERN')

    def test_markdown_sections(self):
        self.run_assessment();text=(self.root/'out/report.md').read_text()
        self.assertIn('Cybersecurity Quality Assessment Report',text)
        for title in ('Executive Summary','Dimensions','Top Risk Drivers','Posture Findings','Behavioral Analysis','Cross-Branch Correlation','Explainability','Recommendations','Sensitivity','Baseline vs Controlled','Coverage','Provenance'):self.assertIn(title,text)
        self.assertIn('13 BENIGN windows and 3 UNKNOWN_ANOMALY windows',text)

    def test_html_standalone(self):
        self.run_assessment();html=(self.root/'out/report.html').read_text()
        class Links(HTMLParser):
            def handle_starttag(self,tag,attrs):
                if tag in ('script','link','img','iframe'):raise AssertionError('External dependencies forbidden')
                if any(k in ('src','href') for k,v in attrs):raise AssertionError('No dependency links')
        Links().feed(html)
        self.assertIn('<style>',html);self.assertIn('class="score"',html);self.assertIn('class="fill"',html)
        for dim in ('D1','D2','D3','D4','D5','D6'):self.assertIn(dim,html)

    def test_html_source_content_escaped(self):
        result=self.run_assessment();a=result['assessment'];a['recommendations'][0]['action']='<script>alert(1)</script>'
        html=render_html(a,result['comparison']);self.assertNotIn('<script>',html);self.assertIn('&lt;script&gt;',html)

    def test_correlations_safe(self):
        cs=self.run_assessment()['assessment']['correlations'];self.assertEqual(len(cs),1)
        self.assertEqual(len(cs[0]['behavior_record_ids']),5)
        self.assertTrue(all(c['causal'] is False and c['exploit_confirmed'] is False and c['score_effect']=='NONE' for c in cs))

    def test_recommendations_deduplicated(self):
        rec=self.run_assessment()['assessment']['recommendations']
        self.assertEqual(len(rec),len(set(r['action'] for r in rec)))

    def test_comparison_d6_only(self):
        comp=self.run_assessment()['comparison'];self.assertEqual(comp['changed_dimensions'],['D6']);self.assertTrue(comp['posture_identical'])
        self.assertEqual(comp['sqli_episode_member_counts'],[5]);self.assertEqual(comp['sqli_episode_count'],1)
        self.assertEqual(comp['baseline_behavior_counts']['unknown_anomaly'],3)

    def test_comparison_math(self):
        comp=self.run_assessment()['comparison'];self.assertEqual(comp['delta'],comp['sqli_cqi']-comp['baseline_cqi'])
        self.assertLess(comp['delta'],0)
        for d in comp['dimensions']:self.assertEqual(d['delta'],d['sqli_quality']-d['baseline_quality'])

    def test_acceptance_pass(self):
        acc=self.run_assessment()['acceptance'];self.assertEqual(acc['overall'],'PASS');self.assertEqual(acc['profile'],'M3C_SCENARIO')
        self.assertTrue(all(c['status']=='PASS' for c in acc['checks'].values()))

    def test_acceptance_broken_required_invariant(self):
        result=self.run_assessment();result['comparison']['changed_dimensions']=['D1','D6']
        acc=check_acceptance(result['assessment'],result['comparison'],{'unchanged':True},True)
        self.assertEqual(acc['overall'],'FAIL');self.assertEqual(acc['checks']['only_D6_changed_between_acceptance_states']['status'],'FAIL')

    def test_wrong_member_expectation_persists_failure(self):
        result=self.run_assessment(expected_sqli_members=4);self.assertEqual(result['acceptance']['overall'],'FAIL')
        self.assertEqual(json.loads((self.root/'out/acceptance.json').read_text())['overall'],'FAIL')

    def test_core_without_comparison_truthful(self):
        result=self.run_assessment(comparison=False);acc=result['acceptance'];self.assertEqual(acc['overall'],'PASS')
        self.assertEqual(acc['profile'],'CORE_ASSESSMENT')
        check=acc['checks']['comparison_cqi_decreased'];self.assertFalse(check['required']);self.assertEqual(check['status'],'FAIL')
        self.assertEqual(result['comparison']['status'],'NOT_REQUESTED')

    def test_manifest_sha_correct(self):
        self.run_assessment();root=self.root/'out';manifest=json.loads((root/'artifact_manifest.json').read_text())
        actual={str(p.relative_to(root)) for p in root.rglob('*') if p.is_file()}-{'artifact_manifest.json'}
        self.assertEqual(actual,{x['filename'] for x in manifest['files']})
        for f in manifest['files']:
            content=(root/f['filename']).read_bytes();self.assertEqual(f['bytes'],len(content));self.assertEqual(f['sha256'],hashlib.sha256(content).hexdigest())

    def test_deterministic_entire_output(self):
        self.run_assessment('one');self.run_assessment('two')
        for p in (self.root/'one').rglob('*'):
            if p.is_file():self.assertEqual(p.read_bytes(),(self.root/'two'/p.relative_to(self.root/'one')).read_bytes())

    def test_refuse_overwrite(self):
        self.run_assessment()
        with self.assertRaises(FileExistsError):self.run_assessment()

    def test_invalid_arguments_before_output(self):
        for kwargs in ({'lookback':0},{'expected_sqli_members':0},{'as_of':'bad'}):
            with self.assertRaises(ValueError):self.run_assessment(**kwargs)
        with self.assertRaises(ValueError):assess(**self.inputs,out=self.root/'out',baseline_as_of=BASELINE)
        with self.assertRaises(ValueError):assess(**self.inputs,out=self.root/'out',baseline_as_of=SQLI,sqli_as_of=BASELINE)
        self.assertFalse((self.root/'out').exists())

    def test_cli_missing_arguments(self):
        with self.assertRaises(SystemExit) as error:main(['assess'])
        self.assertEqual(error.exception.code,2)

    def test_cli_fixture_success(self):
        args=['assess']
        for k,v in self.inputs.items():args += ['--'+k.replace('_','-'),str(v)]
        args += ['--out',str(self.root/'cli'),'--baseline-as-of',BASELINE,'--sqli-as-of',SQLI]
        from src.reporting.assessment import assess as real_assess
        def guarded(*a,**kw):return real_assess(*a,**kw,protected_roots=[self.protected])
        with patch('scripts.run_end_to_end.assess',side_effect=guarded):self.assertEqual(main(args),0)

    def test_no_network_or_apache(self):
        original=Path.open
        def guard(path,*a,**kw):
            if '/var/log/' in str(path):raise AssertionError('Host log forbidden')
            return original(path,*a,**kw)
        with patch('socket.socket',side_effect=AssertionError('Network forbidden')),patch.object(Path,'open',autospec=True,side_effect=guard):self.run_assessment()

    def test_no_training_imports(self):
        result=subprocess.run([sys.executable,'-B','-c','import sys; import src.reporting.assessment; assert not any(x.startswith(("src.branch1", "src.branch2", "xgboost", "sklearn")) for x in sys.modules)'],capture_output=True,text=True)
        self.assertEqual(result.returncode,0,result.stderr)

    def test_apache_argument_rejected_before_read(self):
        args=dict(self.inputs);args['branch1']='/var/log/apache2/access.log'
        with patch.object(Path,'read_bytes',side_effect=AssertionError('No reads allowed')):
            with self.assertRaises(ValueError):assess(**args,out=self.root/'out')

    def test_protected_artifacts_preserved(self):
        before=inventory([self.protected]);self.run_assessment();self.assertTrue(verify_inventory(before)['unchanged'])
        p=next(iter(before));Path(p).write_text('deliberate fixture alteration')
        self.assertFalse(verify_inventory(before)['unchanged'])

    def test_output_artifacts(self):
        self.run_assessment();root=self.root/'out'
        names=('assessment.json','cqi.json','dimensions.json','fusion_clusters.json','correlations.json','coverage.json','sensitivity.json','recommendations.json','provenance.json','comparison.json','report.md','report.html','acceptance.json','artifact_manifest.json','summary.json')
        self.assertTrue(all((root/n).exists() for n in names))
