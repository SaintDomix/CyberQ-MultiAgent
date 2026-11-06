"""On-demand jobs; immutable completed snapshots, explicit partial coverage."""
from datetime import datetime, timezone
from pathlib import Path
from collections import Counter
from threading import RLock, Thread, Event
import json
import re
import uuid
import time
from fusion.schema import dumps
from .model import not_reevaluated, deduplicate
from .policy import PassivePolicy, TARGET, TARGET_ID, validate_target
from .privacy import sha
from .providers import NativePostureProvider, ZapPassiveProvider, now
from .inventory import controls, annotate, coverage, VERSION as INVENTORY_VERSION

ID = re.compile(r'posture-\d{8}T\d{6}Z-[0-9a-f]{12}\Z')


def write(path, value):
    with path.open('x', encoding='utf-8') as f: f.write(dumps(value) + '\n')


class PostureAssessmentOrchestrator:
    def __init__(self, project, catalog, native=None, zap=None, active_stage=None, zap_active_stage=None, full_provider_factory=None,clock=time.monotonic, state_relative='runtime/posture'):
        self.project = Path(project).resolve()
        self.root = (self.project / state_relative).resolve()
        if not self.root.is_relative_to(self.project / 'runtime'):
            raise ValueError('Posture state must be inside project runtime')
        self.inventory = controls(self.project, catalog)
        self.catalog = [r for r in self.inventory if not r.get('coverage_only')]
        from .native import Branch1CurrentProvider
        self.providers = {'native': native or Branch1CurrentProvider(self.project), 'zap': zap or ZapPassiveProvider()}
        from .active import ActiveValidationStage
        self.active_stage = active_stage or ActiveValidationStage(self.project)
        from .zap_active import ZapActiveStage
        self.zap_active_stage = zap_active_stage or ZapActiveStage(self.providers['zap'])
        from .zap_full import FullZapProvider
        self.full_provider_factory=full_provider_factory or FullZapProvider
        self.jobs = {}; self.lock = RLock();self.cancellations={};self.clock=clock;self.deadlines={}

    def scanners(self):
        return [dict(p.readiness() if hasattr(p, 'readiness') else p.availability(), name=p.provider_name, supported_modes=['STANDARD','FULL_AUTHORIZED','PASSIVE_BASELINE'],
                     target=TARGET, active_scanner='PROFILE_DEPENDENT') for p in self.providers.values()]

    def location(self, assessment_id):
        if not ID.fullmatch(assessment_id): raise ValueError('Invalid assessment identity')
        resolved = (self.root / assessment_id).resolve()
        if not resolved.is_relative_to(self.root) or self.root.is_symlink() or resolved.is_symlink():
            raise ValueError('Operational snapshot path outside runtime boundary')
        return resolved

    def start(self, target_id=TARGET_ID, zap_enabled=True, mode='STANDARD', background=True,
              target_url=None, authorized=False, full_config=None):
        from coursework.isolation import require_live_owner
        lease=require_live_owner()
        if zap_enabled and isinstance(lease,dict) and mode not in lease['profiles']:
            raise ValueError('ZAP profile is outside the explicit coursework authorization')
        if isinstance(lease,dict) and lease.get('expires_at') is not None:
            from .native_plan import NativeAssessmentPolicy
            required=NativeAssessmentPolicy().max_duration_seconds+30
            if zap_enabled and mode=='STANDARD':
                from .zap_standard import ASSESSMENT_SECONDS
                required=ASSESSMENT_SECONDS+30
            elif zap_enabled and mode=='FULL_AUTHORIZED':
                from .zap_full import FullBudget
                required+=FullBudget().overall_seconds
            if lease['expires_at']-time.time()<required:
                raise ValueError('Insufficient authorized lease time for the existing bounded profile and cleanup')
        full=None
        if mode in ('STANDARD','FULL_AUTHORIZED'):
            from .target import AuthorizedTarget
            full=AuthorizedTarget(target_url or TARGET,authorized=authorized,scan_profile=mode,**(full_config or {}))
            if not zap_enabled:raise ValueError('STANDARD/FULL_AUTHORIZED requires ZAP')
        else:
            validate_target(target_id)
            if target_url not in (None,TARGET):raise ValueError('Restricted profile target cannot be changed')
        policy = PassivePolicy(mode='PASSIVE_BASELINE' if full else mode)
        with self.lock:
            if any(j['status'] == 'RUNNING' for j in self.jobs.values()):
                raise ValueError('A posture assessment is already running')
            aid = 'posture-' + datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ') + '-' + uuid.uuid4().hex[:12]
            path = self.location(aid); path.mkdir(parents=True, exist_ok=False, mode=0o700)
            job = {'assessment_id': aid, 'target_id': target_id, 'target': full.target_url if full else TARGET, 'mode': mode,'assessment_profile':mode,
                   'started_at': now(), 'status': 'RUNNING', 'provider_statuses': {'native': 'QUEUED', 'zap': 'QUEUED' if zap_enabled else 'SKIPPED'},
                   'scope': 'CURRENT_OPERATIONAL_POSTURE', 'policy': policy.export()}
            from .native_plan import NativeAssessmentPolicy
            job['provider_budgets']={'native':NativeAssessmentPolicy().export(),'zap':policy.export()}
            job['policy_scope']='policy is the unchanged ZAP passive profile; Native uses provider_budgets.native'
            from .active import HARD_CEILING
            job['active_validation_policy']={'enabled':True,'global_hard_ceiling':HARD_CEILING,
                'planning':'After fresh Native/ZAP canonicalization; complete reviewed protocols only','score_effect':'NONE'}
            from .zap_active import POLICY_ID
            job['zap_active_policy']={'policy_id':POLICY_ID,'enabled_scanner_ids':[],
                'execution':'FAIL_CLOSED_UNTIL_RULE_AND_TRANSPORT_APPROVED','hard_request_ceiling':0}
            if full:
                from .zap_full import FullBudget,VERSION
                from dataclasses import asdict
                job.update(target_profile=full.export(aid),policy={'version':VERSION,'mode':mode},
                    zap_active_policy={'policy_id':VERSION,'execution':'PROTECTED_CONTEXT_DAST','request_ceiling':None},
                    policy_scope='FULL_AUTHORIZED ZAP has independent finite stage/overall bounds; Native remains bounded separately.')
                job['provider_budgets']['zap']=asdict(FullBudget())
                if mode=='STANDARD':
                    from .zap_standard import StandardBudget,POLICY_ID,ASSESSMENT_SECONDS,PUBLICATION_RESERVE,VALIDATION_RESERVE
                    self.deadlines[aid]=self.clock()+ASSESSMENT_SECONDS
                    job.update(policy={'version':POLICY_ID,'mode':mode},
                        zap_active_policy={'policy_id':POLICY_ID,'execution':'SELECTIVE_PROTECTED_CONTEXT_DAST','request_ceiling':None},
                        policy_scope='STANDARD: fresh shared evidence path; explicit selected scanner policy; total deadline includes Native, ZAP, validation and publication.',
                        assessment_budget={'hard_seconds':ASSESSMENT_SECONDS,'preferred_seconds':300,'validation_reserve_seconds':VALIDATION_RESERVE,'publication_reserve_seconds':PUBLICATION_RESERVE})
                    job['provider_budgets']['zap']=asdict(StandardBudget())
            write(path / 'request.json', job)
            self.jobs[aid] = job
            self.cancellations[aid]=Event()
        if background:
            Thread(target=self.execute, args=(aid, policy, zap_enabled,full), daemon=True, name=aid).start()
        else:
            self.execute(aid, policy, zap_enabled,full)
        return self.get(aid)

    def cancel(self,aid):
        with self.lock:
            if aid not in self.jobs or self.jobs[aid]['status']!='RUNNING':raise ValueError('No owned running assessment')
            self.cancellations[aid].set()
            return {'assessment_id':aid,'status':'CANCELLATION_REQUESTED','unrelated_processes_touched':False}

    def execute(self, aid, policy, zap_enabled,full=None):
        results = {};began=self.clock();standard=bool(full and full.scan_profile=='STANDARD')
        try:
            for name, provider in self.providers.items():
                if name == 'zap' and not zap_enabled:
                    results[name] = {'provider_id': name, 'status': 'SKIPPED', 'findings': [], 'provenance': {'reason': 'Operator disabled optional passive provider'}}
                    continue
                with self.lock: self.jobs[aid]['provider_statuses'][name] = 'RUNNING'
                try:
                    if full and name=='native' and full.target_url!=TARGET:
                        from platform_normalization.posture import collect_generic
                        results[name]=collect_generic(self.project,aid,full,
                            absolute_deadline=self.deadlines.get(aid) if standard else None)
                        with self.lock:self.jobs[aid]['provider_statuses'][name]=results[name]['status']
                        continue
                    if full and name=='zap':
                        def progress(stage,value):
                            with self.lock:self.jobs[aid].setdefault('zap_progress',{})[stage]=value
                        options={}
                        if standard:
                            from .zap_standard import PUBLICATION_RESERVE,VALIDATION_RESERVE
                            options['absolute_deadline']=self.deadlines[aid]-PUBLICATION_RESERVE-VALIDATION_RESERVE
                        results[name]=self.full_provider_factory(provider,self.project).run(aid,full,
                            progress=progress,cancel=self.cancellations[aid].is_set,**options)
                        continue
                    ready = provider.readiness() if name == 'zap' and hasattr(provider, 'readiness') else None
                    if ready and ready['runtime_status'] == 'AVAILABLE' and ready['assessment_readiness'] != 'READY':
                        results[name] = {'provider_id': name, 'status': 'SKIPPED', 'findings': [],
                            'reason_code': ready['assessment_readiness'], 'provenance': {'readiness': ready,
                            'reason': 'Owned passive runtime prerequisites unavailable; no old alert is reused.'}}
                    else:
                        options={}
                        if standard and name=='native':
                            from .native import Branch1CurrentProvider
                            from .zap_standard import PUBLICATION_RESERVE
                            if isinstance(provider,Branch1CurrentProvider):options['absolute_deadline']=self.deadlines[aid]-PUBLICATION_RESERVE
                        results[name] = provider.start_assessment(aid, policy,**options)
                except Exception:
                    # Never export arbitrary exception text (could contain URLs/secrets).
                    results[name] = {'provider_id': name, 'status': 'FAILED', 'findings': [],
                                     'provenance': {'error': 'Provider failed closed; details withheld'}}
                with self.lock: self.jobs[aid]['provider_statuses'][name] = results[name]['status']
            at = now()
            rows = [r for p in results.values() for r in p['findings']]
            executed = {r['finding_id'] for r in rows}
            inventory=self.inventory if not full or full.target_url==TARGET else []
            rows += not_reevaluated(self.catalog if inventory else [], executed, aid, at)
            annotate(rows, inventory, results['native'])
            canonical = deduplicate(rows,full.target_url if full else TARGET)
            with self.lock:self.jobs[aid]['active_validation_status']='RUNNING'
            try:
                if full and full.target_url!=TARGET:raise ValueError('No reviewed Native validator context for non-lab target')
                options={}
                if standard:
                    from .zap_standard import PUBLICATION_RESERVE
                    options['absolute_deadline']=self.deadlines[aid]-PUBLICATION_RESERVE
                active = self.active_stage.run(canonical,aid,**options)
            except Exception:
                from .active import fail_closed
                active = fail_closed(canonical,aid)
            with self.lock:self.jobs[aid]['zap_active_status']='RUNNING'
            try:
                if full:
                    z=results['zap'];s=z.get('stages',{}).get('active',{})
                    zap_active={'assessment_id':aid,'provider_id':'zap_active','status':s.get('status','FAILED'),
                        'profile':full.scan_profile,'policy':z.get('policy'),'scan_id':s.get('scan_id'),
                        'enabled_scanner_ids':z.get('policy',{}).get('enabled_ids',[]),'selected_url_count':z.get('unique_endpoints',0),
                        'selected_parameter_count':z.get('parameter_count',0),'alerts_produced':z.get('active_alerts',0),
                        'scan_started':bool(s.get('scan_id')),'request_message_count':s.get('request_message_count'),
                        'duration_seconds':s.get('duration_seconds'),'reason_code':z.get('error_code'),
                        'alerts_mapped':sum(f['evidence_source']=='ZAP_ACTIVE' and f['category']!='UNMAPPED' for f in z['findings']),
                        'alerts_unmapped':sum(f['evidence_source']=='ZAP_ACTIVE' and f['category']=='UNMAPPED' for f in z['findings']),
                        'findings':[]}
                else:zap_active = self.zap_active_stage.run(aid,results['zap'])
                # This policy has no executing scanner adapter. Never admit rows
                # injected by a provider, stale cache, or an accidental flag.
                if not full and (zap_active.get('findings') or zap_active.get('scan_started')):
                    raise ValueError('Active evidence outside approved execution policy')
            except Exception:
                from .zap_active import unavailable
                zap_active = unavailable(aid)
            valid = any(p['status'] == 'COMPLETE' or p.get('findings') for p in results.values())
            not_done = sum(r['operational_status'] == 'NOT_REEVALUATED' for r in canonical)
            partial = (not_done > 0 or any(p['status'] not in ('COMPLETE',) for p in results.values())
                       or active['status']=='FAILED' or zap_active['status']!='COMPLETE')
            job = dict(self.jobs[aid])
            job.update(completed_at=now(), posture_collection_completed_at=at, status='FAILED' if not valid else 'PARTIAL' if partial else 'COMPLETE',
                active_validation_status=active['status'],
                active_validation_summary={k:v for k,v in active.items() if k!='results'},
                zap_active_status=zap_active['status'],
                zap_active_summary={k:v for k,v in zap_active.items() if k not in ('findings','scanner_review')},
                provider_statuses={k: p['status'] for k, p in results.items()},
                provider_reasons={k: p.get('reason_code', p.get('error_code')) for k, p in results.items()},
                coverage={'status': 'PARTIAL' if partial else 'FULL', 'not_reevaluated': not_done,
                          'not_checked_in_run': sum(r['operational_status']=='NOT_REEVALUATED' and r['category']!='UNMAPPED' for r in canonical),
                          'historical_results_recycled': False, 'authenticated_zap_coverage': 'NOT_VALIDATED',
                          'unmapped_zap_rules': sum(r['category'] == 'UNMAPPED' for r in canonical)},
                raw_finding_counts={k: len(p['findings']) for k, p in results.items()},
                fresh_finding_counts={k: sum(r['operational_status']!='NOT_REEVALUATED' or r['evidence_source']=='OWASP_ZAP' for r in p['findings']) for k,p in results.items()},
                canonical_finding_count=len(canonical), multi_source_count=sum(r['multi_source'] for r in canonical),
                deduplicated_count=len(rows)-len(canonical), status_counts=dict(Counter(r['operational_status'] for r in canonical)),
                native_checks_rerun=sorted(r['finding_id'] for r in results['native']['findings'] if r['operational_status'] != 'NOT_REEVALUATED'),
                not_reevaluated_checks=sorted(r['finding_id'] for r in canonical if r['operational_status'] == 'NOT_REEVALUATED'),
                findings=canonical, successful_exploitation_confirmed=False, causal=False,
                check_inventory_version=INVENTORY_VERSION,
                check_coverage=coverage(inventory, canonical, results['native']),
                source_versions={k: p.get('version') for k, p in results.items()},
                cqi_reference={'semantics': 'CURRENT CQI assembled on read with current behavioral generation; research CQI unchanged', 'policy': 'fusion-cqi-1.1'})
            if full:
                job['zap_execution']={k:v for k,v in results['zap'].items() if k!='findings'}
                job['source_canonical_counts']=dict(Counter('+'.join(r['evidence_sources']) for r in canonical))
            job['duration_seconds']=max(0,self.clock()-began)
            if standard:
                job['assessment_budget']['elapsed_before_publication_seconds']=job['duration_seconds']
                job['assessment_budget']['deadline_respected']=self.clock()<=self.deadlines[aid]
                if not job['assessment_budget']['deadline_respected']:job['status']='PARTIAL'
            path = self.location(aid)
            for name, result in results.items(): write(path / (name + '.json'), result)
            write(path / 'active_validation.json',active)
            write(path / 'zap_active.json',zap_active)
            job['evidence_hashes'] = {name + '.json': sha((path / (name + '.json')).read_bytes()) for name in results}
            job['evidence_hashes']['active_validation.json']=sha((path/'active_validation.json').read_bytes())
            job['evidence_hashes']['zap_active.json']=sha((path/'zap_active.json').read_bytes())
            job['native_source_sha256'] = {str(p.relative_to(self.project)): sha(p.read_bytes()) for p in sorted((self.project / 'src/branch1/external_rules').glob('*.py'))}
            write(path / 'snapshot.json', job)
            write(path / 'artifact_manifest.json', {'version': 'operational-posture-1.2', 'assessment_id': aid,
                'files': {p.name: {'sha256': sha(p.read_bytes()), 'bytes': p.stat().st_size} for p in sorted(path.iterdir()) if p.is_file()},
                'self_hash_convention': 'Manifest excludes itself; snapshot files are write-once'})
            with self.lock: self.jobs[aid] = job
        except Exception:
            with self.lock: self.jobs[aid].update(status='FAILED', error='Operational snapshot failed closed; incomplete job retained, no baseline substitution')

    def get(self, aid):
        path = self.location(aid)
        if (path / 'artifact_manifest.json').exists():
            manifest = json.loads((path / 'artifact_manifest.json').read_text())
            expected={'request.json','native.json','zap.json','snapshot.json'}
            if manifest.get('version')=='operational-posture-1.1':expected.add('active_validation.json')
            if manifest.get('version')=='operational-posture-1.2':expected.update({'active_validation.json','zap_active.json'})
            if (manifest.get('assessment_id') != aid or manifest.get('version') not in ('operational-posture-1.0','operational-posture-1.1','operational-posture-1.2')
                    or set(manifest.get('files', {})) != expected
                    or {p.name for p in path.iterdir()} != set(manifest['files']) | {'artifact_manifest.json'}):
                raise ValueError('Operational identity/file membership mismatch')
            for name, value in manifest['files'].items():
                file = path / name
                if Path(name).name != name or file.is_symlink() or sha(file.read_bytes()) != value['sha256'] or file.stat().st_size != value['bytes']:
                    raise ValueError('Operational snapshot integrity failed')
            return json.loads((path / 'snapshot.json').read_text())
        with self.lock:
            if aid in self.jobs: return dict(self.jobs[aid])
        if (path / 'request.json').exists():
            return {**json.loads((path / 'request.json').read_text()), 'status': 'INTERRUPTED',
                    'error': 'No completed immutable snapshot; no current findings substituted'}
        raise ValueError('Unknown assessment identity')

    def history(self):
        if not self.root.exists(): return []
        return sorted([self.get(p.name) for p in self.root.iterdir() if p.is_dir() and ID.fullmatch(p.name)],
                      key=lambda r: (r['started_at'], r['assessment_id']), reverse=True)

    def latest(self, successful=False):
        return next((j for j in self.history() if not successful or j['status'] in ('COMPLETE', 'PARTIAL')), None)

    def current(self):
        """Never silently substitute an older success for the latest failed/running job."""
        latest = self.latest()
        return latest if latest and latest['status'] in ('COMPLETE', 'PARTIAL') else None

    def last_successful_zap(self):
        # get()/history() verify all immutable snapshot hashes before selection.
        return next((j for j in self.history() if j.get('provider_statuses', {}).get('zap') == 'COMPLETE'), None)

    def retained_zap(self):
        job = self.last_successful_zap()
        if not job: return None
        payload = json.loads((self.location(job['assessment_id']) / 'zap.json').read_text())
        findings = payload['findings']
        return {'assessment_id': job['assessment_id'], 'completed_at': payload.get('completed_at', job.get('completed_at')),
                'status': 'COMPLETE', 'alert_count': len(findings), 'integrity_status': 'HASH_VERIFIED',
                'mapped_count': sum(f['category'] != 'UNMAPPED' for f in findings),
                'unmapped_count': sum(f['category'] == 'UNMAPPED' for f in findings),
                'scope': 'RETAINED_ZAP_EVIDENCE', 'counted_as_fresh_in_current_cqi': False,
                'label': 'Retained from last successful ZAP assessment; not counted as fresh evidence in current CQI.'}

    def retained_zap_findings(self):
        job = self.last_successful_zap()
        if not job: return []
        payload = json.loads((self.location(job['assessment_id']) / 'zap.json').read_text())
        return payload['findings']
