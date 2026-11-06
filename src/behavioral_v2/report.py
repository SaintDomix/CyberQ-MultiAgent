"""Render actual M5 artifacts; no metric computation, fitting, or placeholders."""
import json
from pathlib import Path
from .data import sha
from .schema import ADDED,FEATURES


def table(headers,rows):
    return '\n'.join(['| '+' | '.join(headers)+' |','| '+' | '.join('---' for _ in headers)+' |']+
        ['| '+' | '.join(str(v).replace('|','/') for v in r)+' |' for r in rows])+'\n'


def render(root,diagnostic,study,external):
    root=Path(root);diagnostic=Path(diagnostic);study=Path(study);external=Path(external)
    read=lambda p:json.loads(p.read_text())
    d=read(diagnostic/'diagnostic.json');cov=read(diagnostic/'benign_coverage.json')
    tuning=read(study/'validation_selection.json');test=read(study/'test_metrics.json');run=read(study/'run_level_test_metrics.json')
    unsup=read(study/'unsupervised_comparison.json');ab=read(study/'ablation.json');ex=read(external/'comparison.json')
    split=read(study/'split_manifest.json');qa=read(study/'explainability_qa.json');analysis=read(study/'feature_analysis_train_only.json')
    diag='# M5A — Live Generalization Diagnostic\n\n'
    diag+='The automatically discovered session is `runtime/demo/31aff64be5fd482ebfbd2679f157ab73/live_001`. '
    diag+='All 130 source records were recovered by bounded offsets with inode/device and individual byte-hash verification; no full-log scan or network request was made. Raw requests, queries, tokens, cookies, referrers and user agents are not copied into M5 artifacts.\n\n'
    diag+='The operator reports ordinary browsing. HTTP evidence is compatible with Moodle navigation, but does not independently adjudicate user intent or prove authentication success. This session is EXTERNAL DIAGNOSTIC HOLDOUT, not labelled training data.\n\n'
    diag+=table(['Sequence','UTC window start','Requests','v1 decision','IF decision','XGB BENIGN score (uncalibrated)'],[
        [r['sequence'],r['window_start'],r['observation_count'],r['decision']['decision'],f"{r['if_decision_function']:.6f}",f"{r['xgb_uncalibrated_score']:.6f}"] for r in d['records']])
    diag+='\nNegative IF decision means anomalous. The accepted package uses contamination=0.15, selected in M2C, and confidence threshold=0.8. It does not use the recalled fixed 0.1.\n\n'
    diag+='## Feature evidence\n\nAll 65 features for all 11 windows, TRAIN/VALIDATION/TEST benign summary distributions, medians, MAD/IQR, robust deviations and TRAIN empirical midrank percentiles are in `outputs/branch2/m5/diagnostic_02/diagnostic.json`. Robust deviation is descriptive, not an IF causal attribution.\n\n'
    for r in d['records']:
        if r['sequence'] not in (6,7,8,10):continue
        diag+=f"### Sequence {r['sequence']}\n\n"
        diag+=table(['Feature','Observed','TRAIN median','TRAIN max','Absolute robust deviation'],[
            [f['feature'],f"{f['value']:.3f}",f"{f['benign_distributions']['train']['median']:.3f}",f"{f['benign_distributions']['train']['max']:.3f}",f"{f['absolute_robust_deviation']:.3f}"] for f in r['all_features_ranked'][:8]])
        diag+='\nSemantic request counts: '+', '.join(f'{k}={v}' for k,v in sorted(r['semantic_counts'].items()))+'.\n\n'
        diag+=table(['Category','Quotes','Encoded tokens','Max query length','JSON args observations'],[
            [k,v['quote_count'],v['url_encoded_count'],v['query_length_max'],v['JSON_args_observations']] for k,v in r['query_indicators_by_semantic_category'].items()])
        diag+='\n'
    diag+='The 19:47:00 window has only seven requests, yet long/encoded AJAX JSON query arguments. The 19:47:50 window has 74 requests (38 assets/theme, 30 AJAX); the next has 28 (22 assets/theme, four AJAX). All 780 quotes and 1,454 encoding tokens in the 74-request window occur on AJAX requests; 24 AJAX observations contain syntactically valid JSON `args`. Installed Moodle `lib/ajax/service.php` reads `args` and uses `json_decode`; JSON quotes are expected syntax. Theme query strings also trigger six SQL lexical tokens per heavy window; token matching alone is not SQL injection evidence.\n\n'
    diag+='This supports a domain/feature-context mismatch hypothesis: query punctuation, resource fan-out and breadth differ from the benign reference. It does not prove which feature caused the IF decision. The 20:11:30 anomaly includes a logout path, AJAX and login navigation, with quotes/encoding again confined to AJAX. No POST body, session identity or role is inferred.\n\n'
    diag+='## Dataset v2 benign coverage\n\n'
    diag+=table(['Scenario','Status','Windows','Runs','Notes'],[[r['scenario'],r['status'],r['window_count'],', '.join(r['run_ids']),r['note']] for r in cov])
    diag+='\nHistorical browser-like paths exist, so “no AJAX/assets in training” would be false. However rapid-browser fan-out is not represented by the >=2 requests/s proxy. B04 COMPLETE manifests plus the identity-verifying bootstrap support administrator login/navigation, but these synthetic HTTP clients do not load embedded assets like a browser. Incorrect-password-then-success and verified multi-role browser protocols are not established.\n'
    report='# M5 — v1 versus Behavioral v2 Results\n\n'
    report+='**Disposition: B. V2 TRADE-OFF / INCONCLUSIVE. Keep accepted v1; do not promote or replace its package.**\n\n'
    report+='## Provenance and scope\n\nM4B source was preserved in WIP commit `a3f9100` on `m4-demo-ui`; M5 branches from `milestone-3-end-to-end` (`30aa494`). New code is isolated under `src/behavioral_v2/`. No accepted Branch1, Branch2, Fusion, CQI or reporting code changed. No traffic was generated.\n\n'
    report+='Dataset v3 reconstructs exactly the same 82 included runs / 392 windows from authoritative captures, with every original 65-feature vector reproduced exactly. TEST-run01 stays excluded. Source hashes, line provenance, windows, labels and run membership are preserved. Historical + verified session03 composition is intentional; failed/partial captures are not imported.\n\n'
    report+=table(['Partition','Runs','Windows','Class run counts'],[[n,p['run_count'],p['window_count'],', '.join(f'{k}:{v}' for k,v in p['class_counts'].items())] for n,p in split['partitions'].items()])
    report+='\nThe same accepted TRAIN/VALIDATION/TEST runs permit a paired comparison. The reused TEST has previously been examined: this is **paired reanalysis**, not a fresh blind test. The external session did not enter fitting, threshold or persistence selection, but informed feature hypotheses and is not a completely blind external validation. Six fresh replication sessions are proposed for that purpose.\n\n'
    report+='## Features and fitting\n\nSchema `dataset-v3-features-2.0` has 83 ordered features: all 65 original features plus 18 additions: '+', '.join(f'`{k}`' for k in ADDED)+'. `request_count` already means total requests; `ajax_request_count/ratio`, redirect and error ratios already exist and are not duplicated. No identity, role, POST-body or unavailable context is invented.\n\n'
    report+=f"TRAIN-only analysis found {len(analysis['constant_features'])} constant features and {len(analysis['high_correlation_abs_ge_098'])} pairs with |Pearson r| >=0.98. These are documented, not deleted post hoc. Baseline features are retained for comparability; related count/rate/ratio features are transparent redundancy. XGB gain importance is descriptive TRAIN-model importance, not causal evidence.\n\n"
    report+='Novelty models share the same schema, split and RobustScaler fitted only on TRAIN BENIGN. IF uses 200 trees, n_jobs=1, seed42; OCSVM uses RBF, nu=.1, gamma=scale; LOF uses novelty=True and min(20,n-1) neighbors. XGB retains v1 settings: 200 trees, depth3, learning_rate=.05, deterministic full row/column sampling, hist, n_jobs=1, seed42, eight classes. XGB uses original numerical values; robust reference is TRAIN BENIGN only.\n\n'
    report+='## Validation-only selection\n\nLarger raw score_samples is more normal for all novelty models. A score strictly below sorted benign-validation score[floor(target*n)] is anomalous; equality is normal. Candidates are 1%, 2%, 5%, 10%. Selection admits targets <=5% and realized validation benign FPR <=5%, maximizes validation attack recall, then lower FPR/lower target. Model ties prefer IF, then OCSVM, then LOF. TEST/external never selects parameters.\n\n'
    vals=[]
    for name,v in tuning['novelty'].items():
        for c in v['candidates']:
            vals.append([name,c['target_benign_FPR'],f"{c['threshold']:.8f}",c['validation']['FPR'],c['validation']['recall']])
    report+=table(['Model','FPR target','Threshold','Observed VAL benign FPR','VAL attack recall'],vals)
    n=tuning['novelty']['IF']['benign_validation_windows']
    report+=f"\nOnly {n} benign VALIDATION windows exist; empirical resolution is {1/n:.4%}. Thus 1%, 2% and 5% targets can coincide. Zero observed FPR is not a population guarantee. Selected model: **{tuning['selected_model']}**. All candidate metrics, including poor IF sensitivity, remain in `validation_selection.json` and `unsupervised_comparison.json`.\n\n"
    report+='## Frozen paired TEST results\n\n'
    report+=table(['Model','BENIGN FPR (11 windows)','Attack recall (58 windows)','Precision','F1','Serialized bytes','Warm novelty ms/window'],[
        [name,v['test']['novelty']['FPR'],v['test']['novelty']['recall'],v['test']['novelty']['precision'],v['test']['novelty']['f1'],v['model_size_bytes'],f"{v['novelty_only_latency_ms_per_window_median']:.4f}"] for name,v in unsup.items()])
    report+='\nLatency is 20 warm local batches including matrix/scaler/schema validation (and its mapper-source hash read), excluding SHAP/XGB/data-artifact I/O. It is measured runtime evidence, not a deterministic artifact or near-real-time SLA. IF seed42/43/44 results are preserved in `seed_stability.json`; OCSVM/LOF have no stochastic seed component. No model uniformly dominates: LOF has lower observed TEST FPR, while validation-selected OCSVM has higher recall. We do not switch models using that TEST observation.\n\n'
    report+=table(['Classifier','Window macro F1','Window accuracy','Run macro F1','Run accuracy'],[
        ['v1 frozen XGB',ab['V1_FROZEN_PACKAGE']['window']['xgboost']['macro_f1'],ab['V1_FROZEN_PACKAGE']['window']['xgboost']['accuracy'],ab['V1_FROZEN_PACKAGE']['run']['xgboost']['macro_f1'],ab['V1_FROZEN_PACKAGE']['run']['xgboost']['accuracy']],
        ['v2 XGB',test['xgboost']['macro_f1'],test['xgboost']['accuracy'],run['xgboost']['macro_f1'],run['xgboost']['accuracy']]])
    report+='\nAll eight classes are present. Full window/run confusion matrices, per-class support/precision/recall/F1 and reconciliation metrics are in the corresponding machine artifacts. XGB scores remain UNCALIBRATED. Run XGB aggregation uses mean class vectors; ties use saved class order. Novelty run aggregation compares mean raw score to the window-calibrated cutoff; its run FPR is measured, not separately calibrated.\n\n'
    report+='## Episode policy and ablation\n\nRaw model disagreements always remain visible. Contiguous same-class windows with identical run/client/agent form an episode; a temporal gap or changed class breaks it. Known confident pattern classifications produce KNOWN_THREAT_ATTEMPT_EPISODE. Unknown anomalies shorter than selected persistence are NOVEL_OBSERVATION, not hidden; UNCERTAIN is also observation-only. These are research candidate semantics, not changes to frozen Fusion/CQI.\n\n'
    report+=table(['Persistence','VAL benign any-alert run FPR','VAL attack run recall'],[
        [c['persistence'],c['validation']['FPR'],c['validation']['recall']] for c in tuning['episode_policy']['candidates']])
    report+=f"\nValidation selected persistence={tuning['episode_policy']['persistence']}; 1 and 2 tie and shortest delay wins. On TEST, persistence2 would reduce the one benign alert run but miss another attack run; this is reporting only, **not permission to reselect**. True episode-level ground-truth intervals do not exist, so we report independently labelled run any-alert metrics and emitted episode counts, not fabricated episode precision/recall.\n\n"
    report+=table(['Ablation','TEST benign FPR','TEST attack recall'],[
        [k,(v['window'].get('isolation_forest') or v['window'].get('novelty'))['FPR'],(v['window'].get('isolation_forest') or v['window'].get('novelty'))['recall']]
        for k,v in ab.items() if isinstance(v,dict)])
    report+='\nOld-style IF means TRAIN score quantile at accepted contamination=.15, not .10. The paired ablation is descriptive: adding semantic features, scaling, calibration and model selection are not a randomized causal experiment. Calibrated IF alone loses substantial attack sensitivity.\n\n'
    report+='## External diagnostic session\n\n'
    report+=table(['System','BENIGN','UNCERTAIN','UNKNOWN_ANOMALY','Known attempts','Alert episodes','Disagreements'],[
        [k,ex[k]['decisions'].get('BENIGN',0),ex[k]['decisions'].get('UNCERTAIN',0),ex[k]['decisions'].get('UNKNOWN_ANOMALY',0),ex[k]['known_attempt_windows'],ex[k]['alert_episodes'],ex[k]['model_disagreements']] for k in ('v1','v2')])
    report+='\nThe accepted v1 saved package exactly reproduces the original live decisions and IF scores. v2 reduces anomaly windows 4→2 and alert episodes 3→1 in this diagnostic session. The two large browser resource windows remain UNKNOWN_ANOMALY; the low-volume long-AJAX and later logout-associated windows become BENIGN. This is a promising **descriptive nuisance reduction**, not established externally labelled FPR or universal generalization. Alternative-model scores/decisions and external ablations are retained without selection in `external_02`.\n\n'
    report+=f"Native exact TreeSHAP explains {qa['nonempty_SHAP']}/{qa['windows']} TEST windows, with raw-margin additivity checks and causal=false. TRAIN BENIGN robust deviations remain available. Saved-model replay is byte-value identical and makes no fit calls.\n\n"
    report+='## Research limitations and next capture\n\nLocal Moodle testbed, small independent run count (only two BENIGN TEST runs), correlated windows, historical/protocol heterogeneity, coarse capture labels, no confirmed successful exploits, no Apache POST bodies, no calibrated probabilities, reused TEST, and diagnostic-informed feature design limit inference. No independently labelled unseen-attack-class set exists; preservation of arbitrary unknown-threat detection is not established. No confidence interval, population FPR, causal effect, or cross-platform universality is claimed.\n\n'
    report+='A new offline plan proposes 24 genuine browser sessions (six protocols × four independent fresh sessions; 12/6/6 pre-reserved TRAIN/VAL/TEST) and six fresh external replication sessions. This is a coverage quota, not a power calculation. Actual available courses/quizzes/roles must be confirmed; absent actions remain absent. Existing traffic generators cannot substitute for a browser loading embedded assets. No additional traffic was collected. See `M5_BENIGN_CAPTURE_PROTOCOL.md`.\n\n'
    report+='`study_01` is retained as an incomplete output attempt: JSON metadata export rejected XGB’s NaN missing-value sentinel after evaluation. `study_02` fixes only metadata serialization and uses identical selected policy and test predictions; no result-based retuning occurred. `diagnostic_01` and `external_01` remain as earlier descriptive versions.\n\n'
    report+='## Reproduction\n\nSee `M5_RESEARCH_PROTOCOL.md` for commands using fresh output names and versioned paths. Accepted v1, M4 checkpoint and pre-existing research files remain intact. Candidate models are not integrated into live inference, Fusion, CQI or UI.\n'
    summary={'classification':ex['classification'],'promote':False,'split':{k:{a:v[a] for a in ('run_count','window_count','class_counts')} for k,v in split['partitions'].items()},
        'features':len(FEATURES),'selection':tuning,'window_test':test,'run_test':run,'external':ex,
        'SHAP_QA':qa,'source_artifact_sha256':{str(p.relative_to(root)):sha(p) for base in (diagnostic,study,external)
            for p in sorted(base.glob('*.json'))}}
    return diag,report,summary
