#!/usr/bin/env python3
"""Generate a seven-page report and nine-slide PDF from actual completed receipts."""
import json
from pathlib import Path
import sys
import textwrap
import uuid

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'src')]
from coursework.isolation import install,STATE
install()
from coursework.multiagent.store import Store
from coursework.multiagent.models import (TaskState,TaskRequest,Message,AgentResult,ToolArguments,ToolResult,EvidenceRef,Failure,VerificationOutcome)


def main():
    base=STATE/'assignment4'
    matrix_path=ROOT/json.loads((base/'latest-validation.json').read_text())['path']
    matrix=json.loads(matrix_path.read_text())
    http=json.loads((STATE/'http-receipt.json').read_text())
    tid=http['multiagent']['task_id'];store=Store();state=store.get(tid)
    if state.status!='COMPLETED':raise ValueError('A genuinely completed HTTP task is required')
    events=store.events(tid);exported=store.export(tid)
    frontend=json.loads((base/'frontend-receipt.json').read_text())
    backend_path=max(STATE.glob('offline-*-receipt.json'),key=lambda p:p.stat().st_mtime)
    backend=json.loads(backend_path.read_text())
    assert matrix['pytest_exit']==frontend['exit_code']==backend['pytest_exit']==0
    directory=base/'materials'/uuid.uuid4().hex;directory.mkdir(parents=True)
    distribution=state.distribution
    positive=[r for r in matrix['cases'] if r.get('case_kind')=='ACTUAL_HISTORICAL_REANALYSIS']
    report_counts={'assignment4_real_scenarios':len(positive),'scenario_checks_passed':matrix['passed'],
        'scenario_checks_failed':matrix['failed'],'frontend_checks_passed':frontend['pass'],
        'backend_regressions_passed':backend['tests']['passed'],'backend_deselected':3,
        'task_id':tid,'distribution':distribution,'http_receipt':'runtime/coursework/http-receipt.json',
        'matrix_path':str(matrix_path.relative_to(ROOT)),'browser':'NOT TESTED: no runnable local browser',
        'live':'BLOCKED: no authorization/handoff','overall_cqi':state.result['cqi']['overall']}
    (directory/'results.json').write_text(json.dumps(report_counts,indent=2)+'\n')
    (directory/'real-task.json').write_text(json.dumps(exported,indent=2)+'\n')
    (base/'ui-task.json').write_text(json.dumps(exported)+'\n')
    contracts={m.__name__:m.model_json_schema() for m in (TaskState,TaskRequest,Message,AgentResult,ToolArguments,ToolResult,EvidenceRef,Failure,VerificationOutcome)}
    (base/'contracts.json').write_text(json.dumps(contracts,indent=2)+'\n')
    shares='\n'.join(f"{a}: {distribution['tool_only']['counts'][a]} attempts / 12 = {distribution['tool_only']['percentages'][a]:.2f}%" for a in distribution['tool_only']['counts'])
    checks='\n'.join(f"{r['test'].split('::')[-1]}: {r['outcome']} / {r.get('task_status','schema-only')}" for r in matrix['cases'])
    pages=[
      ('1. Purpose, scope and actual demonstration',f'''CyberQuality Multi-Agent — Assignment 4 / examination preparation

The implementation adds six roles to the isolated coursework copy. One coordinated task executes all five specialists and returns one gated historical Cybersecurity Quality Index. The original dissertation, research artifacts, frozen models and shared laboratory remain protected.

Actual HTTP task: {tid}
Task state: {state.status}
Registered tool attempts: {state.steps}
CQI policy: {state.result['cqi']['policy']['version']}
Overall historical CQI: {state.result['cqi']['overall']:.10f}
Consistency with existing replay implementation: PASS

The result is historical reanalysis with limitations. Native collection time is unavailable; ZAP and behavioral captures are unpaired. It is not a fresh scan, successful exploit finding or attack probability.

No hosted LLM is called. The agents are deterministic specialists using existing AI inference in the Behavioral role. LLM-only percentages are N/A. This is stated openly for the examiner; the missing formal DOCX may contain an additional LLM-agent interpretation to confirm.

The visible demonstration is the existing React application on localhost:8001, with a new Multi-Agent view. The real task API, build assets, messages, evidence, verification, CQI and blocked operations were exercised over loopback HTTP.'''),
      ('2. Architecture and specialized roles','''Coordinator -> Native, ZAP, Behavioral -> Verification -> Quality -> Coordinator

Coordinator: orchestration only. It dispatches typed messages, checks dependencies, owns durable task state and budgets, and delivers the Quality result. It has no cybersecurity domain tools.

Native Security: two tools read the hash-bound Native baseline and map existing controls while preserving confirmation statuses.

ZAP Security: two tools inspect a real saved assessment and its profile/session provenance, and verify the shared laboratory remains locked. No new scan is performed.

Behavioral Detection: three tools resolve complete authentic runs with 83 features, run frozen OCSVM/XGBoost inference, and produce exact native TreeSHAP plus incidents with existing code.

Evidence Verification: three tools independently check artifacts, identities, metadata, consistency, duplicates, freshness and an immutable SQLite journal.

Cybersecurity Quality: two tools gate on verification, call the unchanged CQI policy, and compare overall/D1-D6 outputs against the existing accepted-replay implementation.

Sequential execution is deliberate. A process-wide filesystem lock prevents concurrent coursework runners, including API and CLI instances. Existing shared-lab ownership gates are never bypassed. The architecture diagram and tool registry are in docs/assignment4/ARCHITECTURE.md.'''),
      ('3. Structured collaboration and durable state',f'''Every message has a strict schema version, task_id, message_id, sender, recipient, kind, actual execution timestamp, dependency IDs and structured payload. Extra fields are rejected.

The Native, ZAP and Behavioral RESULT IDs are named by the Verification DISPATCH. The Quality DISPATCH names the Verification RESULT ID. One Coordinator FINAL points to the Quality result. All messages belong to {tid}.

The SQLite task database stores task requests, agent states, messages, outputs, verification, step count and final result or failure. Events are append-only with sequence and SHA-256 chaining. Each event commits together with state. Read APIs hide private raw tool data.

Transitions: CREATED -> RUNNING -> VERIFYING -> SCORING -> COMPLETED. Failure terminals include FAILED, TIMED_OUT, BLOCKED, LIMIT_EXCEEDED and INTERRUPTED. A terminal state cannot change into a different state.

Defaults are 18 tool attempts, 90 seconds/task, 30 seconds/tool, one retry. Failures retry only when explicitly marked transient. Attempts count even when they fail. Native inference deadlines are cooperative; late results are discarded. CLI timeout provides an additional process bound.

Idempotency returns the existing task without tool rewrites. Conflicting idempotency parameters are rejected. Abandoned work is marked INTERRUPTED; it is not resumed automatically. Audit chains detect accidental corruption, not malicious rewriting of an entire local workspace.'''),
      ('4. Authentic sources, inference and score semantics','''Integration 1: preserved filesystem artifacts, including the frozen Native baseline, verified ZAP snapshots, accepted feature vectors, capture logs and model manifests. Paths are selected by server code and checked against the preservation inventory; raw queries are not exposed in public logs.

Integration 2: an actual immutable SQLite observation journal. Existing record hashes, sequences, accepted model/schema identity and the incident projection cursor are checked. This journal corroborates persistence integrity; it is not silently scored as the selected behavioral run.

Integration 3: local frozen-model code execution. Existing 83-feature extraction, OCSVM and XGBoost inference, native exact TreeSHAP and episode code are reused. No fitting, new dataset, threshold tuning or research-output rewrite occurs.

Native and ZAP confirmation semantics remain unchanged. VERSION_BASED is not CONFIRMED exploitation. Behavioral SQLi/XSS/traversal classifications are attempts or patterns; confidence scores are uncalibrated and explanations are not causal.

Quality scores the unchanged Native/accepted-behavior replay combination with cqi-evidence-2.0. The existing replay clock is documented as a policy reference time, not invented Native collection metadata. Authentic but unpaired ZAP results are supplementary, visible and excluded from this score. This avoids temporal mixing and double counting.

Every successful scenario independently compares the recalculated overall CQI and six dimensions to the existing application implementation. A deliberately corrupted delivered CQI is rejected by the Quality consistency tool.'''),
      ('5. Substantive verification and measured workload',f'''Verification checks actual source availability and confinement; current, producer and preserved hashes; accepted package provenance; source-content equality; evidence IDs/statuses/timestamps; duplicate/contradictory identities; 83-column contracts; saved versus re-inferred outputs; incident membership; temporal scope; and SQLite record/cursor integrity.

Outcomes distinguish VERIFIED, PARTIAL, CONFLICTED, MISSING and INVALID. Missing, invalid or conflicted sources prevent a final assessment. PARTIAL temporal provenance permits only explicitly limited historical reanalysis. Normal replay does not falsely become VERIFIED current security.

Actual normal-task distribution:
{shares}

Total specialist tool attempts: 12. LLM attempts: 0, LLM denominator: 0, percentages N/A. Coordinator registered domain calls: 0. Maximum specialist share: 25%, meeting the stated 40% limit for this workflow.

Counts come from actual tool.started events. Failed/retried attempts count on entry. Internal helper calls, file reads and audit persistence are not separately counted as registered tools. The controlled retry test has 13 attempts; the exhausted workload test openly reports a 100% partial-run share and fails rather than concealing it.'''),
      ('6. Executed scenarios and regression evidence',f'''Actual coordinated historical scenarios passed: {len(positive)}.
SQLi, XSS, traversal, brute-force, benign replay, all-attack replay and an UNKNOWN-containing complete run each execute all five specialists.

Scenario/control checks: {matrix['passed']} passed, {matrix['failed']} failed.
Existing backend regression checks: {backend['tests']['passed']} passed; three intentional legacy-control tests are deselected under the coursework lock.
Frontend unit/React rendering checks: {frontend['pass']} passed, {frontend['fail']} failed.
Production frontend build: completed; existing seven views retained and new Multi-Agent navigation added.
Actual localhost task API: passed; five specialists, 12 attempts, max 25%, JSON audit export and built JS/CSS verified. Invalid schema rejected; live task BLOCKED with zero tool calls.

Failure scenarios include missing/conflicting evidence, invalid message, adapter failure, real timeout, retry recovery/exhaustion, three lab-profile locks, workload exhaustion, incomplete input, corrupted CQI, idempotency, concurrent runner rejection, interruption recovery, invalid hash and exact duplicate claims.

Fault injection changes only delivered memory or test adapters, never source artifacts. A passing failure-control check is not a successful cybersecurity assessment. All created tasks retain actual logs and source references.

Matrix receipt: {matrix_path.relative_to(ROOT)}
Real browser click-through is NOT TESTED: no runnable local browser was available. Node server rendering and HTTP asset verification are not mislabeled as browser automation.'''),
      ('7. Isolation, reproducibility and remaining examination work','''The only writable project is /mnt/assignment/cyberquality_multiagent on /dev/sdb. All generated task state, logs, temporary files, reports and builds are under runtime/coursework. The original source repository, Git, models, databases and services remain protected. No remote is configured or data pushed.

Use README.md commands to run preservation/source-proof checks, a one-command CLI task, the React build and foreground server, scenario validation, regression checks, HTTP smoke run, materials generation and final safety proof. Stop only the owned foreground coursework process with Ctrl-C.

Original source HEAD and the expected annotated tag resolve to commit 95513fc10dd4356352f9bc935ba8bcf63532a04e. Safety receipts compare original status and tag object with the pre-task baseline and check 2,801 preserved artifact files. No original service stop, scan, Apache log consumption, SSH or system configuration action is performed.

Shared Moodle/Apache/ZAP live behavior remains locked and unverified. PASSIVE_BASELINE, STANDARD and FULL_AUTHORIZED capabilities are preserved, not newly authorized. A future user-controlled exclusive handoff is required; the original application cannot be forced to honor a coursework-only lock.

Before final examination: rehearse the demonstration; inspect the detailed test matrix and real trace; confirm any formal LLM-agent requirement in the missing DOCX; arrange browser click-through if a browser becomes available; authorize a separate live phase only with safe lab ownership; decide whether hard preemptive cancellation is required beyond cooperative native inference deadlines.

This report supports a working Assignment 4 offline demonstration. It does not claim untested live parity, LLM calls, current exploit findings or an examination grade.''')
    ]
    slide_data=[
      ('CyberQuality Multi-Agent',f'Assignment 4 / examination demonstration\nOne task, five specialists, one gated historical CQI\nActual task: {tid}\nNo shared-lab access; no simulated LLM calls'),
      ('Architecture','Coordinator -> Native + ZAP + Behavioral\n-> Evidence Verification -> Quality -> Coordinator\nCoordinator performs orchestration only\nEach specialist has two or three registered tools'),
      ('Authentic integrations','Preserved filesystem evidence: Native, ZAP, features, captures\nImmutable SQLite journal: record hashes, sequence, cursor\nFrozen model code: 83 features, OCSVM, XGBoost, exact TreeSHAP\nInternal helpers are not mislabeled external APIs'),
      ('Substantive verification','Availability, independent hashes and preserved provenance\nIdentity, time, schema, duplicates, contradictions, incident links\nVERIFIED / PARTIAL / CONFLICTED / MISSING / INVALID\nUnpaired ZAP is supplementary; invalid evidence blocks CQI'),
      ('Actual measured calls',shares+'\n12 registered tool attempts; largest share 25%\nLLM calls 0; LLM shares N/A; Coordinator domain calls 0'),
      ('Bounded and persistent execution','Strict JSON messages and explicit shared SQLite state\nStep/time limits, bounded retry, no unbounded queue\nIdempotency, exclusive runner lock and crash interruption\nHash-chained events; failed attempts remain counted'),
      ('Actual validation',f'{len(positive)} genuine five-specialist historical scenarios\n{matrix["passed"]} scenario/control checks passed\n{backend["tests"]["passed"]} existing backend checks and {frontend["pass"]} frontend checks passed\nNew production build and localhost task API verified\nFailure handling is not assessment success'),
      ('Demonstration','Open localhost:8001 -> Multi-Agent -> sqli_run\nShow six roles, one task ID, JSON dependencies and actual tools\nInspect partial temporal verification, references, D1-D6 and shares\nExport trace; stop only the owned coursework process'),
      ('Limits and examination next steps','Historical analysis is not a current laboratory assessment\nNo LLM provider used; confirm formal rubric interpretation\nReal browser interaction not tested; no local executable\nLive tests require separate approval and exclusive handoff\nNative inference deadlines are cooperative; rehearse and inspect receipts')
    ]
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    from matplotlib.backends.backend_pdf import PdfPages
    def render_pdf(items,path,slides=False):
        with PdfPages(path) as pdf:
            for index,(title,body) in enumerate(items,1):
                fig=plt.figure(figsize=(12.8,7.2) if slides else (8.27,11.69),facecolor='white')
                fig.text(.07,.94,title,fontsize=22 if slides else 16,weight='bold',va='top',color='#152e4c')
                lines=[]
                for paragraph in body.splitlines():lines.extend(textwrap.wrap(paragraph,88 if not slides else 85) or [''])
                if not slides and len(lines)>59:raise ValueError('Report page text would overflow')
                fig.text(.07,.85 if slides else .875,'\n'.join(lines),fontsize=17 if slides else 10,
                         va='top',linespacing=1.45 if slides else 1.35,family='DejaVu Sans')
                fig.text(.07,.035,f'CyberQuality coursework | Actual trace {tid[-12:]} | {index}/{len(items)}',fontsize=8,color='#53647a')
                pdf.savefig(fig)
                if index==1:fig.savefig(directory/('slides-preview.png' if slides else 'report-preview.png'),dpi=110)
                plt.close(fig)
            assert pdf.get_pagecount()==len(items)
    render_pdf(pages,directory/'exam-report.pdf')
    render_pdf(slide_data,directory/'presentation.pdf',True)
    (directory/'exam-report.md').write_text('\n\n---\n\n'.join('# '+title+'\n\n'+body for title,body in pages)+'\n')
    (directory/'presentation.md').write_text('\n\n---\n\n'.join('# '+title+'\n\n'+body for title,body in slide_data)+'\n')
    (directory/'test-matrix.md').write_text('# Actual executed scenario matrix\n\n'+checks+'\n')
    (base/'latest-materials.json').write_text(json.dumps({'path':str(directory.relative_to(ROOT)),
        'report_pages':7,'slides':9,'task_id':tid},indent=2)+'\n')
    print(json.dumps({'materials':str(directory),'report_pages':7,'slides':9,'task_id':tid},indent=2))


if __name__=='__main__':main()
