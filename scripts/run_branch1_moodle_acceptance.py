#!/usr/bin/env python3
"""Plan, or bootstrap ephemeral authorized roles and run the existing active engine."""
import argparse
from dataclasses import replace
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
from branch1 import Context
from branch1.active import Registry, SafetyPolicy, run_active
from branch1.active.advanced import AccessControl
from branch1.active.models import RequestSpec
from branch1.active.runtime import RuntimeContext
from branch1.active.safety import Executor
from branch1.adapters.moodle_sessions import verified_sessions
from branch1.reporting import validate_output, write_report
from evidence_contracts import SecurityFinding


def load_parent(path):
    records=json.loads(Path(path).read_text())
    selected=[r for r in records if r['finding_id']=='ROLE-student-security_report']
    if len(selected)!=1 or selected[0]['confirmation_status']=='FALSE_POSITIVE':
        raise ValueError('Exactly one non-dismissed security-report parent required')
    return SecurityFinding.from_dict(selected[0])


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--target',required=True)
    parser.add_argument('--context-env',default='B1_ACTIVE_CONTEXT')
    parser.add_argument('--parent-findings',type=Path,default=ROOT/'outputs/branch1_unified_live_smoke/findings.json')
    parser.add_argument('--out',type=Path,required=True)
    parser.add_argument('--active',action='store_true')
    parser.add_argument('--authorized',action='store_true')
    parser.add_argument('--interactive',action='store_true',help='Hidden credential input instead of literal command arguments')
    parser.add_argument('--budget',type=int,default=20,help='Total bootstrap plus validation request budget')
    parser.add_argument('--response-cap',type=int,default=262144,help='Explicit acceptance cap; standard engine default remains 65536')
    args=parser.parse_args()
    try:
        output=validate_output(ROOT,args.out)
        if output.exists() and any(output.iterdir()): raise ValueError('Use a new empty output directory')
        runtime=RuntimeContext.from_env(args.context_env)
        parent=load_parent(args.parent_findings)
        context=runtime.mappings[parent.finding_id]['access_control']
        policy=SafetyPolicy(args.target,args.active,args.authorized,args.budget,5,0.25,args.response_cap)
        ctx=Context(ROOT,output=output)
        registry=Registry((AccessControl(),))
        if args.active:
            policy.check(RequestSpec(context['url'],'reviewed role acceptance endpoint'))
            with verified_sessions(policy,runtime,context,interactive=args.interactive) as bootstrap:
                remaining=policy.request_budget-bootstrap['requests_used']
                active_policy=replace(policy,request_budget=remaining)
                executor=Executor(active_policy,runtime=runtime)
                executor.last_request=bootstrap['rate_checkpoint']
                summary=run_active(ctx,[parent],active_policy,registry=registry,runtime=runtime,executor=executor)
                ctx.artifacts['moodle_session_bootstrap.json']={k:v for k,v in bootstrap.items() if k!='rate_checkpoint'}
                summary['total_budget']=policy.request_budget
                summary['bootstrap_requests_used']=bootstrap['requests_used']
                summary['total_requests_used']=bootstrap['requests_used']+summary['requests_used']
        else:
            summary=run_active(ctx,[parent],policy,registry=registry,runtime=runtime)
        results=ctx.artifacts['active_validation_results.json']
        expected={'outcome':'ROLE_DENIED','check_result':'PASS','confirmation_status':'NOT_CONFIRMED'}
        evaluated=results[0]['execution_status']=='EXECUTED'
        actual={k:results[0][k] for k in expected}
        ctx.artifacts['moodle_acceptance_comparison.json']={'expected':expected,'actual':actual,'evaluated':evaluated,
            'matched':actual==expected if evaluated else None,
            'scope':'student-denied/admin-allowed report content; not global access-control correctness'}
        write_report(ctx,[parent],{'roles':1},{parent.evidence_id:'roles'},active_summary=summary)
        print(f'Moodle role acceptance: {summary["requests_used"]} validation requests; evidence: {output}')
        return 2 if args.active and (not evaluated or actual!=expected) else 0
    except (ValueError,OSError,KeyError,TypeError):
        # Do not print upstream exception values, server content, credentials or cookie headers.
        print('Moodle acceptance failed: missing/invalid context, bounded bootstrap, identity verification or output prerequisites; no credential retry',file=sys.stderr)
        return 1


if __name__=='__main__': raise SystemExit(main())
