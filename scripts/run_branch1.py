#!/usr/bin/env python3
"""Unified offline replay or authorized live passive posture assessment."""
import argparse
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from branch1 import Context, run
from branch1.common import Document
from branch1.reporting import validate_output, write_report
from branch1.roles import load_csv


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=["offline", "live-passive"], default="offline")
    parser.add_argument("--project", type=Path, default=ROOT)
    parser.add_argument("--out", type=Path)
    parser.add_argument("--target")
    parser.add_argument("--authorized", action="store_true", help="Assert authorization for supplied target")
    parser.add_argument("--internal-evidence", type=Path)
    parser.add_argument("--role-evidence", type=Path, nargs="+", help="Review JSON or cross-role v3 CSV files")
    parser.add_argument("--advisories", type=Path, default=ROOT / "src/branch1/advisories.json")
    parser.add_argument("--patch-baseline", type=int, help="Explicit branch-compatible build baseline; no current-release claim")
    parser.add_argument("--webserver-uid", type=int, help="Expected collector UID for web-server-account assertions")
    parser.add_argument("--timeout", type=float, default=8)
    parser.add_argument("--plan-active", action="store_true", help="Network-free active planning in offline mode")
    parser.add_argument("--active", action="store_true", help="Execute bounded validators; requires --plan-active --authorized --target")
    parser.add_argument("--active-budget", type=int, default=20)
    parser.add_argument("--active-timeout", type=float, default=5)
    parser.add_argument("--active-rate", type=float, default=0.25, help="Requests per second; maximum 0.5")
    parser.add_argument("--active-context-env", help="Environment variable containing noncredential runtime mappings and session environment references")
    args = parser.parse_args()
    project = args.project.resolve()
    try:
        from branch1.active import SafetyPolicy, run_active
        from branch1.active.runtime import RuntimeContext
        runtime = RuntimeContext.from_env(args.active_context_env) if args.active_context_env else RuntimeContext()
        if args.active_context_env and not args.plan_active:
            raise ValueError("--active-context-env requires --plan-active")
        if args.active and not args.plan_active:
            raise ValueError("--active requires --plan-active --authorized --target")
        if args.plan_active and not args.active and args.mode != "offline":
            raise ValueError("Planning-only mode requires --mode offline to guarantee zero network requests")
        policy = SafetyPolicy(args.target, args.active, args.authorized, args.active_budget,
                              args.active_timeout, args.active_rate) if args.plan_active else None
        output = validate_output(project, args.out or project / ("outputs/branch1_active_plan_m1c" if args.plan_active else "outputs/branch1_unified"))
        if args.active and output.exists() and any(output.iterdir()):
            raise ValueError("Active execution requires a new empty output directory")
        ctx = Context(project, mode=args.mode, output=output, timeout=args.timeout,
                      webserver_uid=args.webserver_uid, patch_baseline=args.patch_baseline)
        if args.mode == "offline":
            if args.internal_evidence or args.role_evidence or ((args.target or args.authorized) and not args.plan_active):
                raise ValueError("Offline replay accepts saved baseline only; live input options are not allowed")
        else:
            if not args.authorized or not args.target or not args.internal_evidence or not args.role_evidence:
                raise ValueError("Live mode requires --authorized --target --internal-evidence --role-evidence")
            if output.exists() and any(output.iterdir()):
                raise ValueError("Live collection requires a new empty output directory")
            from branch1.client import validate_target
            ctx.target = validate_target(args.target)
            if args.timeout <= 0:
                raise ValueError("Timeout must be positive")
            ctx.internal_document = Document.load(args.internal_evidence, project)
            if not isinstance(ctx.internal_document.payload, dict):
                raise ValueError("Internal evidence must be a JSON object")
            for key in ["core", "settings", "filesystem", "runtime"]:
                if not isinstance(ctx.internal_document.payload.get(key, {}), dict):
                    raise ValueError(f"Invalid internal evidence section: {key}")
            ctx.advisory_document = Document.load(args.advisories, project)
            if not isinstance(ctx.advisory_document.payload, list):
                raise ValueError("Advisories must be a JSON list")
            csv_inputs = [p for p in args.role_evidence if p.suffix.lower() == ".csv"]
            if csv_inputs and len(csv_inputs) != len(args.role_evidence):
                raise ValueError("Supply role CSVs or review JSON, not both")
            if csv_inputs:
                ctx.role_inputs = [load_csv(p, project) for p in csv_inputs]
            else:
                ctx.role_documents = [Document.load(p, project) for p in args.role_evidence]
        findings, counts, assignments = run(ctx)
        active_summary = run_active(ctx, findings, policy, runtime=runtime) if policy else None
        summary = write_report(ctx, findings, counts, assignments, active_summary=active_summary)
    except (OSError, ValueError, TypeError, KeyError) as exc:
        parser.exit(1, f"Branch 1 failed: {exc}\n")
    print(f"Branch 1 {args.mode}: {summary['total_records']} records → {output}")
    print(f"Modules: {summary['module_counts']}")


if __name__ == "__main__":
    main()
