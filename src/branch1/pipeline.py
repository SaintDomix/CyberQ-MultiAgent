"""Four simple module callables returning canonical Branch 1 findings."""
from dataclasses import dataclass, field
from pathlib import Path

from evidence_contracts import SecurityFinding
from evidence_contracts.baseline import load_baseline_source
from .common import Document
from . import internal, intelligence, roles


@dataclass
class Context:
    project: Path
    mode: str = "offline"
    target: str | None = None
    output: Path | None = None
    internal_document: Document | None = None
    advisory_document: Document | None = None
    role_documents: list = field(default_factory=list)
    role_inputs: list = field(default_factory=list)
    timeout: float = 8
    webserver_uid: int | None = None
    patch_baseline: int | None = None
    artifacts: dict = field(default_factory=dict)
    baseline_cache: dict = field(default_factory=dict)

    def baseline(self, source):
        if source not in self.baseline_cache:
            self.baseline_cache[source] = load_baseline_source(self.project, source)
        return self.baseline_cache[source]

    def artifact_path(self, name):
        path = self.output / name
        return str(path.relative_to(self.project))


def external_module(ctx):
    if ctx.mode == "offline":
        return ctx.baseline("external_mvp")
    from .external import assess
    findings, artifact = assess(ctx.target, ctx.artifact_path("external_evidence.json"), ctx.timeout)
    ctx.artifacts["external_evidence.json"] = artifact
    return findings


def _is_intelligence(finding):
    return finding.finding_id.startswith(("CORE-", "PATCH-", "ADV-"))


def internal_module(ctx):
    if ctx.mode == "offline":
        return [f for f in ctx.baseline("deep_v2") if not _is_intelligence(f)]
    return internal.assess(ctx.internal_document, ctx.webserver_uid)


def intelligence_module(ctx):
    if ctx.mode == "offline":
        return [f for f in ctx.baseline("deep_v2") if _is_intelligence(f)]
    return intelligence.assess(ctx.internal_document, ctx.advisory_document, ctx.patch_baseline)


def roles_module(ctx):
    if ctx.mode == "offline":
        return ctx.baseline("role_review_v3")
    if ctx.role_inputs:
        findings, artifact = roles.compare(ctx.role_inputs, ctx.artifact_path("role_comparison_evidence.json"))
        ctx.artifacts["role_comparison_evidence.json"] = artifact
        return findings
    return [f for document in ctx.role_documents for f in roles.review_json(document)]


DEFAULT_MODULES = {"external": external_module, "intelligence": intelligence_module,
                   "internal": internal_module, "roles": roles_module}


def run(ctx, modules=None):
    if ctx.mode not in {"offline", "live-passive"}:
        raise ValueError("Unknown assessment mode")
    if ctx.mode == "live-passive" and (not ctx.target or not ctx.internal_document or not ctx.advisory_document or not (ctx.role_documents or ctx.role_inputs)):
        raise ValueError("Live passive assessment requires target, internal evidence, advisories and role evidence")
    findings, module_counts, assignments = [], {}, {}
    for name, module in (DEFAULT_MODULES if modules is None else modules).items():
        records = list(module(ctx))
        if any(not isinstance(f, SecurityFinding) for f in records):
            raise TypeError(f"Module {name} must return canonical SecurityFinding records")
        module_counts[name] = len(records)
        for record in records:
            if record.evidence_id in assignments:
                raise ValueError("Duplicate evidence identities; no silent deduplication")
            assignments[record.evidence_id] = name
        findings.extend(records)
    return findings, module_counts, assignments
