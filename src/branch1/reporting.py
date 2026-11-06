"""Deterministic canonical reports with preservation checks."""
from collections import Counter
import csv
import io
import json
from pathlib import Path

from evidence_contracts.models import SCHEMA_VERSION
from .common import json_bytes


def validate_output(project, output):
    project, output = Path(project).resolve(), Path(output).resolve()
    root = project / "outputs"
    if output == root or not output.is_relative_to(root):
        raise ValueError("Output must be a subdirectory of project/outputs")
    for name in ["security_scan_local", "behavioral_quick", "behavioral_v2", "behavioral_v3", "tables", "figures", "normalized_baseline"]:
        protected = root / name
        if output == protected or output.is_relative_to(protected):
            raise ValueError("Output overlaps preserved historical results")
    return output


def write_report(ctx, findings, module_counts, assignments, active_summary=None):
    output = validate_output(ctx.project, ctx.output)
    rows = [f.to_dict() for f in findings]
    artifacts = ctx.artifacts
    if active_summary is not None:
        from .active.redaction import redact
        rows = redact(rows)
        artifacts = redact(artifacts)
        for row in rows:
            row["provenance"]["mapping_notes"].append("Active-stage export redacts secrets; IDs and source hashes identify the unchanged original evidence, not this redacted representation.")
    summary = {"schema_version": SCHEMA_VERSION, "mode": ctx.mode, "total_records": len(rows),
               "module_counts": module_counts,
               "source_counts": dict(Counter(r["evidence_source"] for r in rows)),
               "category_counts": dict(Counter(r["category"] or "UNKNOWN" for r in rows)),
               "check_result_counts": dict(Counter(r["check_result"] or "UNKNOWN" for r in rows)),
               "confirmation_status_counts": dict(Counter(r["confirmation_status"] or "UNKNOWN" for r in rows)),
               "severity_counts": dict(Counter(r["severity"] or "UNKNOWN" for r in rows)),
               "finding_modules": assignments,
               "source_files": sorted({(f.provenance.source_file, f.provenance.source_sha256) for f in findings}),
               "limitations": ["No active exploit validation, root-cause fusion or risk scoring.",
                               "Counts include PASS, unknown and dismissed observations; they are not vulnerability counts.",
                               "Confidence estimates, unsupported collection times and root causes remain unknown."]}
    if active_summary is not None:
        summary["active_validation"] = active_summary
        summary["limitations"][0] = "Bounded validation is separate linked evidence; no root-cause fusion or risk scoring. Negative checks do not establish system safety."
        # Fresh collection artifacts may be redacted on export; retain original hash meaning explicitly.
        import hashlib
        summary["export_artifacts_sha256"] = {name: hashlib.sha256(json_bytes(payload)).hexdigest() for name,payload in artifacts.items()}
    stream = io.StringIO(newline="")
    fields = list(rows[0]) if rows else ["evidence_id", "finding_id", "check_result", "confirmation_status"]
    writer = csv.DictWriter(stream, fields, lineterminator="\n")
    writer.writeheader()
    for row in rows:
        writer.writerow({k: json.dumps(v, ensure_ascii=False, sort_keys=True, allow_nan=False)
                         if isinstance(v, (list, dict)) else v for k,v in row.items()})
    payloads = {"findings.json": json_bytes(rows), "findings.csv": stream.getvalue().encode(),
                "branch1_summary.json": json_bytes(summary),
                **{name: json_bytes(payload) for name,payload in artifacts.items()}}
    for name, data in payloads.items():
        if Path(name).name != name:
            raise ValueError("Artifact names must be simple filenames")
        destination = output / name
        if destination.is_symlink() or (destination.exists() and destination.read_bytes() != data):
            raise ValueError(f"Refusing to overwrite {destination}; use a new output directory")
    output.mkdir(parents=True, exist_ok=True)
    for name, data in payloads.items():
        if not (output / name).exists():
            with (output/name).open("xb") as handle:
                handle.write(data)
    return summary
