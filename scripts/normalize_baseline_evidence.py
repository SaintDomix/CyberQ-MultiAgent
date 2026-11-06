#!/usr/bin/env python3
"""Normalize saved evidence offline. Never import or run a scanner."""

import argparse
from collections import Counter
import csv
import io
import json
from pathlib import Path
import sys

# Work from any current directory without installation or PYTHONPATH changes.
REPOSITORY = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPOSITORY / "src"))

from evidence_contracts.baseline import BASELINE_SOURCES, normalize_baseline
from evidence_contracts.models import SCHEMA_VERSION


def render_outputs(findings):
    rows = [f.to_dict() for f in findings]
    summary = {
        "schema_version": SCHEMA_VERSION,
        "total_records": len(rows),
        "sources": {},
        "check_result_counts": dict(Counter(r["check_result"] or "UNKNOWN" for r in rows)),
        "confirmation_status_counts": dict(Counter(r["confirmation_status"] or "UNKNOWN" for r in rows)),
        "unavailable_fields": ["confidence", "affected_component", "root_cause", "start_utc", "end_utc"],
        "interpretation": (
            "Normalized historical observations, including passes and dismissed candidates. "
            "Record counts are not vulnerability counts. No live validation, scoring or fusion performed."
        ),
    }
    for source, path in BASELINE_SOURCES.items():
        selected = [r for r in rows if r["evidence_source"] == source]
        summary["sources"][source] = {
            "source_file": path,
            "records": len(selected),
            "source_sha256": selected[0]["provenance"]["source_sha256"] if selected else None,
            "mapping_notes": sorted({note for r in selected for note in r["provenance"]["mapping_notes"]}),
        }
    stream = io.StringIO(newline="")
    # All contracts export the same fields; JSON remains the authoritative format.
    fields = list(rows[0]) if rows else []
    writer = csv.DictWriter(stream, fieldnames=fields, lineterminator="\n")
    writer.writeheader()
    for row in rows:
        writer.writerow({key: json.dumps(value, sort_keys=True, ensure_ascii=False, allow_nan=False)
                         if isinstance(value, (dict, list)) else value
                         for key, value in row.items()})
    return {
        "findings.json": json.dumps(rows, indent=2, ensure_ascii=False, allow_nan=False) + "\n",
        "findings.csv": stream.getvalue(),
        "normalization_summary.json": json.dumps(summary, indent=2, ensure_ascii=False, allow_nan=False) + "\n",
    }


def write_outputs(project: Path, output: Path):
    project, output = project.resolve(), output.resolve()
    # Restrict export to outputs/<new-directory>, protecting all source evidence.
    outputs_root = project / "outputs"
    if output == outputs_root or not output.is_relative_to(outputs_root):
        raise ValueError("Output must be a subdirectory of project/outputs")
    protected = [outputs_root / "security_scan_local", outputs_root / "behavioral_quick",
                 outputs_root / "behavioral_v2", outputs_root / "behavioral_v3",
                 outputs_root / "tables", outputs_root / "figures"]
    if any(output == p or output.is_relative_to(p) for p in protected):
        raise ValueError("Output overlaps a preserved historical output directory")
    findings = normalize_baseline(project)
    payloads = render_outputs(findings)
    # Repeat runs may reuse identical artifacts, but never overwrite different evidence.
    for name, text in payloads.items():
        destination = output / name
        if destination.is_symlink():
            raise ValueError(f"Refusing output symlink: {destination}")
        if destination.exists() and destination.read_bytes() != text.encode("utf-8"):
            raise ValueError(f"Output differs; choose a new --out directory: {destination}")
    output.mkdir(parents=True, exist_ok=True)
    for name, text in payloads.items():
        destination = output / name
        if not destination.exists():
            with destination.open("x", encoding="utf-8", newline="") as handle:
                handle.write(text)
    return findings


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project", type=Path, default=REPOSITORY)
    parser.add_argument("--out", type=Path, help="New directory under project/outputs")
    args = parser.parse_args()
    output = args.out if args.out is not None else args.project / "outputs/normalized_baseline"
    try:
        findings = write_outputs(args.project, output)
    except (OSError, ValueError, TypeError) as exc:
        parser.exit(1, f"Normalization failed: {exc}\n")
    print(f"Normalized {len(findings)} records to {output.resolve()}")
    for source in BASELINE_SOURCES:
        print(f"  {source}: {sum(f.evidence_source == source for f in findings)}")


if __name__ == "__main__":
    main()
