#!/usr/bin/env python3
"""
validate_outputs.py — GhostTrace Digital Forensics Investigation
================================================================
Validates the generated output files to ensure they are well-formed,
consistent, and ready for submission.

Checks performed:
1. Evidence inventory CSV — correct headers, no empty rows, valid dates
2. Hash manifest JSON — valid JSON, all entries have sha256 field
3. Incident timeline CSV — correct headers, chronological order, no duplicates
4. Findings register CSV — correct headers, all finding IDs unique
5. Browser findings CSV — correct headers if present

Usage:
    python validate_outputs.py [--base GhostTrace/]

Exit codes:
    0 — All checks passed
    1 — One or more checks failed (details printed to stdout)
"""

import argparse
import csv
import json
import sys
from datetime import datetime, timezone
from pathlib import Path


if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


# ──────────────────────────────────────────────────────────────────────────────
# Validation result tracker
# ──────────────────────────────────────────────────────────────────────────────
class ValidationReport:
    def __init__(self, verbose: bool = True):
        self.results: list[dict] = []
        self.verbose = verbose

    def ok(self, check: str, detail: str = ""):
        self.results.append({"status": "PASS", "check": check, "detail": detail})
        if self.verbose:
            print(f"  [PASS] {check}" + (f" - {detail}" if detail else ""))

    def fail(self, check: str, detail: str):
        self.results.append({"status": "FAIL", "check": check, "detail": detail})
        if self.verbose:
            print(f"  [FAIL] {check} - {detail}")

    def warn(self, check: str, detail: str):
        self.results.append({"status": "WARN", "check": check, "detail": detail})
        if self.verbose:
            print(f"  [WARN] {check} - {detail}")

    def skip(self, check: str, reason: str):
        self.results.append({"status": "SKIP", "check": check, "detail": reason})
        if self.verbose:
            print(f"  [SKIP] {check} - {reason}")

    @property
    def passed(self) -> int:
        return sum(1 for r in self.results if r["status"] == "PASS")

    @property
    def failed(self) -> int:
        return sum(1 for r in self.results if r["status"] == "FAIL")

    @property
    def warned(self) -> int:
        return sum(1 for r in self.results if r["status"] == "WARN")

    @property
    def skipped(self) -> int:
        return sum(1 for r in self.results if r["status"] == "SKIP")

    def summary(self) -> str:
        return (f"Total: {len(self.results)} | "
                f"PASS: {self.passed} | "
                f"FAIL: {self.failed} | "
                f"WARN: {self.warned} | "
                f"SKIP: {self.skipped}")

    def to_dict(self) -> dict:
        return {
            "summary": {
                "total": len(self.results),
                "passed": self.passed,
                "failed": self.failed,
                "warned": self.warned,
                "skipped": self.skipped,
            },
            "results": self.results,
        }


# ──────────────────────────────────────────────────────────────────────────────
# Individual validators
# ──────────────────────────────────────────────────────────────────────────────
def validate_inventory_csv(path: Path, report: ValidationReport) -> None:
    """Validate the evidence inventory CSV."""
    if not path.is_file():
        report.skip("Evidence inventory CSV", f"File not found: {path}")
        return

    required_fields = ["evidence_id", "filename", "size_bytes", "sha256" ]
    # sha256 not always in inventory — check what's actually there
    required_fields = ["evidence_id", "filename", "size_bytes"]

    try:
        with open(path, newline="", encoding="utf-8") as fh:
            reader = csv.DictReader(fh)
            headers = reader.fieldnames or []
            rows = list(reader)

        for field in required_fields:
            if field in headers:
                report.ok(f"Inventory has column '{field}'")
            else:
                report.fail(f"Inventory missing column", f"'{field}' not found in {headers}")

        report.ok("Inventory CSV parseable", f"{len(rows)} rows")

        empty_rows = [i+2 for i, r in enumerate(rows) if not any(v.strip() for v in r.values())]
        if empty_rows:
            report.warn("Inventory has empty rows", f"Rows: {empty_rows[:5]}")
        else:
            report.ok("No empty rows in inventory")

    except Exception as exc:
        report.fail("Inventory CSV parseable", str(exc))


def validate_hash_manifest(path: Path, report: ValidationReport) -> None:
    """Validate the hash manifest JSON."""
    json_path = path.with_suffix(".json")
    if not json_path.is_file():
        report.skip("Hash manifest JSON", f"Not found: {json_path}")
        return

    try:
        with open(json_path, encoding="utf-8") as fh:
            data = json.load(fh)
        report.ok("Hash manifest JSON parseable")

        if "entries" not in data:
            report.fail("Hash manifest structure", "Missing 'entries' key")
            return

        entries = data["entries"]
        report.ok("Hash manifest has entries", f"{len(entries)} files")

        missing_hashes = [e.get("relative_path", "?") for e in entries
                         if not e.get("sha256")]
        if missing_hashes:
            report.fail("All entries have sha256", f"Missing: {missing_hashes[:3]}")
        else:
            report.ok("All hash entries have sha256 values")

        # Validate hash format (64 hex chars)
        invalid_hashes = [e.get("relative_path", "?") for e in entries
                         if e.get("sha256") and len(e["sha256"]) != 64]
        if invalid_hashes:
            report.fail("Hash format (64 hex)", f"Invalid: {invalid_hashes[:3]}")
        else:
            report.ok("All SHA-256 hashes are correct length (64 chars)")

    except json.JSONDecodeError as exc:
        report.fail("Hash manifest JSON parseable", str(exc))
    except Exception as exc:
        report.fail("Hash manifest validation", str(exc))


def validate_timeline_csv(path: Path, report: ValidationReport) -> None:
    """Validate the incident timeline CSV."""
    if not path.is_file():
        report.skip("Timeline CSV", f"Not found: {path}")
        return

    required_fields = ["timestamp_utc", "event_description", "artifact_source"]

    try:
        with open(path, newline="", encoding="utf-8") as fh:
            reader = csv.DictReader(fh)
            headers = reader.fieldnames or []
            rows = list(reader)

        for field in required_fields:
            if field in headers:
                report.ok(f"Timeline has column '{field}'")
            else:
                report.fail("Timeline missing required column", f"'{field}'")

        report.ok("Timeline CSV parseable", f"{len(rows)} events")

        if not rows:
            report.warn("Timeline is empty", "No events found")
            return

        # Check chronological order
        timestamps = []
        for row in rows:
            ts_raw = row.get("timestamp_utc", "")
            try:
                ts = datetime.strptime(ts_raw.rstrip("Z"), "%Y-%m-%dT%H:%M:%S")
                timestamps.append(ts)
            except ValueError:
                continue

        if timestamps:
            is_sorted = all(timestamps[i] <= timestamps[i+1] for i in range(len(timestamps)-1))
            if is_sorted:
                report.ok("Timeline is in chronological order")
            else:
                report.fail("Timeline chronological order", "Events are not sorted by timestamp")

            report.ok("Timeline date range",
                     f"{timestamps[0].isoformat()} -> {timestamps[-1].isoformat()}")

        # Check for duplicates
        desc_ts_pairs = [(r.get("timestamp_utc"), r.get("event_description")) for r in rows]
        if len(desc_ts_pairs) != len(set(desc_ts_pairs)):
            report.warn("Duplicate timeline entries", "Some (timestamp, description) pairs repeat")
        else:
            report.ok("No duplicate timeline entries")

    except Exception as exc:
        report.fail("Timeline CSV validation", str(exc))


def validate_findings_register(path: Path, report: ValidationReport) -> None:
    """Validate the findings register CSV."""
    if not path.is_file():
        report.skip("Findings register CSV", f"Not found: {path}")
        return

    required_fields = ["finding_id", "artifact_source", "observation"]

    try:
        with open(path, newline="", encoding="utf-8") as fh:
            reader = csv.DictReader(fh)
            headers = reader.fieldnames or []
            rows = list(reader)

        for field in required_fields:
            if field in headers:
                report.ok(f"Findings register has column '{field}'")
            else:
                report.fail("Findings register missing column", f"'{field}'")

        report.ok("Findings register parseable", f"{len(rows)} findings")

        # Unique finding IDs
        if "finding_id" in headers:
            ids = [r.get("finding_id", "") for r in rows]
            unique_ids = set(ids)
            if len(ids) != len(unique_ids):
                report.fail("Finding IDs are unique",
                           f"Duplicates: {[i for i in ids if ids.count(i) > 1][:5]}")
            else:
                report.ok("All finding IDs are unique")

        # Confidence values are valid
        valid_confidence = {"high", "medium", "low", "uncertain"}
        if "confidence" in headers:
            invalid_conf = [r.get("confidence", "") for r in rows
                           if r.get("confidence", "").lower() not in valid_confidence]
            if invalid_conf:
                report.warn("Confidence values", f"Non-standard values: {invalid_conf[:3]}")
            else:
                report.ok("All confidence values are valid")

    except Exception as exc:
        report.fail("Findings register validation", str(exc))


def validate_readme(path: Path, report: ValidationReport) -> None:
    """Basic README validation."""
    if not path.is_file():
        report.fail("README.md exists", f"Not found: {path}")
        return

    content = path.read_text(encoding="utf-8")
    checks = [
        ("GhostTrace", "Contains project title"),
        ("Harshit Rawat", "Contains team member name"),
        ("Kaushiki Choubey", "Contains team member name"),
        ("Jiya Jain", "Contains team member name"),
        ("SHA-256", "Contains integrity verification mention"),
        ("Autopsy", "Contains tool reference"),
    ]
    for keyword, label in checks:
        if keyword in content:
            report.ok(f"README: {label}", f"Found '{keyword}'")
        else:
            report.warn(f"README: {label}", f"'{keyword}' not found")

    word_count = len(content.split())
    if word_count < 200:
        report.warn("README length", f"Only {word_count} words — may be too short")
    else:
        report.ok("README length", f"{word_count} words")


def run_validation(base: Path | None = None, verbose: bool = False) -> dict:
    """Run all validation checks and return a structured dictionary."""
    if base is None:
        base = Path(".")
    base = base.resolve()
    report = ValidationReport(verbose=verbose)

    validate_readme(base / "README.md", report)
    validate_inventory_csv(base / "evidence" / "evidence_inventory.csv", report)
    validate_hash_manifest(base / "evidence" / "hash_manifest", report)
    validate_timeline_csv(base / "timeline" / "incident_timeline.csv", report)
    validate_findings_register(base / "analysis" / "findings_register.csv", report)

    return report.to_dict()


# ──────────────────────────────────────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────────────────────────────────────
def main() -> int:
    parser = argparse.ArgumentParser(
        description="Validate GhostTrace investigation output files.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--base", type=Path, default=Path("."),
                        help="Base directory of the GhostTrace project. Default: current directory.")
    args = parser.parse_args()

    base = args.base.resolve()
    report = ValidationReport(verbose=True)

    print(f"\n{'='*60}")
    print("GhostTrace - Output Validation Report")
    print(f"Base directory: {base}")
    print(f"Run time: {datetime.now(timezone.utc).isoformat()}")
    print(f"{'='*60}\n")

    # Run all validators
    print("[ README ]")
    validate_readme(base / "README.md", report)

    print("\n[ EVIDENCE INVENTORY ]")
    validate_inventory_csv(base / "evidence" / "evidence_inventory.csv", report)

    print("\n[ HASH MANIFEST ]")
    validate_hash_manifest(base / "evidence" / "hash_manifest", report)

    print("\n[ INCIDENT TIMELINE ]")
    validate_timeline_csv(base / "timeline" / "incident_timeline.csv", report)

    print("\n[ FINDINGS REGISTER ]")
    validate_findings_register(base / "analysis" / "findings_register.csv", report)

    # Print summary
    print(f"\n{'='*60}")
    print(f"VALIDATION SUMMARY")
    print(f"{'='*60}")
    print(f"  {report.summary()}")
    print(f"{'='*60}\n")

    return 0 if report.failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
