#!/usr/bin/env python3
"""
generate_inventory.py — GhostTrace Digital Forensics Investigation
===================================================================
Builds a CSV evidence inventory from a directory of evidence files,
recording filename, size, extension, MIME type guess, and timestamps.

Usage:
    python generate_inventory.py --path evidence/ --output evidence/evidence_inventory.csv

This script is READ-ONLY; it never modifies evidence files.
"""

import argparse
import csv
import mimetypes
import os
import sys
from datetime import datetime, timezone
from pathlib import Path


# ──────────────────────────────────────────────────────────────────────────────
# CSV field definitions
# ──────────────────────────────────────────────────────────────────────────────
FIELDNAMES = [
    "evidence_id",
    "filename",
    "relative_path",
    "extension",
    "mime_type_guess",
    "size_bytes",
    "size_human",
    "created_utc",
    "modified_utc",
    "accessed_utc",
    "notes",
]


def human_size(size_bytes: int) -> str:
    """Convert bytes to a human-readable string."""
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size_bytes < 1024:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024
    return f"{size_bytes:.1f} PB"


def stat_to_utc(timestamp: float) -> str:
    return datetime.fromtimestamp(timestamp, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def classify_extension(ext: str) -> str:
    """Return a category label for common forensic artifact types."""
    ext = ext.lower()
    categories = {
        "disk_image": {".dd", ".img", ".e01", ".aff", ".vmdk"},
        "database":   {".db", ".sqlite", ".sqlite3"},
        "log":        {".log", ".evtx", ".evt"},
        "document":   {".pdf", ".docx", ".doc", ".xlsx", ".xls", ".pptx"},
        "archive":    {".zip", ".rar", ".7z", ".tar", ".gz"},
        "executable": {".exe", ".dll", ".bat", ".ps1", ".sh"},
        "browser":    {".ldb", ".sst", ".localstorage"},
        "registry":   {".reg", ".hiv"},
        "memory":     {".dmp", ".mem", ".raw"},
        "csv_data":   {".csv"},
        "config":     {".ini", ".cfg", ".conf", ".xml", ".json", ".yaml", ".yml"},
        "script":     {".py", ".js", ".rb", ".pl"},
        "image":      {".png", ".jpg", ".jpeg", ".bmp", ".gif", ".tiff"},
    }
    for category, exts in categories.items():
        if ext in exts:
            return category
    return "other"


def build_inventory(base_path: Path, exclude_patterns: list[str]) -> list[dict]:
    """Walk the directory tree and collect metadata for each file."""
    import fnmatch

    entries = []
    counter = 1

    for file_path in sorted(base_path.rglob("*")):
        if not file_path.is_file():
            continue

        # Apply exclusions
        rel = str(file_path.relative_to(base_path))
        if any(fnmatch.fnmatch(file_path.name, pat) for pat in exclude_patterns):
            continue

        try:
            stat = file_path.stat()
            ext = file_path.suffix
            mime, _ = mimetypes.guess_type(str(file_path))
            category = classify_extension(ext)

            entries.append({
                "evidence_id":    f"EV-{counter:04d}",
                "filename":       file_path.name,
                "relative_path":  rel,
                "extension":      ext,
                "mime_type_guess": mime or "unknown",
                "size_bytes":     stat.st_size,
                "size_human":     human_size(stat.st_size),
                "created_utc":    stat_to_utc(stat.st_ctime),
                "modified_utc":   stat_to_utc(stat.st_mtime),
                "accessed_utc":   stat_to_utc(stat.st_atime),
                "notes":          category,
            })
            counter += 1
        except (OSError, PermissionError) as exc:
            print(f"[WARN] Skipping {file_path}: {exc}", file=sys.stderr)

    return entries


def write_csv(entries: list[dict], output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=FIELDNAMES)
        writer.writeheader()
        writer.writerows(entries)
    print(f"[+] Evidence inventory written: {output_path}  ({len(entries)} entries)")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate a CSV evidence inventory for forensic analysis.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--path",    required=True, type=Path, help="Evidence directory.")
    parser.add_argument("--output",  required=True, type=Path, help="Output CSV path.")
    parser.add_argument("--exclude", nargs="*", default=["*.pyc", "*.tmp", "*.log"],
                        help="Glob patterns to exclude from the inventory.")
    args = parser.parse_args()

    base = args.path.resolve()
    if not base.is_dir():
        print(f"[ERROR] Not a directory: {base}", file=sys.stderr)
        return 1

    print(f"\nGhostTrace — Evidence Inventory Generator")
    print(f"Source directory : {base}")
    print(f"Output           : {args.output}\n")

    entries = build_inventory(base, args.exclude)
    if not entries:
        print("[WARN] No files found in the specified directory.", file=sys.stderr)
        return 0

    write_csv(entries, args.output)

    # Summary statistics
    total_size = sum(e["size_bytes"] for e in entries)
    print(f"\n[SUMMARY]")
    print(f"  Total files : {len(entries)}")
    print(f"  Total size  : {human_size(total_size)}")

    ext_counts: dict[str, int] = {}
    for e in entries:
        cat = e["notes"]
        ext_counts[cat] = ext_counts.get(cat, 0) + 1
    print("  By category :")
    for cat, count in sorted(ext_counts.items(), key=lambda x: -x[1]):
        print(f"    {cat:<15} : {count}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
