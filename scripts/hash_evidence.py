#!/usr/bin/env python3
"""
hash_evidence.py — GhostTrace Digital Forensics Investigation
=============================================================
Generates SHA-256 hashes for evidence files to verify integrity.

Usage:
    python hash_evidence.py --path <directory_or_file> --output <hash_manifest.txt>

Example:
    python hash_evidence.py --path evidence/ --output evidence/hash_manifest.txt
    python hash_evidence.py --path evidence/disk_image.dd --output evidence/hash_manifest.txt

This script is READ-ONLY; it never modifies the evidence files.
"""

import argparse
import hashlib
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path


# ──────────────────────────────────────────────────────────────────────────────
# Constants
# ──────────────────────────────────────────────────────────────────────────────
ALGORITHM = "sha256"
BUFFER_SIZE = 65_536          # 64 KiB read buffer for large files
SEPARATOR = "=" * 72


# ──────────────────────────────────────────────────────────────────────────────
# Core hashing function
# ──────────────────────────────────────────────────────────────────────────────
def compute_sha256(file_path: Path) -> str:
    """Compute the SHA-256 digest of a file without loading it fully into RAM."""
    if not file_path.is_file():
        raise FileNotFoundError(f"Not a file: {file_path}")

    hasher = hashlib.sha256()
    with open(file_path, "rb") as fh:
        while chunk := fh.read(BUFFER_SIZE):
            hasher.update(chunk)
    return hasher.hexdigest()


def collect_targets(path: Path) -> list[Path]:
    """Return a sorted list of files to hash (single file or directory tree)."""
    if path.is_file():
        return [path]
    elif path.is_dir():
        return sorted(p for p in path.rglob("*") if p.is_file())
    else:
        raise ValueError(f"Path does not exist or is not accessible: {path}")


# ──────────────────────────────────────────────────────────────────────────────
# Output writer
# ──────────────────────────────────────────────────────────────────────────────
def write_manifest(results: list[dict], output_path: Path) -> None:
    """Write the hash manifest in both human-readable text and JSON formats."""
    output_path.parent.mkdir(parents=True, exist_ok=True)

    # Plain-text manifest
    txt_path = output_path.with_suffix(".txt")
    with open(txt_path, "w", encoding="utf-8") as fh:
        fh.write("GhostTrace — SHA-256 Evidence Hash Manifest\n")
        fh.write(f"Generated : {datetime.now(timezone.utc).isoformat()}\n")
        fh.write(f"Algorithm : {ALGORITHM.upper()}\n")
        fh.write(SEPARATOR + "\n\n")
        for entry in results:
            fh.write(f"File      : {entry['relative_path']}\n")
            fh.write(f"Size      : {entry['size_bytes']:,} bytes\n")
            fh.write(f"SHA-256   : {entry['sha256']}\n")
            fh.write(f"Modified  : {entry['mtime_utc']}\n")
            fh.write("\n")
        fh.write(SEPARATOR + "\n")
        fh.write(f"Total files hashed: {len(results)}\n")

    # JSON manifest (machine-readable)
    json_path = output_path.with_suffix(".json")
    with open(json_path, "w", encoding="utf-8") as fh:
        json.dump(
            {
                "tool": "GhostTrace hash_evidence.py",
                "generated_utc": datetime.now(timezone.utc).isoformat(),
                "algorithm": ALGORITHM,
                "total_files": len(results),
                "entries": results,
            },
            fh,
            indent=2,
        )

    print(f"[+] Text manifest written  : {txt_path}")
    print(f"[+] JSON manifest written  : {json_path}")


# ──────────────────────────────────────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────────────────────────────────────
def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate SHA-256 hashes for forensic evidence files.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--path",
        required=True,
        type=Path,
        help="Path to a single evidence file or directory to hash recursively.",
    )
    parser.add_argument(
        "--output",
        required=True,
        type=Path,
        help="Base path for the output manifest (extensions .txt and .json added automatically).",
    )
    parser.add_argument(
        "--exclude",
        nargs="*",
        default=[],
        help="Glob patterns to exclude (e.g. '*.log' '*.tmp').",
    )
    args = parser.parse_args()

    evidence_path = args.path.resolve()
    if not evidence_path.exists():
        print(f"[ERROR] Path not found: {evidence_path}", file=sys.stderr)
        return 1

    print(f"\n{SEPARATOR}")
    print("GhostTrace — SHA-256 Evidence Hasher")
    print(SEPARATOR)
    print(f"Source  : {evidence_path}")
    print(f"Output  : {args.output}")
    print()

    try:
        targets = collect_targets(evidence_path)
    except ValueError as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 1

    # Apply exclusion patterns
    if args.exclude:
        import fnmatch
        filtered = []
        for t in targets:
            excluded = any(fnmatch.fnmatch(t.name, pat) for pat in args.exclude)
            if not excluded:
                filtered.append(t)
        targets = filtered

    results = []
    errors = []

    for file_path in targets:
        try:
            digest = compute_sha256(file_path)
            stat = file_path.stat()
            mtime = datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat()
            rel_path = str(file_path.relative_to(evidence_path.parent)
                          if evidence_path.is_dir()
                          else file_path.name)
            entry = {
                "relative_path": rel_path,
                "absolute_path": str(file_path),
                "sha256": digest,
                "size_bytes": stat.st_size,
                "mtime_utc": mtime,
            }
            results.append(entry)
            print(f"  [OK] {rel_path}")
            print(f"       SHA-256: {digest}")
        except (OSError, PermissionError) as exc:
            errors.append({"path": str(file_path), "error": str(exc)})
            print(f"  [WARN] Could not hash {file_path}: {exc}", file=sys.stderr)

    if not results:
        print("[ERROR] No files were hashed successfully.", file=sys.stderr)
        return 1

    write_manifest(results, args.output)

    print(f"\n[SUMMARY]")
    print(f"  Files hashed  : {len(results)}")
    print(f"  Errors        : {len(errors)}")
    if errors:
        print("  Failed files  :")
        for e in errors:
            print(f"    - {e['path']}: {e['error']}")

    return 0 if not errors else 2


if __name__ == "__main__":
    sys.exit(main())
