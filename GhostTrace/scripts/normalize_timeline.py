#!/usr/bin/env python3
"""
normalize_timeline.py — GhostTrace Digital Forensics Investigation
===================================================================
Reads a raw timeline CSV (produced by Autopsy or manual artifact collection),
normalizes timestamps to UTC, sorts chronologically, deduplicates, and writes
a clean incident timeline CSV.

Input CSV must contain at minimum the column: timestamp
Additional recognized columns:
    timezone, artifact_source, artifact_path, event_description,
    finding_id, interpretation, confidence

Usage:
    python normalize_timeline.py --input timeline/raw_timeline.csv
                                 --output timeline/incident_timeline.csv
                                 --timezone IST

Timezone shortcuts supported: UTC, IST (UTC+5:30), EST, PST, CET
"""

import argparse
import csv
import sys
from datetime import datetime, timezone, timedelta
from pathlib import Path


# ──────────────────────────────────────────────────────────────────────────────
# Timezone registry
# ──────────────────────────────────────────────────────────────────────────────
TIMEZONE_OFFSETS = {
    "UTC":  timedelta(hours=0),
    "IST":  timedelta(hours=5, minutes=30),   # India Standard Time
    "EST":  timedelta(hours=-5),
    "EDT":  timedelta(hours=-4),
    "PST":  timedelta(hours=-8),
    "PDT":  timedelta(hours=-7),
    "CET":  timedelta(hours=1),
    "CEST": timedelta(hours=2),
    "GMT":  timedelta(hours=0),
}

CANONICAL_FIELDS = [
    "timestamp_utc",
    "timestamp_local",
    "timezone",
    "artifact_source",
    "artifact_path",
    "event_description",
    "finding_id",
    "interpretation",
    "confidence",
    "raw_timestamp",
]

TIMESTAMP_FORMATS = [
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%dT%H:%M:%SZ",
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%d %H:%M",
    "%m/%d/%Y %H:%M:%S",
    "%d/%m/%Y %H:%M:%S",
    "%Y-%m-%dT%H:%M:%S.%f",
    "%Y/%m/%d %H:%M:%S",
]


def parse_timestamp(raw: str, tz_offset: timedelta) -> datetime | None:
    """Try multiple formats to parse a timestamp; attach timezone offset."""
    raw = raw.strip()
    if not raw:
        return None

    # Already has timezone indicator?
    if raw.endswith("Z"):
        try:
            dt = datetime.strptime(raw, "%Y-%m-%dT%H:%M:%SZ")
            return dt.replace(tzinfo=timezone.utc)
        except ValueError:
            pass

    for fmt in TIMESTAMP_FORMATS:
        try:
            dt = datetime.strptime(raw, fmt)
            # Attach supplied timezone offset
            tz = timezone(tz_offset)
            return dt.replace(tzinfo=tz)
        except ValueError:
            continue

    return None


def to_utc(dt: datetime) -> datetime:
    """Convert an aware datetime to UTC."""
    return dt.astimezone(timezone.utc)


def normalize_row(row: dict, tz_offset: timedelta, default_tz: str) -> dict | None:
    """Normalize a raw CSV row to the canonical format."""
    raw_ts = row.get("timestamp", row.get("Timestamp", row.get("time", "")))
    if not raw_ts:
        return None

    dt = parse_timestamp(raw_ts, tz_offset)
    if dt is None:
        return None

    dt_utc = to_utc(dt)

    return {
        "timestamp_utc":   dt_utc.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "timestamp_local":  dt.strftime("%Y-%m-%dT%H:%M:%S"),
        "timezone":        row.get("timezone", default_tz),
        "artifact_source": row.get("artifact_source", row.get("source", "unknown")),
        "artifact_path":   row.get("artifact_path", row.get("path", "")),
        "event_description": row.get("event_description", row.get("description", row.get("event", ""))),
        "finding_id":      row.get("finding_id", row.get("id", "")),
        "interpretation":  row.get("interpretation", ""),
        "confidence":      row.get("confidence", "medium"),
        "raw_timestamp":   raw_ts,
    }


def read_raw_timeline(input_path: Path) -> list[dict]:
    """Read the raw timeline CSV."""
    if not input_path.is_file():
        raise FileNotFoundError(f"Input file not found: {input_path}")
    with open(input_path, newline="", encoding="utf-8-sig") as fh:
        reader = csv.DictReader(fh)
        return list(reader)


def write_normalized_timeline(rows: list[dict], output_path: Path) -> None:
    """Write the normalized timeline CSV."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=CANONICAL_FIELDS)
        writer.writeheader()
        writer.writerows(rows)
    print(f"[+] Timeline written: {output_path}  ({len(rows)} events)")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Normalize a forensic timeline CSV to UTC and canonical format.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--input",    required=True, type=Path, help="Raw timeline CSV path.")
    parser.add_argument("--output",   required=True, type=Path, help="Output normalized CSV path.")
    parser.add_argument("--timezone", default="UTC",
                        help=f"Source timezone. Known shortcuts: {', '.join(TIMEZONE_OFFSETS)}. Default: UTC")
    args = parser.parse_args()

    tz_key = args.timezone.upper()
    if tz_key not in TIMEZONE_OFFSETS:
        print(f"[ERROR] Unknown timezone '{args.timezone}'. "
              f"Known: {list(TIMEZONE_OFFSETS.keys())}", file=sys.stderr)
        return 1

    tz_offset = TIMEZONE_OFFSETS[tz_key]

    print(f"\nGhostTrace — Timeline Normalizer")
    print(f"Input     : {args.input}")
    print(f"Output    : {args.output}")
    print(f"Timezone  : {tz_key} (UTC{'+' if tz_offset >= timedelta(0) else ''}"
          f"{tz_offset.total_seconds()/3600:.1f}h)")
    print()

    try:
        raw_rows = read_raw_timeline(args.input)
    except FileNotFoundError as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 1

    normalized = []
    skipped = 0

    for i, row in enumerate(raw_rows, start=2):  # row 1 is header
        norm = normalize_row(row, tz_offset, tz_key)
        if norm is None:
            print(f"  [WARN] Row {i}: Could not parse timestamp — skipped", file=sys.stderr)
            skipped += 1
        else:
            normalized.append(norm)

    # Sort chronologically by UTC timestamp
    normalized.sort(key=lambda r: r["timestamp_utc"])

    # Deduplicate (same UTC timestamp + same source + same description)
    seen = set()
    deduped = []
    for row in normalized:
        key = (row["timestamp_utc"], row["artifact_source"], row["event_description"])
        if key not in seen:
            seen.add(key)
            deduped.append(row)
        else:
            print(f"  [INFO] Duplicate removed: {row['timestamp_utc']} — {row['event_description'][:50]}")

    write_normalized_timeline(deduped, args.output)

    print(f"\n[SUMMARY]")
    print(f"  Raw rows processed : {len(raw_rows)}")
    print(f"  Valid events       : {len(deduped)}")
    print(f"  Skipped (no ts)    : {skipped}")
    print(f"  Duplicates removed : {len(normalized) - len(deduped)}")

    if deduped:
        print(f"  Earliest event     : {deduped[0]['timestamp_utc']}")
        print(f"  Latest event       : {deduped[-1]['timestamp_utc']}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
