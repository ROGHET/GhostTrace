#!/usr/bin/env python3
"""
parse_browser_history.py — GhostTrace Digital Forensics Investigation
======================================================================
Extracts browsing history from a Chromium-based browser's SQLite History
database and writes the results to a CSV file.

Chromium-based browsers (Chrome, Edge, Brave, etc.) store history in:
    Windows: %LOCALAPPDATA%\Google\Chrome\User Data\Default\History
    Linux:   ~/.config/google-chrome/Default/History

The 'urls' table contains visit URLs and timestamps.
Chromium timestamps are stored as microseconds since 1601-01-01 (WebKit epoch).

Usage:
    python parse_browser_history.py --db path/to/History --output analysis/browser_findings.csv

IMPORTANT: Always work on a COPY of the database; SQLite may lock the file
           while the browser is running.
"""

import argparse
import csv
import sqlite3
import sys
from datetime import datetime, timezone, timedelta
from pathlib import Path


# ──────────────────────────────────────────────────────────────────────────────
# Chromium WebKit epoch conversion
# ──────────────────────────────────────────────────────────────────────────────
WEBKIT_EPOCH_OFFSET = datetime(1601, 1, 1, tzinfo=timezone.utc)


def webkit_ts_to_datetime(webkit_ts: int) -> datetime:
    """Convert WebKit microsecond timestamp to UTC datetime."""
    return WEBKIT_EPOCH_OFFSET + timedelta(microseconds=webkit_ts)


# ──────────────────────────────────────────────────────────────────────────────
# Firefox epoch conversion (Unix milliseconds)
# ──────────────────────────────────────────────────────────────────────────────
def firefox_ts_to_datetime(ff_ts: int) -> datetime:
    """Convert Firefox microsecond-since-Unix-epoch timestamp to UTC datetime."""
    return datetime(1970, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=ff_ts)


# ──────────────────────────────────────────────────────────────────────────────
# Output fields
# ──────────────────────────────────────────────────────────────────────────────
FIELDNAMES = [
    "visit_id",
    "url",
    "title",
    "visit_count",
    "last_visit_utc",
    "typed_count",
    "hidden",
    "source_db",
]


def connect_readonly(db_path: Path) -> sqlite3.Connection:
    """Open a SQLite database in read-only mode using URI connection."""
    uri = f"file:{db_path.as_posix()}?mode=ro"
    return sqlite3.connect(uri, uri=True)


def extract_chromium_history(db_path: Path) -> list[dict]:
    """Extract URLs and visits from a Chromium History database."""
    results = []
    try:
        conn = connect_readonly(db_path)
        cursor = conn.cursor()
        cursor.execute("""
            SELECT
                id,
                url,
                title,
                visit_count,
                last_visit_time,
                typed_count,
                hidden
            FROM urls
            ORDER BY last_visit_time DESC
        """)
        rows = cursor.fetchall()
        conn.close()

        for row in rows:
            vid, url, title, vc, lvt, tc, hidden = row
            try:
                dt = webkit_ts_to_datetime(lvt)
                ts_str = dt.strftime("%Y-%m-%dT%H:%M:%SZ")
            except (ValueError, OverflowError, OSError):
                ts_str = f"raw:{lvt}"

            results.append({
                "visit_id":      vid,
                "url":           url,
                "title":         title or "",
                "visit_count":   vc,
                "last_visit_utc": ts_str,
                "typed_count":   tc,
                "hidden":        hidden,
                "source_db":     db_path.name,
            })
    except sqlite3.OperationalError as exc:
        print(f"[ERROR] Could not read Chromium history DB: {exc}", file=sys.stderr)
    return results


def extract_firefox_history(db_path: Path) -> list[dict]:
    """Extract URLs from a Firefox places.sqlite database."""
    results = []
    try:
        conn = connect_readonly(db_path)
        cursor = conn.cursor()
        cursor.execute("""
            SELECT
                p.id,
                p.url,
                p.title,
                p.visit_count,
                p.last_visit_date,
                p.typed,
                p.hidden
            FROM moz_places p
            WHERE p.last_visit_date IS NOT NULL
            ORDER BY p.last_visit_date DESC
        """)
        rows = cursor.fetchall()
        conn.close()

        for row in rows:
            vid, url, title, vc, lvt, tc, hidden = row
            try:
                dt = firefox_ts_to_datetime(lvt)
                ts_str = dt.strftime("%Y-%m-%dT%H:%M:%SZ")
            except (ValueError, OverflowError, OSError):
                ts_str = f"raw:{lvt}"

            results.append({
                "visit_id":      vid,
                "url":           url,
                "title":         title or "",
                "visit_count":   vc,
                "last_visit_utc": ts_str,
                "typed_count":   tc,
                "hidden":        hidden,
                "source_db":     db_path.name,
            })
    except sqlite3.OperationalError as exc:
        print(f"[ERROR] Could not read Firefox history DB: {exc}", file=sys.stderr)
    return results


def detect_browser_type(db_path: Path) -> str:
    """Attempt to detect whether this is a Chromium or Firefox database."""
    try:
        conn = connect_readonly(db_path)
        cursor = conn.cursor()
        tables = [r[0] for r in cursor.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()]
        conn.close()
        if "urls" in tables and "visits" in tables:
            return "chromium"
        if "moz_places" in tables:
            return "firefox"
        return "unknown"
    except sqlite3.DatabaseError:
        return "unknown"


def write_csv(entries: list[dict], output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=FIELDNAMES)
        writer.writeheader()
        writer.writerows(entries)
    print(f"[+] Browser history written: {output_path}  ({len(entries)} URLs)")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Extract browser history from a Chromium/Firefox SQLite database.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--db",     required=True, type=Path, help="Path to browser history SQLite file.")
    parser.add_argument("--output", required=True, type=Path, help="Output CSV path.")
    parser.add_argument("--browser", choices=["auto", "chromium", "firefox"], default="auto",
                        help="Browser type. Default: auto-detect.")
    args = parser.parse_args()

    db_path = args.db.resolve()
    if not db_path.is_file():
        print(f"[ERROR] Database not found: {db_path}", file=sys.stderr)
        return 1

    print(f"\nGhostTrace — Browser History Parser")
    print(f"Database  : {db_path}")
    print(f"Output    : {args.output}")

    browser = args.browser
    if browser == "auto":
        browser = detect_browser_type(db_path)
        print(f"Detected  : {browser}")

    if browser == "chromium":
        entries = extract_chromium_history(db_path)
    elif browser == "firefox":
        entries = extract_firefox_history(db_path)
    else:
        print(f"[ERROR] Unknown browser type — could not determine schema.", file=sys.stderr)
        return 1

    if not entries:
        print("[WARN] No browser history entries extracted.", file=sys.stderr)
        return 0

    write_csv(entries, args.output)

    # Show most visited domains
    from urllib.parse import urlparse
    domain_counts: dict[str, int] = {}
    for e in entries:
        try:
            domain = urlparse(e["url"]).netloc
            domain_counts[domain] = domain_counts.get(domain, 0) + 1
        except Exception:
            pass

    print(f"\n[TOP 10 DOMAINS]")
    for domain, count in sorted(domain_counts.items(), key=lambda x: -x[1])[:10]:
        print(f"  {count:>4}  {domain}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
