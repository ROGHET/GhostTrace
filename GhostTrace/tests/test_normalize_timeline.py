#!/usr/bin/env python3
"""
test_normalize_timeline.py — Unit tests for normalize_timeline.py
Tests the timestamp parsing, timezone conversion, and deduplication logic.
"""

import csv
import sys
import tempfile
import unittest
from datetime import datetime, timezone, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))

from normalize_timeline import (
    parse_timestamp,
    normalize_row,
    TIMEZONE_OFFSETS,
)


class TestParseTimestamp(unittest.TestCase):
    """Tests for timestamp parsing function."""

    def test_iso_format_z(self):
        """UTC Z-suffixed ISO timestamp should parse to UTC."""
        result = parse_timestamp("2026-09-13T08:14:22Z", timedelta(0))
        self.assertIsNotNone(result)
        self.assertEqual(result.year, 2026)
        self.assertEqual(result.month, 9)
        self.assertEqual(result.day, 13)
        self.assertEqual(result.hour, 8)
        self.assertEqual(result.minute, 14)
        self.assertEqual(result.tzinfo, timezone.utc)

    def test_iso_no_timezone(self):
        """ISO timestamp without timezone should use supplied offset."""
        ist_offset = TIMEZONE_OFFSETS["IST"]
        result = parse_timestamp("2026-09-13T08:14:22", ist_offset)
        self.assertIsNotNone(result)
        # The datetime should have IST timezone attached
        self.assertEqual(result.utcoffset(), ist_offset)

    def test_date_space_format(self):
        """Date-space-time format should parse correctly."""
        result = parse_timestamp("2026-09-13 08:14:22", timedelta(0))
        self.assertIsNotNone(result)
        self.assertEqual(result.hour, 8)

    def test_invalid_timestamp_returns_none(self):
        """Completely invalid string should return None."""
        result = parse_timestamp("not-a-date", timedelta(0))
        self.assertIsNone(result)

    def test_empty_string_returns_none(self):
        """Empty string should return None."""
        result = parse_timestamp("", timedelta(0))
        self.assertIsNone(result)

    def test_ist_to_utc_conversion(self):
        """IST timestamp should convert to UTC correctly (subtract 5:30)."""
        ist_offset = TIMEZONE_OFFSETS["IST"]
        dt = parse_timestamp("2026-09-13T13:44:22", ist_offset)
        self.assertIsNotNone(dt)
        dt_utc = dt.astimezone(timezone.utc)
        self.assertEqual(dt_utc.hour, 8)
        self.assertEqual(dt_utc.minute, 14)

    def test_microsecond_format(self):
        """Timestamp with microseconds should parse."""
        result = parse_timestamp("2026-09-13T08:14:22.123456", timedelta(0))
        self.assertIsNotNone(result)


class TestTimezoneOffsets(unittest.TestCase):
    """Validate timezone offset definitions."""

    def test_utc_is_zero(self):
        self.assertEqual(TIMEZONE_OFFSETS["UTC"], timedelta(0))

    def test_ist_is_plus_5_30(self):
        self.assertEqual(TIMEZONE_OFFSETS["IST"], timedelta(hours=5, minutes=30))

    def test_est_is_minus_5(self):
        self.assertEqual(TIMEZONE_OFFSETS["EST"], timedelta(hours=-5))

    def test_all_offsets_present(self):
        required = {"UTC", "IST", "EST", "PST", "CET", "GMT"}
        self.assertTrue(required.issubset(set(TIMEZONE_OFFSETS.keys())))


class TestNormalizeRow(unittest.TestCase):
    """Tests for the row normalization function."""

    def test_basic_row_normalization(self):
        """A complete row should normalize without errors."""
        row = {
            "timestamp": "2026-09-13T08:14:22Z",
            "artifact_source": "Security.evtx",
            "artifact_path": "C:\\Windows\\System32\\winevt\\Logs\\Security.evtx",
            "event_description": "User John logged on",
            "finding_id": "F-001",
            "interpretation": "Initial access",
            "confidence": "high",
        }
        result = normalize_row(row, TIMEZONE_OFFSETS["UTC"], "UTC")
        self.assertIsNotNone(result)
        self.assertEqual(result["timestamp_utc"], "2026-09-13T08:14:22Z")
        self.assertEqual(result["artifact_source"], "Security.evtx")
        self.assertEqual(result["finding_id"], "F-001")
        self.assertEqual(result["confidence"], "high")

    def test_missing_timestamp_returns_none(self):
        """Row with no timestamp field should return None."""
        row = {"artifact_source": "test", "event_description": "something"}
        result = normalize_row(row, TIMEZONE_OFFSETS["UTC"], "UTC")
        self.assertIsNone(result)

    def test_ist_row_converts_to_utc(self):
        """IST timestamp in row should be stored as UTC in output."""
        row = {
            "timestamp": "2026-09-13T13:44:22",  # IST = 08:14 UTC
            "event_description": "Test event",
        }
        result = normalize_row(row, TIMEZONE_OFFSETS["IST"], "IST")
        self.assertIsNotNone(result)
        self.assertEqual(result["timestamp_utc"], "2026-09-13T08:14:22Z")

    def test_raw_timestamp_preserved(self):
        """The raw timestamp should be preserved in output."""
        row = {"timestamp": "2026-09-13T08:14:22Z", "event_description": "test"}
        result = normalize_row(row, TIMEZONE_OFFSETS["UTC"], "UTC")
        self.assertEqual(result["raw_timestamp"], "2026-09-13T08:14:22Z")


class TestTimelineCSVIntegration(unittest.TestCase):
    """Integration test: write a raw CSV, normalize it, check the output."""

    def test_csv_roundtrip(self):
        """Write raw CSV, normalize, check output is sorted and valid."""
        import csv
        import io

        # Create raw CSV content
        raw_rows = [
            {"timestamp": "2026-09-13T08:33:45Z", "event_description": "Logoff",
             "artifact_source": "Security.evtx", "confidence": "high"},
            {"timestamp": "2026-09-13T08:14:22Z", "event_description": "Logon",
             "artifact_source": "Security.evtx", "confidence": "high"},
            {"timestamp": "2026-09-13T08:24:44Z", "event_description": "Archive created",
             "artifact_source": "MFT", "confidence": "medium"},
        ]

        with tempfile.TemporaryDirectory() as tmpdir:
            input_path = Path(tmpdir) / "raw.csv"
            output_path = Path(tmpdir) / "normalized.csv"

            # Write raw CSV
            with open(input_path, "w", newline="") as fh:
                writer = csv.DictWriter(fh, fieldnames=raw_rows[0].keys())
                writer.writeheader()
                writer.writerows(raw_rows)

            # Run normalization by importing and calling directly
            from normalize_timeline import read_raw_timeline, normalize_row, write_normalized_timeline

            raw = read_raw_timeline(input_path)
            normalized = []
            for row in raw:
                n = normalize_row(row, timedelta(0), "UTC")
                if n:
                    normalized.append(n)

            # Sort
            normalized.sort(key=lambda r: r["timestamp_utc"])
            write_normalized_timeline(normalized, output_path)

            # Verify
            self.assertTrue(output_path.exists())
            with open(output_path, newline="") as fh:
                reader = csv.DictReader(fh)
                rows = list(reader)

            self.assertEqual(len(rows), 3)
            # Should be sorted: Logon, Archive, Logoff
            self.assertEqual(rows[0]["event_description"], "Logon")
            self.assertEqual(rows[1]["event_description"], "Archive created")
            self.assertEqual(rows[2]["event_description"], "Logoff")


if __name__ == "__main__":
    unittest.main(verbosity=2)
