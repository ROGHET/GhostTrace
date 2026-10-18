#!/usr/bin/env python3
"""
test_hash_evidence.py — Unit tests for hash_evidence.py
Tests run against synthetic fixture files; no real evidence is used.
"""

import hashlib
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

# Add scripts directory to path
sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))

from hash_evidence import compute_sha256, collect_targets, BUFFER_SIZE


class TestComputeSHA256(unittest.TestCase):
    """Tests for the core SHA-256 hashing function."""

    def setUp(self):
        """Create a temporary directory with known test files."""
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        """Clean up temporary files."""
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _create_file(self, name: str, content: bytes) -> Path:
        path = Path(self.tmpdir) / name
        path.write_bytes(content)
        return path

    def _expected_hash(self, content: bytes) -> str:
        return hashlib.sha256(content).hexdigest()

    def test_empty_file(self):
        """SHA-256 of an empty file should be the known constant."""
        path = self._create_file("empty.bin", b"")
        result = compute_sha256(path)
        expected = hashlib.sha256(b"").hexdigest()
        self.assertEqual(result, expected)

    def test_known_content(self):
        """SHA-256 of known content should match independently computed hash."""
        content = b"GhostTrace forensic evidence test fixture"
        path = self._create_file("known.txt", content)
        result = compute_sha256(path)
        self.assertEqual(result, self._expected_hash(content))

    def test_hash_length(self):
        """SHA-256 digest should always be 64 hex characters."""
        for content in [b"a", b"test data", b"\x00" * 1000]:
            path = self._create_file("test.bin", content)
            result = compute_sha256(path)
            self.assertEqual(len(result), 64)
            self.assertTrue(all(c in "0123456789abcdef" for c in result))

    def test_binary_content(self):
        """Binary content should hash correctly."""
        content = bytes(range(256))
        path = self._create_file("binary.bin", content)
        result = compute_sha256(path)
        self.assertEqual(result, self._expected_hash(content))

    def test_large_file_hash(self):
        """Test hashing a file larger than BUFFER_SIZE."""
        content = b"X" * (BUFFER_SIZE * 3 + 100)
        path = self._create_file("large.bin", content)
        result = compute_sha256(path)
        self.assertEqual(result, self._expected_hash(content))

    def test_different_content_different_hash(self):
        """Different content should produce different hashes."""
        p1 = self._create_file("f1.txt", b"content one")
        p2 = self._create_file("f2.txt", b"content two")
        self.assertNotEqual(compute_sha256(p1), compute_sha256(p2))

    def test_same_content_same_hash(self):
        """Identical content in different files should produce the same hash."""
        content = b"identical content"
        p1 = self._create_file("copy1.txt", content)
        p2 = self._create_file("copy2.txt", content)
        self.assertEqual(compute_sha256(p1), compute_sha256(p2))

    def test_file_not_found(self):
        """Should raise FileNotFoundError for non-existent files."""
        with self.assertRaises(FileNotFoundError):
            compute_sha256(Path(self.tmpdir) / "nonexistent.bin")

    def test_original_file_not_modified(self):
        """The original file must not be modified after hashing."""
        content = b"do not modify this"
        path = self._create_file("sensitive.bin", content)
        original_mtime = path.stat().st_mtime
        original_size = path.stat().st_size
        compute_sha256(path)
        self.assertEqual(path.read_bytes(), content)
        self.assertEqual(path.stat().st_size, original_size)


class TestCollectTargets(unittest.TestCase):
    """Tests for the target file collection function."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _create_file(self, relative: str, content: bytes = b"test") -> Path:
        path = Path(self.tmpdir) / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        return path

    def test_single_file(self):
        """Single file path should return a list with that one file."""
        path = self._create_file("single.txt")
        result = collect_targets(path)
        self.assertEqual(result, [path])

    def test_directory_collects_all_files(self):
        """Directory should return all files recursively."""
        files = [
            self._create_file("dir/a.txt"),
            self._create_file("dir/b.txt"),
            self._create_file("dir/sub/c.txt"),
        ]
        result = collect_targets(Path(self.tmpdir) / "dir")
        self.assertEqual(set(result), set(files))

    def test_empty_directory(self):
        """Empty directory should return an empty list."""
        empty_dir = Path(self.tmpdir) / "empty"
        empty_dir.mkdir()
        result = collect_targets(empty_dir)
        self.assertEqual(result, [])

    def test_sorted_output(self):
        """Output should be sorted."""
        self._create_file("dir/c.txt")
        self._create_file("dir/a.txt")
        self._create_file("dir/b.txt")
        result = collect_targets(Path(self.tmpdir) / "dir")
        self.assertEqual(result, sorted(result))

    def test_invalid_path_raises(self):
        """Non-existent path should raise ValueError."""
        with self.assertRaises(ValueError):
            collect_targets(Path(self.tmpdir) / "nonexistent")


if __name__ == "__main__":
    unittest.main(verbosity=2)
