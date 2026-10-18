#!/usr/bin/env python3
"""
test_gui_backend.py — Unit & Integration Tests for GhostTrace GUI Backend
Tests all Flask routes, security path validation, hashing API, and automated validation runner.
"""

import io
import json
import os
import sys
import unittest
from pathlib import Path

# Add project root and scripts directory to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "scripts"))

from app import app, is_safe_path, BASE_DIR


class TestGUIBackend(unittest.TestCase):
    """Test suite for GhostTrace Flask GUI application."""

    def setUp(self):
        app.config["TESTING"] = True
        app.config["WTF_CSRF_ENABLED"] = False
        self.client = app.test_client()

    def test_security_path_traversal(self):
        """Path traversal validator must reject paths outside project root."""
        # Safe paths
        self.assertTrue(is_safe_path(BASE_DIR / "evidence" / "evidence_inventory.csv", BASE_DIR))
        self.assertTrue(is_safe_path(BASE_DIR / "timeline" / "incident_timeline.csv", BASE_DIR))
        self.assertTrue(is_safe_path(BASE_DIR, BASE_DIR))

        # Malicious paths attempting directory traversal
        outside_path = BASE_DIR / ".." / "some_file.txt"
        self.assertFalse(is_safe_path(outside_path, BASE_DIR))
        system_path = Path("C:/Windows/System32/cmd.exe")
        self.assertFalse(is_safe_path(system_path, BASE_DIR))

    def test_dashboard_route(self):
        """GET / should render the dashboard with status 200 and key indicators."""
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        html = response.data.decode("utf-8")
        self.assertIn("GhostTrace", html)
        self.assertIn("Investigation Overview", html)
        self.assertIn("Evidence Catalog", html)

    def test_evidence_route(self):
        """GET /evidence should list recorded evidence items."""
        response = self.client.get("/evidence")
        self.assertEqual(response.status_code, 200)
        html = response.data.decode("utf-8")
        self.assertIn("Evidence Inventory Management", html)
        self.assertIn("EV-0001", html)

    def test_hash_verification_route(self):
        """GET /hash-verification should display the hashing workstation."""
        response = self.client.get("/hash-verification")
        self.assertEqual(response.status_code, 200)
        html = response.data.decode("utf-8")
        self.assertIn("Hash Verification", html)
        self.assertIn("SHA-256 Digest Calculator", html)

    def test_api_hash_calculate_existing_file(self):
        """POST /api/hash/calculate on an existing evidence file should return 64-char hex."""
        response = self.client.post("/api/hash/calculate", data={
            "selected_file": "evidence/evidence_inventory.csv",
            "reference_hash": "",
        })
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertTrue(data["success"])
        self.assertEqual(len(data["sha256"]), 64)
        self.assertEqual(data["target_name"], "evidence_inventory.csv")

    def test_api_hash_calculate_with_matching_reference(self):
        """POST /api/hash/calculate with reference should accurately report match."""
        # First get actual hash
        res1 = self.client.post("/api/hash/calculate", data={
            "selected_file": "evidence/evidence_inventory.csv",
        })
        actual_hash = res1.get_json()["sha256"]

        # Now test with matching reference
        res2 = self.client.post("/api/hash/calculate", data={
            "selected_file": "evidence/evidence_inventory.csv",
            "reference_hash": actual_hash,
        })
        self.assertEqual(res2.status_code, 200)
        data2 = res2.get_json()
        self.assertTrue(data2["is_match"])

        # Test with mismatched reference
        res3 = self.client.post("/api/hash/calculate", data={
            "selected_file": "evidence/evidence_inventory.csv",
            "reference_hash": "0000000000000000000000000000000000000000000000000000000000000000",
        })
        self.assertEqual(res3.status_code, 200)
        data3 = res3.get_json()
        self.assertFalse(data3["is_match"])

    def test_api_hash_calculate_traversal_rejection(self):
        """POST /api/hash/calculate must reject traversal attempts with 403."""
        response = self.client.post("/api/hash/calculate", data={
            "selected_file": "../../Windows/System32/calc.exe",
        })
        self.assertEqual(response.status_code, 403)

    def test_timeline_route(self):
        """GET /timeline should display the reconstructed incident timeline."""
        response = self.client.get("/timeline")
        self.assertEqual(response.status_code, 200)
        html = response.data.decode("utf-8")
        self.assertIn("Incident Timeline", html)
        self.assertIn("company_data_Q3.xlsx", html)

    def test_api_timeline_export(self):
        """GET /api/timeline/export should return downloadable CSV."""
        response = self.client.get("/api/timeline/export")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.mimetype, "text/csv")
        self.assertIn(b"timestamp_utc", response.data)

    def test_browser_forensics_route(self):
        """GET /browser-forensics should display Chromium history analysis."""
        response = self.client.get("/browser-forensics")
        self.assertEqual(response.status_code, 200)
        html = response.data.decode("utf-8")
        self.assertIn("Browser Forensics", html)
        self.assertIn("wetransfer.com", html)

    def test_findings_route(self):
        """GET /findings should render the findings matrix."""
        response = self.client.get("/findings")
        self.assertEqual(response.status_code, 200)
        html = response.data.decode("utf-8")
        self.assertIn("Forensic Findings Register", html)
        self.assertIn("F-001", html)

    def test_api_findings_json(self):
        """GET /api/findings should return valid JSON list of findings."""
        response = self.client.get("/api/findings")
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertTrue(data["success"])
        self.assertGreaterEqual(data["total"], 10)

    def test_validation_route(self):
        """GET /validation should display the audit validation center."""
        response = self.client.get("/validation")
        self.assertEqual(response.status_code, 200)
        html = response.data.decode("utf-8")
        self.assertIn("Validation Center", html)
        self.assertIn("Checks Passed", html)

    def test_api_validation_run(self):
        """POST /api/validation/run should execute audit and return 29+ passing checks."""
        response = self.client.post("/api/validation/run")
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertTrue(data["success"])
        self.assertGreaterEqual(data["summary"]["passed"], 28)
        self.assertEqual(data["summary"]["failed"], 0)

    def test_reports_route(self):
        """GET /reports should display the academic report viewer."""
        response = self.client.get("/reports")
        self.assertEqual(response.status_code, 200)
        html = response.data.decode("utf-8")
        self.assertIn("Academic Forensics Report Viewer", html)

    def test_view_raw_report_route(self):
        """GET /report/view should serve the full academic HTML report."""
        response = self.client.get("/report/view")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.mimetype, "text/html")
        self.assertIn(b"GhostTrace", response.data)

    def test_settings_route(self):
        """GET /settings should display system properties and team members."""
        response = self.client.get("/settings")
        self.assertEqual(response.status_code, 200)
        html = response.data.decode("utf-8")
        self.assertIn("Harshit Rawat", html)
        self.assertIn("16014024059", html)
        self.assertIn("127.0.0.1", html)

    def test_api_system_status(self):
        """GET /api/system/status should return healthy status."""
        response = self.client.get("/api/system/status")
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data["status"], "healthy")


if __name__ == "__main__":
    unittest.main()
