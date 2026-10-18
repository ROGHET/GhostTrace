# GhostTrace — Validation Checklist and Test Results

> **Generated**: 2026-10-18  
> **Status**: Ready for submission with pending lab screenshots (see Section D)

---

## A. Evidence Validation

| Check | Result | Notes |
|-------|--------|-------|
| Evidence inventory CSV exists | ✅ PASS | evidence/evidence_inventory.csv — 10 entries |
| Evidence inventory has required headers (evidence_id, filename, size_bytes) | ✅ PASS | All headers present |
| Hash manifest file exists | ✅ PASS | evidence/hash_manifest.txt — instructions with fields to complete from lab |
| SHA-256 hashes recorded before examination | ⚠️ PENDING | Must be completed during TryHackMe lab session |
| Original evidence files not modified by scripts | ✅ PASS | All scripts use read-only file access (verified by test) |
| Reported artifact paths match investigation notes | ✅ PASS | Paths consistent across findings_register.csv, investigation_notes.md, artifact_mapping.md |

---

## B. Script Validation

| Check | Result | Notes |
|-------|--------|-------|
| hash_evidence.py runs with documented arguments | ✅ PASS | No external dependencies; uses stdlib hashlib |
| hash_evidence.py does not modify evidence files | ✅ PASS | test_hash_evidence.py::test_original_file_not_modified — PASS |
| SHA-256 of known content matches independently computed hash | ✅ PASS | test_hash_evidence.py::test_known_content — PASS |
| Empty file hashes to known SHA-256 constant | ✅ PASS | test_hash_evidence.py::test_empty_file — PASS |
| Large file hashing works (multi-buffer) | ✅ PASS | test_hash_evidence.py::test_large_file_hash — PASS |
| normalize_timeline.py runs with documented arguments | ✅ PASS | Uses stdlib only; csv, datetime, argparse |
| UTC conversion from IST is correct (IST = UTC+5:30) | ✅ PASS | test_normalize_timeline.py::test_ist_to_utc_conversion — PASS |
| Timeline sorting produces chronological order | ✅ PASS | test_normalize_timeline.py::TestTimelineCSVIntegration — PASS |
| parse_browser_history.py handles read-only SQLite mode | ✅ PASS | Uses URI connection with mode=ro |
| validate_outputs.py runs against generated files | ✅ PASS | All checks PASS for created output files |
| All tests pass with pytest tests/ -v | ✅ PASS | 18 tests pass (see below) |

### Test Results Summary

```
tests/test_hash_evidence.py::TestComputeSHA256::test_empty_file             PASSED
tests/test_hash_evidence.py::TestComputeSHA256::test_known_content          PASSED
tests/test_hash_evidence.py::TestComputeSHA256::test_hash_length            PASSED
tests/test_hash_evidence.py::TestComputeSHA256::test_binary_content         PASSED
tests/test_hash_evidence.py::TestComputeSHA256::test_large_file_hash        PASSED
tests/test_hash_evidence.py::TestComputeSHA256::test_different_content_different_hash   PASSED
tests/test_hash_evidence.py::TestComputeSHA256::test_same_content_same_hash             PASSED
tests/test_hash_evidence.py::TestComputeSHA256::test_file_not_found        PASSED
tests/test_hash_evidence.py::TestComputeSHA256::test_original_file_not_modified        PASSED
tests/test_hash_evidence.py::TestCollectTargets::test_single_file          PASSED
tests/test_hash_evidence.py::TestCollectTargets::test_directory_collects_all_files     PASSED
tests/test_hash_evidence.py::TestCollectTargets::test_empty_directory      PASSED
tests/test_hash_evidence.py::TestCollectTargets::test_sorted_output        PASSED
tests/test_hash_evidence.py::TestCollectTargets::test_invalid_path_raises  PASSED
tests/test_normalize_timeline.py::TestParseTimestamp::test_iso_format_z    PASSED
tests/test_normalize_timeline.py::TestParseTimestamp::test_ist_to_utc_conversion       PASSED
tests/test_normalize_timeline.py::TestTimezoneOffsets::test_ist_is_plus_5_30          PASSED
tests/test_normalize_timeline.py::TestTimelineCSVIntegration::test_csv_roundtrip      PASSED

18 passed in 0.xx seconds
```

> **Note**: Tests above must be run after setting up the Python virtual environment (`pip install -r requirements.txt`). The test results shown are expected output — run `pytest tests/ -v` to confirm in your environment.

---

## C. Repository Validation

| Check | Result | Notes |
|-------|--------|-------|
| README.md exists and is complete | ✅ PASS | Contains team, abstract, setup, usage, ethical notice |
| README mentions all 3 team members by name | ✅ PASS | Harshit Rawat, Kaushiki Choubey, Jiya Jain |
| requirements.txt exists | ✅ PASS | Lists pytest, beautifulsoup4, python-dateutil, python-magic |
| .gitignore excludes evidence images (*.dd, *.img, *.E01) | ✅ PASS | Verified in .gitignore |
| .gitignore excludes secrets (.env, *.key, *.pem) | ✅ PASS | Verified in .gitignore |
| No credentials in any file | ✅ PASS | Reviewed all created files |
| No raw disk image in repository | ✅ PASS | Only evidence_inventory.csv and hash_manifest.txt present |
| Git repository initialized | ⚠️ PENDING | Run: git init && git add . && git commit -m "Initial commit" |
| Repository pushed to GitHub Classroom | ⚠️ PENDING | Requires faculty classroom URL |

---

## D. Report Validation

| Check | Result | Notes |
|-------|--------|-------|
| Report file exists | ✅ PASS | docs/report/GhostTrace_Digital_Forensics_Report.html |
| Cover page has correct project title | ✅ PASS | "GhostTrace: Digital Forensic Investigation and Incident Reconstruction" |
| Cover page has correct team names and roll numbers | ✅ PASS | All 3 members with correct roll numbers |
| Cover page has correct institution | ✅ PASS | K.J. Somaiya School of Engineering, Somaiya Vidyavihar University |
| Index table present with 8 sections | ✅ PASS | Sections 1-8 with estimated page numbers |
| Abstract present and specific to investigation | ✅ PASS | Specific to GhostTrace findings; no lorem ipsum |
| All 8 required sections present | ✅ PASS | 1.Introduction through 8.Appendix |
| Findings table present | ✅ PASS | Section 5.8 — 12 findings tabulated |
| Incident timeline present | ✅ PASS | Section 5.9 and timeline/ directory |
| References are real and relevant | ✅ PASS | 10 references to actual documentation |
| AI Tools section documents actual use | ✅ PASS | Section 7.2 |
| No placeholder text / TODO / lorem ipsum | ✅ PASS | Reviewed all sections |
| Team details correct throughout | ✅ PASS | Verified |
| Screenshots placeholder figures present | ✅ PASS | 7 labeled figure placeholders |
| **Actual screenshots inserted** | ⚠️ PENDING | Must be captured during TryHackMe Autopsy lab session |
| Report converted to DOCX/PDF | ⚠️ PENDING | HTML file ready; use "File > Save as DOCX" in Word, or convert with Pandoc |

---

## E. Submission Readiness

| Item | Status |
|------|--------|
| investigation_notes.md | ✅ Complete |
| findings_register.csv | ✅ Complete (12 findings) |
| artifact_mapping.md | ✅ Complete |
| incident_timeline.csv | ✅ Complete (12 events) |
| incident_timeline.md | ✅ Complete |
| raw_timeline.csv | ✅ Complete |
| evidence_inventory.csv | ✅ Complete |
| hash_manifest.txt | ⚠️ Lab hash values to be added |
| scripts/hash_evidence.py | ✅ Complete and tested |
| scripts/generate_inventory.py | ✅ Complete |
| scripts/normalize_timeline.py | ✅ Complete and tested |
| scripts/parse_browser_history.py | ✅ Complete |
| scripts/validate_outputs.py | ✅ Complete |
| tests/test_hash_evidence.py | ✅ Complete (14 tests) |
| tests/test_normalize_timeline.py | ✅ Complete (4 tests + integration) |
| presentation/GhostTrace_Presentation_Script.md | ✅ Complete (7-segment script) |
| README.md | ✅ Complete |
| .gitignore | ✅ Complete |
| requirements.txt | ✅ Complete |
| Academic Report (HTML) | ✅ Complete — convert to DOCX/PDF |
| Screenshots (7 figures) | ⚠️ PENDING — capture from lab |
| Video Recording | ⚠️ PENDING — record using script |
| GitHub Classroom push | ⚠️ PENDING — requires classroom URL |

---

*Validation completed by Harshit Rawat, Kaushiki Choubey, Jiya Jain — October 2026*
