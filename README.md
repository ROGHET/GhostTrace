# GhostTrace: Digital Forensic Investigation and Incident Reconstruction

> **Course**: Honours Program in Cyber Security and Forensics — Cybersecurity and Forensics Laws, Theory Internal Assessment 2  
> **Institution**: K. J. Somaiya School of Engineering, Somaiya Vidyavihar University, Mumbai, India  
> **Academic Year**: 2026–2027

---

## Team Members

| Name | Roll No. | Email |
|------|----------|-------|
| Harshit Rawat | 16014024059 | harshit.rawat@somaiya.edu |
| Kaushiki Choubey | 16014024013 | kaushiki.c@somaiya.edu |
| Jiya Jain | 16014024022 | Jiya31@somaiya.edu |

---

## Abstract

GhostTrace is an academic digital forensics investigation project that reconstructs the sequence of events associated with a simulated insider-threat security incident. The investigation uses the TryHackMe "Autopsy" forensics lab (room: `autopsy2`) together with the Autopsy Digital Forensics platform (version 4.21) as the primary examination environment. A representative disk image provided by TryHackMe is analyzed to recover file-system metadata, deleted files, browser history, Windows event logs, and user-activity artifacts. Python scripts automate SHA-256 integrity verification, evidence inventory generation, and timeline normalization. The reconstructed timeline and findings register demonstrate how correlated forensic artifacts can establish the likely sequence of malicious actions in a real-world-style incident.

---

## Investigation Overview

**Lab Environment**: TryHackMe — Autopsy Forensics Room (`autopsy2`)  
**Primary Tool**: Autopsy Digital Forensics Platform v4.21  
**Evidence Type**: Windows NTFS disk image (FAT/NTFS)  
**Investigation Question**: What artifacts on the suspect system indicate data exfiltration or unauthorized access, and what is the reconstructed sequence of events?

---

## Repository Structure

```
GhostTrace/
├── README.md                          ← This file
├── requirements.txt                   ← Python dependencies
├── .gitignore                         ← Excluded files
│
├── docs/
│   └── report/
│       ├── GhostTrace_Digital_Forensics_Report.docx   ← Final report (Word)
│       └── GhostTrace_Digital_Forensics_Report.pdf    ← PDF version
│
├── evidence/
│   ├── evidence_inventory.csv         ← Evidence manifest
│   ├── hash_manifest.txt              ← SHA-256 integrity hashes
│   └── sample_data/                   ← Synthetic fixtures for testing
│       ├── sample_browser_history.sqlite
│       ├── sample_event.evtx.json
│       └── sample_mft_entries.csv
│
├── scripts/
│   ├── hash_evidence.py               ← SHA-256 hashing utility
│   ├── generate_inventory.py          ← Evidence inventory builder
│   ├── normalize_timeline.py          ← Timeline CSV normalizer
│   ├── parse_browser_history.py       ← Browser artifact parser
│   └── validate_outputs.py            ← Output validation script
│
├── analysis/
│   ├── investigation_notes.md         ← Detailed investigation notes
│   ├── findings_register.csv          ← Structured findings with confidence
│   └── artifact_mapping.md            ← Artifact-to-finding correlation
│
├── timeline/
│   ├── incident_timeline.csv          ← Master timeline (timestamped events)
│   └── incident_timeline.md           ← Human-readable timeline
│
├── screenshots/
│   ├── 01_environment_setup.png
│   ├── 02_case_creation.png
│   ├── 03_evidence_ingestion.png
│   ├── 04_hash_verification.png
│   ├── 05_artifact_examination.png
│   ├── 06_timeline_analysis.png
│   └── 07_findings_validation.png
│
├── presentation/
│   ├── GhostTrace_Presentation_Script.md   ← Video speaking script
│   └── recording_plan.md                  ← Scene-by-scene recording plan
│
└── tests/
    ├── test_hash_evidence.py
    ├── test_normalize_timeline.py
    └── fixtures/
        └── sample_files/
```

---

## Prerequisites

### Software Requirements
- **Python 3.10+** — [python.org](https://www.python.org/downloads/)
- **Autopsy 4.21** — [sleuthkit.org/autopsy](https://www.sleuthkit.org/autopsy/download.php)
- **Git** — [git-scm.com](https://git-scm.com/)
- **TryHackMe Account** — [tryhackme.com](https://tryhackme.com/) (for lab access)

### Python Dependencies

```bash
# Create and activate a virtual environment (recommended)
python -m venv venv
venv\Scripts\activate          # Windows
# source venv/bin/activate     # Linux/Mac

# Install dependencies
pip install -r requirements.txt
```

---

## Evidence Preparation

> **IMPORTANT**: This project uses a TryHackMe-provided forensic disk image. Do NOT commit raw disk images to version control. The `evidence/` directory contains only:
> - The evidence inventory CSV
> - SHA-256 hash manifest
> - Synthetic test fixtures (no real evidence data)

### Acquiring the Evidence

1. Log into TryHackMe and navigate to the **Autopsy** room (`autopsy2`)
2. Deploy the lab machine — a Windows disk image will be available inside the VM
3. Note the image filename, size, and path as displayed in the lab
4. Calculate the SHA-256 hash **before** examination:
   ```bash
   python scripts/hash_evidence.py --path /path/to/image.dd --output evidence/hash_manifest.txt
   ```

---

## Script Usage

### 1. Hash Evidence (`hash_evidence.py`)
Generates SHA-256 hashes for all files in a directory.
```bash
python scripts/hash_evidence.py --path evidence/ --output evidence/hash_manifest.txt
```

### 2. Generate Evidence Inventory (`generate_inventory.py`)
Builds a CSV inventory of evidence files with metadata.
```bash
python scripts/generate_inventory.py --path evidence/ --output evidence/evidence_inventory.csv
```

### 3. Normalize Timeline (`normalize_timeline.py`)
Sorts and deduplicates raw timeline entries, outputs a clean CSV.
```bash
python scripts/normalize_timeline.py --input timeline/raw_timeline.csv --output timeline/incident_timeline.csv --timezone IST
```

### 4. Parse Browser History (`parse_browser_history.py`)
Extracts URLs and timestamps from a Chromium SQLite history database.
```bash
python scripts/parse_browser_history.py --db evidence/sample_data/sample_browser_history.sqlite --output analysis/browser_findings.csv
```

### 5. Validate Outputs (`validate_outputs.py`)
Checks that all generated outputs are consistent and well-formed.
```bash
python scripts/validate_outputs.py
```

---

## Autopsy Workflow

1. **Launch Autopsy** → Select "New Case"
2. **Case Name**: `GhostTrace_Investigation`
3. **Add Data Source** → Select the disk image file
4. **Run Ingest Modules** → Enable: File Type Identification, Hash Lookup, Recent Activity, Keyword Search, Email Parser, Encryption Detection
5. **Examine Artifacts**:
   - `Results > Extracted Content > Web History` — browser artifacts
   - `Results > Extracted Content > Recent Documents` — recent file access
   - `Views > File Types` — examine file categories
   - `Analysis Results > Keyword Hits` — suspicious keyword matches
6. **Generate Timeline** → `Tools > Make Timeline`
7. **Export Report** → `Generate Report > HTML Report`

---

## Running Tests

```bash
# Run all tests
pytest tests/ -v

# Run with coverage
pytest tests/ -v --cov=scripts --cov-report=html
```

---

## Ethical and Legal Notice

This investigation is conducted entirely within an authorized academic laboratory environment (TryHackMe). All evidence is simulated training data provided by TryHackMe for educational purposes. No real systems, real individuals, or production environments were accessed. The investigation follows digital forensics best practices for evidence preservation and documentation.

---

## Report and Deliverables

- **Academic Report**: `docs/report/GhostTrace_Digital_Forensics_Report.docx`
- **Forensic Timeline**: `timeline/incident_timeline.csv`
- **Findings Register**: `analysis/findings_register.csv`
- **Presentation Script**: `presentation/GhostTrace_Presentation_Script.md`

---

## Submission

### GitHub Classroom
Once the faculty provides the GitHub Classroom assignment URL, push the repository:

```bash
# Initialize Git (if not already done)
git init
git add .
git commit -m "Initial GhostTrace forensics project submission"

# Add the GitHub Classroom remote (replace URL with actual classroom URL)
git remote add origin <GITHUB_CLASSROOM_REPO_URL>
git branch -M main
git push -u origin main
```

---

## Limitations

- The TryHackMe lab environment requires an active subscription and authenticated browser session — this cannot be automated.
- Autopsy GUI-based examination requires manual interaction; scripts supplement but do not replace the GUI workflow.
- Timestamp analysis assumes UTC unless otherwise stated; IST (UTC+5:30) conversions are documented in the timeline.
- Chain-of-custody documentation follows academic lab conventions and does not constitute legally admissible evidence handling.

---

*Project deadline: 18 October 2026 | Group/Title approval: 18 August 2026*
