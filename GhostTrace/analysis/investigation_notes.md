# GhostTrace — Investigation Notes

> **Case Reference**: GhostTrace-2026-001  
> **Lab Platform**: TryHackMe — Autopsy Forensics Room (`autopsy2`)  
> **Autopsy Version**: 4.21 (The Sleuth Kit)  
> **Evidence Type**: Windows NTFS disk image  
> **Examiners**: Harshit Rawat, Kaushiki Choubey, Jiya Jain  
> **Date of Analysis**: October 2026  
> **Status**: Completed

---

## 1. Case Background

**Investigation Question**:  
*What artifacts on the suspect system indicate unauthorized data access or exfiltration, and what is the reconstructed sequence of events?*

**Background**:  
This is an educational simulation conducted within the TryHackMe Autopsy forensics lab. The lab provides a pre-prepared Windows disk image representing a system belonging to a hypothetical organization where an insider threat incident is suspected. The image was analyzed to identify digital artifacts that reconstruct the incident.

**Note**: This is a simulated educational dataset — no real organization, real individuals, or real victims are involved.

---

## 2. Evidence Sources

| ID | Source | Type | Location in Image |
|----|--------|------|-------------------|
| EV-0001 | Disk image | NTFS disk image | TryHackMe lab VM |
| EV-0002 | Chrome Browser History | SQLite database | C:\Users\John\AppData\Local\Google\Chrome\User Data\Default\History |
| EV-0003 | Windows System Event Log | EVTX | C:\Windows\System32\winevt\Logs\System.evtx |
| EV-0004 | Windows Security Event Log | EVTX | C:\Windows\System32\winevt\Logs\Security.evtx |
| EV-0005 | User registry hive | Registry | C:\Users\John\NTUSER.DAT |
| EV-0006 | $MFT | NTFS Master File Table | $MFT (volume root) |
| EV-0007 | $Recycle.Bin | Deleted file metadata | C:\$Recycle.Bin |

---

## 3. Scope of Investigation

**In scope**:
- User account activity (logon/logoff events)
- File system metadata (timestamps, file creation, deletion)
- Browser history and web artifacts
- Windows event logs (Security, System)
- Recycle Bin metadata
- Autopsy-generated timeline

**Out of scope**:
- Network packet capture (not available in this image)
- Memory forensics (no memory dump provided)
- Email artifacts (no email client data present in available sample)
- Anti-virus or EDR logs (not available)

---

## 4. Autopsy Case Setup

### Case Details
```
Case Name:      GhostTrace_Investigation
Case Number:    CSFL-2026-001
Examiner:       Harshit Rawat / Kaushiki Choubey / Jiya Jain
Organization:   K.J. Somaiya School of Engineering
```

### Ingest Modules Enabled
1. **File Type Identification** — Identifies files by content (magic bytes), not extension
2. **Hash Lookup** — Calculates MD5/SHA-256 for all files
3. **Recent Activity** — Extracts browser history, recent documents, installed programs, USB devices
4. **Keyword Search** — Searches for keywords: "exfil", "wetransfer", "password", "confidential"
5. **Email Parser** — Parses email database files (PST, MBOX)
6. **Encryption Detection** — Flags potentially encrypted or password-protected files
7. **Extension Mismatch Detector** — Flags files whose extension does not match their content type

### Data Source
- Type: Raw disk image (.dd or .E01)
- Sector size: 512 bytes
- File system: NTFS
- OS: Windows (version determined from SOFTWARE registry hive)

---

## 5. Examination Procedure

### Phase A — Evidence Acquisition
1. Note the disk image filename, path, and size from the TryHackMe lab
2. Calculate SHA-256 hash using `certutil -hashfile <image> SHA256`
3. Record hash in `evidence/hash_manifest.txt`
4. Create working copy — do not modify the original
5. Launch Autopsy and create a new case

### Phase B — Case Ingestion
1. Add the disk image as a data source
2. Enable ingest modules (listed above)
3. Wait for ingestion to complete
4. Review the ingest summary for any errors

### Phase C — Artifact Examination
1. **File System Browse** → Navigate to user's Desktop, Documents, AppData
2. **Recent Activity → Web History** → Filter by date range (September 2026)
3. **Recent Activity → Recent Documents** → Review accessed files
4. **Event Logs** → Filter Event IDs 4624, 4634, 4672, 4673, 4688, 20001
5. **Deleted Files** → Review $Recycle.Bin contents and unallocated space
6. **Timeline** → Generate timeline and filter to September 13, 2026

### Phase D — Timeline Construction
1. Export timeline from Autopsy (Tools > Make Timeline)
2. Filter to the relevant date range
3. Export notable events to CSV
4. Import into `normalize_timeline.py` for normalization
5. Cross-reference timestamps between sources

---

## 6. Key Observations

### 6.1 Browser History Analysis
- Chrome History database parsed by Autopsy's Recent Activity module
- WebKit timestamps converted correctly to UTC
- Two key URLs identified: wetransfer.com navigation and upload confirmation
- No evidence of browsing to cloud storage (Dropbox, OneDrive, Google Drive) — WeTransfer was the only external transfer site visited

### 6.2 File System Metadata
- $FILE_NAME creation timestamps are more reliable than $STANDARD_INFORMATION for establishing when files were first created
- $STANDARD_INFORMATION timestamps can be modified by user-mode tools (timestomping); $FILE_NAME requires kernel-level access to modify
- The creation timestamp for exfil.zip (F-005) came from $FILE_NAME — higher confidence

### 6.3 Recycle Bin Forensics
- Autopsy parses $I (index) and $R (data) files in $Recycle.Bin
- $I files contain: original path, original file size, deletion timestamp
- $R files contain: actual file contents
- F-008: $I file recovered → original filename (exfil.zip) and deletion time confirmed
- F-009: $R file absent → contents permanently deleted or overwritten

### 6.4 Windows Event Logs
- Event ID 4624 (Logon), 4634 (Logoff), 4672 (Special privileges assigned)
- No Event 4625 (Failed logon) observed — no evidence of brute force
- USB Event ID 20001: Plug and Play device installation, no user context available

### 6.5 NTFS $MFT Analysis
- MFT entries provide MAC timestamps (Modified, Accessed, Created) for all files
- For company_data_Q3.xlsx: access timestamp updated at 08:19:33 UTC (F-003)
- Note: On Windows, access timestamps are often suppressed. The fact that they updated here may indicate the NtfsDisableLastAccessUpdate registry key was not set, OR the timestamp reflects a metadata operation rather than file open.

---

## 7. Artifact Correlation Map

```
Security Log (F-001) ─────► Logon at 08:14
                              │
Security Log (F-002) ─────► Admin privileges at 08:17
                              │
MFT — xlsx (F-003) ────────► Document accessed at 08:19
                              │
Chrome History (F-004) ────► Search for compression at 08:22
                              │
MFT — exfil.zip (F-005) ──► Archive created at 08:24
                              │
Chrome History (F-006) ────► WeTransfer navigation at 08:26
                              │
Chrome History (F-007) ────► Upload completion at 08:28
                              │
$Recycle.Bin (F-008) ──────► Archive deleted at 08:31
                              │
$Recycle.Bin (F-009) ──────► Recycle Bin emptied at 08:32
                              │
Security Log (F-010) ─────► Logoff at 08:33
                              │
System Log (F-011) ────────► USB device at 09:05 (possibly unrelated)
```

---

## 8. Investigative Hypotheses — Assessment

| Hypothesis | Status | Supporting Evidence | Contradicting Evidence |
|---|---|---|---|
| H1: User 'John' accessed sensitive data | Supported | F-001, F-002, F-003 | None identified |
| H2: User staged data in a compressed archive | Supported | F-004, F-005 | Archive contents not confirmed |
| H3: Data was exfiltrated via WeTransfer | Supported (circumstantial) | F-006, F-007 | Upload contents not verifiable from local artifacts |
| H4: User attempted to conceal actions | Supported | F-008, F-009 | Could be routine file cleanup |
| H5: USB used as secondary exfiltration | Insufficient evidence | F-011 (USB connected) | No user account context; timing gap of 31 minutes |

---

## 9. Limitations and Caveats

1. **No network artifacts** — WeTransfer upload contents cannot be confirmed from local disk artifacts
2. **No memory dump** — Volatile memory artifacts (running processes, network connections at time of incident) are unavailable
3. **Timestamp reliability** — $STANDARD_INFORMATION timestamps can be manipulated; findings prioritize $FILE_NAME timestamps
4. **Baseline unavailable** — Normal behavior patterns for user 'John' are not established; behavioral anomalies are assessed on general expectation, not per-user baseline
5. **Educational dataset** — The disk image is provided by TryHackMe for educational purposes; findings reflect the simulation designed by the platform
6. **Chain of custody** — This investigation follows academic laboratory conventions; it does not satisfy legal chain-of-custody requirements for court proceedings

---

*Prepared as part of GhostTrace academic forensics investigation — K.J. Somaiya School of Engineering*
