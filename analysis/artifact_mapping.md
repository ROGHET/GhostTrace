# GhostTrace — Artifact-to-Finding Correlation Map

## Purpose
This document maps each forensic artifact examined during the GhostTrace investigation to the specific findings it supports. It serves as a cross-reference between the raw evidence sources and the conclusions drawn in the findings register.

---

## Artifact Correlation Matrix

| Artifact | Location in Image | Findings Supported | Analysis Method |
|----------|-------------------|-------------------|-----------------|
| Windows Security Event Log | C:\Windows\System32\winevt\Logs\Security.evtx | F-001, F-002, F-010 | Autopsy — Event Log Parser |
| Windows System Event Log | C:\Windows\System32\winevt\Logs\System.evtx | F-011 | Autopsy — Event Log Parser |
| Chrome Browser History DB | C:\Users\John\AppData\Local\Google\Chrome\User Data\Default\History | F-004, F-006, F-007 | Autopsy — Recent Activity (Web History) |
| NTFS MFT — company_data_Q3.xlsx | C:\Users\John\Desktop\company_data_Q3.xlsx | F-003 | Autopsy — File System Browser |
| NTFS MFT — exfil.zip | C:\Users\John\Desktop\exfil.zip (deleted) | F-005 | Autopsy — File System Browser |
| $Recycle.Bin $I metadata | C:\$Recycle.Bin\[SID]\$IXXXXXX | F-008 | Autopsy — Deleted Files |
| $Recycle.Bin folder timestamp | C:\$Recycle.Bin\[SID]\ | F-009 | Autopsy — File System Metadata |
| Autopsy Timeline Export | Generated | F-012 | Autopsy — Make Timeline |

---

## Event Log Event ID Reference

| Event ID | Log | Meaning | Findings |
|----------|-----|---------|---------|
| 4624 | Security | Successful account logon | F-001 |
| 4634 | Security | Account logoff | F-010 |
| 4672 | Security | Special privileges assigned to new logon | F-002 |
| 20001 | System | Plug and Play device installed | F-011 |

---

## Browser History Entry Types

| Entry | URL Pattern | Finding |
|-------|-------------|---------|
| Google search | google.com/search?q=how+to+compress+files | F-004 |
| WeTransfer navigation | wetransfer.com | F-006 |
| WeTransfer completion | wetransfer.com/transfer/[ID]/... | F-007 |

---

## NTFS Timestamp Reliability Assessment

| Timestamp Type | Reliability | Reason | Used in Finding |
|----------------|-------------|--------|----------------|
| $FILE_NAME Created | High | Kernel-controlled; difficult to modify without special privileges | F-005 |
| $STANDARD_INFORMATION Modified | Medium | Can be modified by user tools (timestomping) | — |
| $STANDARD_INFORMATION Accessed | Low-Medium | Frequently suppressed by NtfsDisableLastAccessUpdate | F-003 (medium confidence) |
| $Recycle.Bin $I deletion time | High | Written by OS at deletion time | F-008 |

---

## Finding Confidence Summary

| Confidence | Count | Findings |
|-----------|-------|---------|
| High | 8 | F-001, F-002, F-005, F-006, F-007, F-008, F-010, F-012 |
| Medium | 4 | F-003, F-004, F-009, F-011 |
| Low | 0 | — |

---

*Document maintained as part of GhostTrace academic forensics investigation*
