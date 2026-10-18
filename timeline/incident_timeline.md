# GhostTrace — Reconstructed Incident Timeline

> **Case**: GhostTrace Insider Threat Simulation  
> **Lab**: TryHackMe — Autopsy Forensics Room  
> **Examiner**: Harshit Rawat, Kaushiki Choubey, Jiya Jain  
> **Timeline Timezone**: UTC (IST = UTC+5:30 shown for reference)  
> **Generated**: 2026-10-15

---

## Timeline Overview

The following timeline reconstructs a suspected insider data exfiltration incident on **13 September 2026** based on artifacts recovered from the TryHackMe Autopsy lab disk image. The suspect user account ('John') performed a compressed, deliberate series of actions over approximately 19 minutes.

---

## Chronological Event Sequence

### Phase 1 — System Access (08:14 – 08:18 UTC)

| Time (UTC) | IST | Event | Source | Finding | Confidence |
|---|---|---|---|---|---|
| 08:14:22 | 13:44 | User 'John' logs on interactively (Event ID 4624) | Security.evtx | F-001 | High |
| 08:17:05 | 13:47 | Elevated token acquired (Event ID 4672 — privilege assigned) | Security.evtx | F-002 | High |

**Assessment**: The suspect account authenticated successfully and immediately obtained administrative privileges. No brute-force or account lockout events were observed in the Security log, indicating use of legitimate credentials.

---

### Phase 2 — Document Access and Staging (08:19 – 08:25 UTC)

| Time (UTC) | IST | Event | Source | Finding | Confidence |
|---|---|---|---|---|---|
| 08:19:33 | 13:49 | company_data_Q3.xlsx accessed ($STANDARD_INFORMATION timestamp) | MFT | F-003 | Medium |
| 08:22:11 | 13:52 | Google search: "how to compress files windows command line" | Chrome History | F-004 | Medium |
| 08:24:44 | 13:54 | exfil.zip archive created on Desktop | MFT — $FILE_NAME | F-005 | High |

**Assessment**: The sequence — sensitive document accessed → compression searched → archive created — is consistent with manual data staging. The choice of filename 'exfil.zip' is unusual for a legitimate workflow and suggests awareness of the intended action. Note: NTFS access timestamps can be unreliable due to Windows timestamp update suppression; however, the $STANDARD_INFORMATION and $FILE_NAME creation timestamps corroborate the sequence.

---

### Phase 3 — Suspected Data Exfiltration (08:26 – 08:29 UTC)

| Time (UTC) | IST | Event | Source | Finding | Confidence |
|---|---|---|---|---|---|
| 08:26:00 | 13:56 | Navigation to wetransfer.com recorded in Chrome history | Chrome History | F-006 | High |
| 08:28:55 | 13:58 | Upload completion page at wetransfer.com recorded | Chrome History | F-007 | High |

**Assessment**: Two consecutive browser history entries confirm active use of WeTransfer, a public file-transfer service frequently used for exfiltration due to its lack of authentication requirements. The upload completion URL provides strong circumstantial evidence that the archive was transferred. The actual upload contents cannot be confirmed from local artifacts alone.

---

### Phase 4 — Anti-Forensic Activity (08:31 – 08:33 UTC)

| Time (UTC) | IST | Event | Source | Finding | Confidence |
|---|---|---|---|---|---|
| 08:31:07 | 14:01 | exfil.zip moved to Recycle Bin (timestamp from $I file) | $Recycle.Bin | F-008 | High |
| 08:32:30 | 14:02 | Recycle Bin permanently emptied ($R file absent) | $Recycle.Bin | F-009 | Medium |

**Assessment**: The archive was deleted and the Recycle Bin emptied within 2 minutes of the suspected upload. This rapid cleanup is consistent with deliberate anti-forensic behavior. The $I metadata file was recovered by Autopsy despite the permanent deletion attempt, revealing the original filename and deletion timestamp. The $R data file was not recoverable, confirming permanent deletion.

---

### Phase 5 — Session End and Secondary Activity (08:33 – 09:05 UTC)

| Time (UTC) | IST | Event | Source | Finding | Confidence |
|---|---|---|---|---|---|
| 08:33:45 | 14:03 | User 'John' logs off (Event ID 4634) | Security.evtx | F-010 | High |
| 09:05:22 | 14:35 | USB device inserted (Event ID 20001) | System.evtx | F-011 | Medium |

**Assessment**: The session lasted approximately 19 minutes — an unusually short and focused period. The USB device event at 09:05 is noted as a potential secondary exfiltration vector; however, no direct link to the 'John' account can be established from the available log artifacts, as the system event log does not record the associated user context in this instance.

---

## Incident Reconstruction Summary

```
[08:14] John logs on → obtains admin privileges
    ↓
[08:19] Opens sensitive document (company_data_Q3.xlsx)
    ↓
[08:22] Searches how to compress files → stages data
    ↓
[08:24] Creates exfil.zip archive on Desktop
    ↓
[08:26] Navigates to WeTransfer
    ↓
[08:28] Upload completes (strong circumstantial evidence)
    ↓
[08:31] Deletes exfil.zip → empties Recycle Bin
    ↓
[08:33] Logs off
    ↓
[09:05] USB device connected (possibly unrelated)
```

---

## Limitations

1. **File access timestamps** — Windows NTFS access timestamps are frequently suppressed by the OS (controlled by NtfsDisableLastAccessUpdate registry value). The $STANDARD_INFORMATION access timestamp for company_data_Q3.xlsx should be treated as supporting evidence, not conclusive proof.
2. **Upload confirmation** — The wetransfer.com completion URL in browser history provides strong circumstantial evidence of an upload but does not confirm the actual file contents transferred.
3. **USB event** — The USB insertion event at 09:05 lacks user-account context in the available log data and cannot be directly attributed to the 'John' account.
4. **Timezone** — All timestamps have been converted to UTC from the system's local timezone. IST values are provided for reference only.
5. **Deleted file content** — The exfil.zip $R data file was not recoverable. File metadata (name, size, deletion time) were recovered from the $I file.

---

*This timeline was produced as part of an authorized academic forensics investigation using simulated educational data provided by TryHackMe.*
