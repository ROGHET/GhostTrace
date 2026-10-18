# GhostTrace — Video Presentation Script
# 7–8 Minute Recording Plan and Speaking Script

**Project**: GhostTrace: Digital Forensic Investigation and Incident Reconstruction  
**Course**: Honours Program in Cyber Security and Forensics — CSFL Theory IA-2  
**Institution**: K.J. Somaiya School of Engineering, Somaiya Vidyavihar University  
**Team**: Harshit Rawat | Kaushiki Choubey | Jiya Jain  
**Target Duration**: 7 minutes 30 seconds

---

## Recording Order and Time Allocation

| Segment | Speaker | Duration | Content |
|---------|---------|----------|---------|
| Opening | Harshit Rawat | 0:00 – 0:45 | Introduction, problem statement, investigation objective |
| Tools & Methodology | Kaushiki Choubey | 0:45 – 2:30 | Tools, evidence, integrity verification, workflow |
| Live Investigation | Jiya Jain | 2:30 – 5:45 | Autopsy demo, artifact examination, timeline |
| Findings & Conclusion | All three | 5:45 – 7:30 | Key findings, limitations, conclusion, future scope |

---

## Scene-by-Scene Recording Plan

### SCENE 1 — Introduction (0:00–0:45) — Speaker: Harshit Rawat
**Screen**: Title slide or project README with project title visible

**Talking Points**:
- Greet and introduce the team and project
- State the investigation objective clearly
- Explain why digital forensics matters

---

### SCENE 2 — Tools and Environment (0:45–1:30) — Speaker: Kaushiki Choubey
**Screen**: TryHackMe lab landing page (logged in) and/or Autopsy interface

**Talking Points**:
- Introduce TryHackMe and the Autopsy lab
- Explain Autopsy as a forensic examination tool
- Mention Python scripts for automation

---

### SCENE 3 — Evidence and Integrity Verification (1:30–2:30) — Speaker: Kaushiki Choubey
**Screen**: Terminal showing SHA-256 hash computation + hash_manifest.txt

**Talking Points**:
- Explain why SHA-256 hashing matters for evidence integrity
- Show the hash_evidence.py script running
- Show the evidence_inventory.csv

---

### SCENE 4 — Autopsy Case Creation and Evidence Ingestion (2:30–3:30) — Speaker: Jiya Jain
**Screen**: Autopsy — New Case wizard and ingestion progress

**Talking Points**:
- Walk through creating a case in Autopsy
- Show evidence ingestion and ingest module selection
- Explain what each ingest module does

---

### SCENE 5 — Artifact Examination (3:30–5:00) — Speaker: Jiya Jain
**Screen**: Autopsy — Web History panel, Event Log viewer, File System browser

**Talking Points**:
- Show Chrome browser history: WeTransfer URL and upload confirmation
- Show Event Log entries: logon (4624), privilege (4672), logoff (4634)
- Show MFT entry for exfil.zip and company_data_Q3.xlsx
- Show Recycle Bin $I file recovery

---

### SCENE 6 — Timeline Reconstruction (5:00–5:45) — Speaker: Jiya Jain
**Screen**: Autopsy Timeline view + incident_timeline.md

**Talking Points**:
- Show Autopsy's built-in timeline view
- Walk through the key events in chronological order
- Summarize the 19-minute incident window

---

### SCENE 7 — Findings, Limitations, Conclusion (5:45–7:30) — All Members
**Screen**: findings_register.csv / analysis summary slide

**Sub-segments**:
- **Harshit** (5:45–6:15): State the verified findings; directly answer the investigation question
- **Kaushiki** (6:15–6:45): Discuss limitations — what cannot be confirmed; ethical considerations
- **Jiya** (6:45–7:15): Future scope — what would strengthen the investigation
- **All** (7:15–7:30): Thank you and conclusion

---

## Full Speaking Script

---

### HARSHIT RAWAT — Segment 1: Introduction (0:00–0:45)

> "Hello, we are Team GhostTrace from K.J. Somaiya School of Engineering.
> I'm Harshit Rawat, and with me are Kaushiki Choubey and Jiya Jain.
> 
> Our project is titled **GhostTrace: Digital Forensic Investigation and Incident Reconstruction**, submitted as part of Theory Internal Assessment 2 for our Honours Program in Cyber Security and Forensics.
> 
> The core question we set out to answer is: **When an insider threat incident is suspected — how do we use digital forensic artifacts to reconstruct exactly what happened?**
> 
> In modern organizations, data theft often happens quietly. An employee logs on, accesses sensitive files, transfers them, deletes the evidence, and logs off — all within minutes. Our investigation demonstrates how digital forensics can recover this sequence of events from a Windows disk image, even when the attacker tried to cover their tracks.
> 
> We used TryHackMe's Autopsy forensics lab as our investigation platform. Kaushiki will now walk you through our tools and methodology."

---

### KAUSHIKI CHOUBEY — Segment 2: Tools and Environment (0:45–1:30)

> "Thank you, Harshit.
> 
> For our investigation environment, we used **TryHackMe**, a leading cybersecurity training platform, specifically their Autopsy forensics lab. This provides us with a legally authorized, simulated Windows disk image designed for digital forensics education.
> 
> Our primary examination tool is **Autopsy version 4.21**, developed by The Sleuth Kit team. Autopsy provides a comprehensive graphical interface for forensic examination — it can browse file systems, parse browser history, analyze Windows event logs, recover deleted files, and generate chronological timelines.
> 
> We supplemented Autopsy with custom Python scripts for SHA-256 integrity verification, evidence inventory generation, and timeline normalization. All scripts are included in our GitHub repository."

---

### KAUSHIKI CHOUBEY — Segment 3: Evidence Integrity (1:30–2:30)

> "Before examining any evidence, we must ensure its integrity. In digital forensics, this means calculating a SHA-256 cryptographic hash of the disk image **before** any examination begins.
> 
> You can see on screen our `hash_evidence.py` script generating the SHA-256 hash. This hash acts like a fingerprint — if even a single bit of the image changes, the hash changes completely. We record this in our hash manifest file, creating an academic chain-of-custody record.
> 
> We also generated an evidence inventory CSV documenting all ten evidence artifacts we examined, including their file sizes, types, and modification timestamps.
> 
> This methodical documentation is critical — in a real investigation, it's what establishes the admissibility and reliability of your findings. Jiya will now take you through the actual Autopsy investigation."

---

### JIYA JAIN — Segment 4: Autopsy Case and Ingestion (2:30–3:30)

> "Thank you, Kaushiki.
> 
> I'll now demonstrate our Autopsy investigation. We start by creating a new Autopsy case — this is our case management container. You can see the case details: case name GhostTrace_Investigation, examiner names, and institution.
> 
> We then add the disk image as a data source. Autopsy will process the entire file system. We enable six ingest modules: File Type Identification, Hash Lookup, Recent Activity — which extracts browser history and recently accessed files — Keyword Search, Email Parser, and Encryption Detection.
> 
> The ingestion process analyzes the entire disk image and populates Autopsy's results tree with categorized findings. Once complete, we have a structured view of all artifacts on the system."

---

### JIYA JAIN — Segment 5: Artifact Examination (3:30–5:00)

> "Let's look at the key artifacts.
> 
> First, **browser history**. Under Results > Extracted Content > Web History, Autopsy has parsed the Chrome browser's SQLite database and displayed all URLs with their timestamps. Here we can see the two critical entries: at 08:26 UTC, the user navigated to wetransfer.com, and at 08:28 UTC, a WeTransfer upload completion page was recorded.
> 
> Next, **Windows Event Logs**. Autopsy parses EVTX files and lets us filter by Event ID. Event ID 4624 confirms the user 'John' logged on at 08:14:22 UTC. Event ID 4672 at 08:17 shows administrative privileges were assigned. Event ID 4634 at 08:33 confirms logoff — a total session of just 19 minutes.
> 
> Moving to the **file system**, the MFT entry for exfil.zip shows a creation timestamp of 08:24:44 UTC — placed on the Desktop, consistent with the compression search we saw in browser history.
> 
> Finally, **Recycle Bin forensics**. Even though the archive was deleted and the Recycle Bin was emptied, Autopsy recovered the $I metadata file which reveals the original filename 'exfil.zip', its size, and the deletion timestamp of 08:31:07 UTC."

---

### JIYA JAIN — Segment 6: Timeline (5:00–5:45)

> "With all these artifacts correlated, we can now see the complete picture in Autopsy's timeline view.
> 
> [Show Timeline screen]
> 
> The incident unfolded over 19 minutes and 23 seconds on the morning of September 13th. In order: logon, privilege escalation, sensitive document access, searching for compression tools, creating the archive, navigating to WeTransfer, uploading the file, deleting and permanently purging the archive, then logging off.
> 
> Every step left a trace — across event logs, browser history, the MFT, and the Recycle Bin. This is the power of multi-source artifact correlation in digital forensics. Back to Harshit for our findings."

---

### HARSHIT RAWAT — Segment 7a: Verified Findings (5:45–6:15)

> "Based on our examination, here are our verified findings.
> 
> The investigation question was: do the artifacts indicate unauthorized data access or exfiltration? The answer is yes, with high confidence.
> 
> The evidence shows user 'John' logged on, obtained administrative privileges, accessed a sensitive financial document, created a compressed archive, uploaded it to WeTransfer, deleted the archive, and emptied the Recycle Bin — all within 19 minutes. This pattern is consistent with a deliberate insider data exfiltration attempt followed by anti-forensic cleanup.
> 
> Nine of our twelve findings are rated high confidence. The only uncertainty is the actual content of the upload — browser history confirms the transfer action but cannot reveal the transmitted data."

---

### KAUSHIKI CHOUBEY — Segment 7b: Limitations (6:15–6:45)

> "Importantly, our findings have limitations we must acknowledge honestly.
> 
> First: we cannot confirm the upload contents from local disk artifacts alone. Second: NTFS access timestamps can be unreliable and should not be treated as definitive proof of file opening. Third: the USB device event lacks user context and cannot be directly attributed to 'John'. Fourth: this is a simulated educational dataset — our methodology applies to real investigations, but the findings reflect the simulation designed by TryHackMe.
> 
> In a real legal investigation, these findings would require corroboration from network logs, server-side records, or endpoint monitoring before prosecution could proceed."

---

### JIYA JAIN — Segment 7c: Future Scope (6:45–7:15)

> "For future work, several enhancements would strengthen this investigation.
> 
> First, integrating network packet capture analysis would allow us to confirm the actual data transferred via WeTransfer. Second, a memory forensics analysis using Volatility would reveal the processes running during the incident and any loaded encryption keys. Third, comparing the suspect's behavior against a historical baseline would more precisely identify behavioral anomalies. Fourth, extending the analysis to setupapi.dev.log would reveal prior USB device connection history. Finally, using The Sleuth Kit's command-line tools alongside Autopsy would allow more granular control over raw MFT parsing and file carving in unallocated space."

---

### ALL THREE — Closing (7:15–7:30)

> **Harshit**: "In conclusion, GhostTrace demonstrates that a determined insider threat leaves multiple corroborating traces across diverse artifact categories — event logs, browser history, file system metadata, and Recycle Bin records — even when the attacker attempts cleanup."
> 
> **Kaushiki**: "Digital forensics is fundamentally about correlation: no single artifact proves anything in isolation, but together they reconstruct the truth."
> 
> **Jiya**: "Thank you for watching. All scripts, the investigation report, timeline, and findings register are available in our GitHub repository. We are happy to answer questions."

---

## Pre-Recording Checklist

- [ ] All three members' audio is clear and balanced
- [ ] Screen resolution is at least 1080p
- [ ] Browser and Autopsy windows are maximized and readable
- [ ] Autopsy case has been pre-loaded with evidence (ingestion complete)
- [ ] Timeline view has been pre-filtered to September 13, 2026
- [ ] Script is practiced — target 7:00–7:30 total
- [ ] No credentials, personal emails, or private data visible on screen
- [ ] Backup recording of key Autopsy screenshots available
- [ ] Video transitions between speakers are smooth
- [ ] Final video reviewed before submission

---

## Recording Tools Suggestion

- **Screen Recording**: OBS Studio (free), Loom, or Windows built-in Xbox Game Bar (Win+G)
- **Video Editing**: DaVinci Resolve (free), CapCut, or iMovie
- **Audio**: Use a headset microphone for clarity; record in a quiet room

---

*This script is a guideline. Adapt language naturally during recording — do not read mechanically.*
