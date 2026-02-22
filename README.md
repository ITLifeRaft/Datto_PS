System Health Observer is a read‑only Datto‑ready PowerShell script that scans Windows Event Logs, filters noise, highlights known and unknown issues, and reports a clear health status via Datto UDF 23—without making any system changes.

Script Summary
System Health Observer (Phase‑1) is a read‑only Windows Event Log health monitoring script designed for Datto RMM environments.
It scans recent Windows Event Logs, classifies events into meaningful categories (Noise, Known Safe, Known Unsafe, and Unknown), and produces both machine‑readable and human‑readable results. The script does not perform any remediation; it is strictly observational.
The script:

Reviews selected Windows Event Logs within a configurable time window
Suppresses known noise and benign events
Identifies known safe and known unsafe issue patterns
Flags unknown events for human review
Writes local diagnostic artifacts (JSON and TXT)
Updates Datto UDF 23 with either a health status or summary
Returns structured JSON and exit codes for Datto component monitoring

The goal is to reduce alert noise, surface actionable signals, and provide a consistent, auditable view of Windows log health without changing system state.


## What the Script Does

- Scans Windows Event Logs within a configurable lookback window
- Classifies events into:
  - **Noise** (expected / suppressed)
  - **Known Issue – Safe**
  - **Known Issue – Unsafe**
  - **Unknown**
- Applies rule‑based classification logic (provider, event ID, conditions)
- Writes local artifacts for audit and review
- Updates a Datto RMM **UDF**
- Emits JSON output and exit codes for Datto component status

By default, this script **writes to Datto UDF 23**:
