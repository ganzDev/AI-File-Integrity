# Deliverable 2 — Security Event Logging & Forensics

## Overview

Deliverable 2 extends the file-integrity monitor with forensic logging and basic rule-based suspicious-activity detection. The system combines filesystem events with Linux audit records to provide context about who performed an operation, which process was involved, and when it occurred.

## Implemented Components

- **auditd integration:** Records file operations under `/opt/organization/`, including changes and access attempts.
- **SQLite event storage:** Stores structured filesystem events and persistent security findings.
- **Process information:** Uses process metadata to enrich correlated events.
- **Event correlation:** Matches filesystem events with audit records using file paths and timestamps.
- **Rule-based detection:** Flags events such as file creation, modification, deletion, permission changes, and denied access.
- **Risk and severity scoring:** Assigns scores and severity levels to detected findings.
- **Persistent findings:** Retains findings across detector runs and VM restarts.

## Verification

The pipeline was tested with a file created by the simulated user `alice`:

- File: `/opt/organization/finance/verification_test.txt`
- Filesystem events: `CREATED` and `MODIFIED`
- Audit event: `404`
- Process: `bash` (PID `4423`)
- Correlated SQLite event IDs: `13` and `14`
- Finding ID: `44`
- Risk score: `10` — **MEDIUM**
- Status: `OPEN`

The finding remained in SQLite after rerunning the detector and restarting the VM. After reboot, `auditd` was active and both audit rules were loaded. The test confirmed the end-to-end flow from filesystem monitoring through audit correlation, scoring, and persistent storage.

## Current Scope

This deliverable covers security event logging, forensic context, correlation, and initial rule-based detection. Controlled attack-scenario evaluation and LLM-based agentic investigation are planned for Deliverable 3.
