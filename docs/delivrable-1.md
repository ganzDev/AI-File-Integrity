# Deliverable 1 — Initial System & File Integrity Monitoring

## 1. Project Overview

The **AI-Based File Integrity and Insider Threat Detection** project is a security monitoring system designed around a simulated organization. The organization contains multiple departments with separate employees, directories, and access permissions.

Deliverable 1 establishes the Linux environment and implements the initial file integrity monitoring system using Python, `watchdog`, and SHA-256 hashing.

## 2. System Environment

The project runs inside an Ubuntu Linux virtual machine.

Five departments and corresponding Linux groups were created:

| Department | User |
|------------|------|
| Finance | Alice |
| HR | Bob |
| Management | Carol |
| Engineering | Dave |
| Marketing | Eve |

Department directories are located under:

    /opt/organization/
	--> finance/
	--> hr/
	--> managament/
	--> engineering/
	--> marketing/

Linux group ownership and `2770` (drwxrws---) permissions restrict each employee to their assigned department. Access-control tests confirmed that employees can access their own department while unauthorized access is denied.

## 3. File Integrity Monitoring

The monitoring program is implemented in Python using the `watchdog` library. It recursively monitors `/opt/organization/` for filesystem activity.

The monitor detects:

- File creation
- File modification
- File deletion
- File permission changes

SHA-256 hashes are calculated for created and modified files. This allows changes to file contents to be identified through changes in their hash values.

Permission changes are recorded with both the previous and new permission values.

## 4. Event Logging

Detected events are displayed in the terminal and stored in:

    logs/file_events.log

Events contain a timestamp, event type, file path, and relevant information such as hashes or permissions.

Example:

    2026-09-24 20:01:01 | MODIFIED | /opt/organization/finance/log_test.txt | SHA256=...
    2026-09-24 20:01:11 | PERMISSION_CHANGED | /opt/organization/finance/log_test.txt | OLD=0o664 | NEW=0o600
    2026-09-24 20:01:18 | DELETED | /opt/organization/finance/log_test.txt

## 5. Testing

The system was tested using all five simulated employees.

Test operations included creating, modifying, changing permissions, and deleting files within authorized department directories. The monitoring system successfully recorded the corresponding events and generated SHA-256 hashes.

Linux access-control tests also confirmed that employees were denied access to departments outside their assigned group.

The current monitor records filesystem changes but does not identify the specific user responsible for an event. User attribution and additional auditing will be implemented in a later project phase.

## 6. Deliverable 1 Result

Deliverable 1 establishes the project's initial security environment and demonstrates functional file integrity monitoring. The system can enforce department-level access controls, detect common filesystem changes, calculate file hashes, and persist security events for later analysis.

Future project phases will build on this foundation with additional auditing, forensic analysis, and AI-based threat detection.
