# Deliverable 1 — Test Results

## 1. Access Control Tests

| User | Authorized Department | Unauthorized Access |
|---|---|---|
| Alice | Finance | Denied |
| Bob | HR | Denied |
| Carol | Management | Denied |
| Dave | Engineering | Denied |
| Eve | Marketing | Denied |

Each user successfully accessed their assigned department and was denied access to other department directories.

## 2. File Monitoring Tests

The monitoring system was tested with files created inside the department directories.

| Test | Result |
|---|---|
| File creation | Detected |
| File modification | Detected |
| File deletion | Detected |
| SHA-256 calculation | Verified |
| Permission change | Detected |
| Persistent event logging | Verified |

## 3. Example Test Sequence

A test file was created in the Finance directory, modified, had its permissions changed, and was then deleted.

The monitor recorded the following event types:

    CREATED
    MODIFIED
    PERMISSION_CHANGED
    DELETED

SHA-256 values changed when the file contents were modified, confirming that the hashing functionality was working.

## 4. Result

All required functionality for Deliverable 1 was successfully implemented and tested.

One known limitation is that the current monitor records filesystem events but does not identify the Linux user responsible for each event. User attribution will be added in a later project phase.
