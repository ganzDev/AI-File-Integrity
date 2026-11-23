# Deliverable 3 — Attack Simulation & Agentic AI

**Project:** AI-File-Integrity — AI-Based File Integrity Monitoring and Insider Threat Detection  
**Course:** CSCI 411 — Computer Security and Forensics  
**Deliverable:** 3 — Attack Simulation & Agentic AI  
**Date:** November 2026

## 1. Overview

Deliverable 2 established the system's forensic foundation: filesystem monitoring with Watchdog, Linux `auditd` records, SQLite storage, event correlation, and basic rule-based detection. Those components could report *what happened*, *which file was involved*, and—when matching audit evidence was available—*who performed the operation and which process was responsible*.

Deliverable 3 builds on that foundation in two ways. First, it introduces controlled attack simulations to generate realistic security events in the monitored environment. Second, it adds an LLM-based investigator that can retrieve supporting evidence, examine related activity, and produce a structured security assessment. The investigator's factual audit claims are then checked independently against the recorded evidence.

The intended workflow is:

```text
Controlled filesystem activity
            |
            v
Watchdog events + Linux auditd records
            |
            v
Correlation + rule-based detection
            |
            v
SQLite security finding
            |
            v
LLM investigator <--> read-only evidence tools
            |
            v
Structured threat assessment
            |
            v
Independent evidence validation + saved results
```

**Scope:** This deliverable investigates suspicious filesystem behavior; the AI recommends actions but does not autonomously block users, reverse filesystem changes, or establish whether an operation was authorized without independent authorization evidence.

## 2. Controlled Attack Simulations

The project uses a dedicated simulator, [`src/attack_simulator.py`](../src/attack_simulator.py), to exercise the monitoring pipeline inside the Ubuntu test environment. Its scenarios operate on the monitored organization directory, `/opt/organization/`, and generate activity that can be observed by Watchdog and `auditd`.

The seven primary scenarios correspond to the Deliverable 3 requirements:

| Scenario | Simulated behavior | What the system should capture |
| --- | --- | --- |
| Unauthorized department access | A user attempts to access a restricted directory | User identity, process, attempted read, and permission-denied audit evidence |
| Unauthorized file modification | A user attempts to write to a protected file | Target path, write intent, process, and success/failure result |
| Suspicious deletion | Several files are removed within a short period | Individual deletion operations and their shared user/process context |
| Permission modification | File or directory access permissions are changed | Permission-change evidence, affected path, and resulting risk assessment |
| Compromised-account behavior | A simulated account accesses files outside its expected activity | Identity and unusual file-access patterns requiring review |
| Rapid modification | Multiple files are modified in quick succession | Changes across files, timing, and related activity |
| Suspicious process interaction | A process interacts with monitored files in an unusual way | Process metadata, filesystem behavior, and audit evidence |

These are **controlled demonstrations**, not real-world intrusions. A simulated compromise represents suspicious activity performed under a test account; it is not proof that an account was actually compromised.

The tests also include benign/control cases and variations in deletion activity. These are useful for identifying when a detector or LLM confuses unusual behavior with confirmed malicious intent.

## 3. Improvements to Monitoring, Parsing, and Detection

The existing forensic pipeline was extended to support the simulations and the AI investigator.

### Audit evidence and path handling

[`src/audit_parser.py`](../src/audit_parser.py) processes Linux audit records, including system calls, process information, effective user IDs, success/failure results, and referenced filesystem paths. A significant correction was made for operations such as `unlinkat`, where filenames may be relative to the process's working directory. By using the audit `CWD` record to construct the full path, deletion events can be associated with the correct monitored files instead of being missed during correlation.

### Event correlation

[`src/correlator.py`](../src/correlator.py) matches Watchdog notifications with compatible audit operations using file paths, timestamps, and operation types. It also includes incident grouping for related audit records. Where appropriate, related operations are grouped based on **effective user ID, process ID, parent directory, operation type, and a bounded time window**. This is particularly useful for bursts of file deletion or modification.

### Continuous rule-based detection

[`src/detector.py`](../src/detector.py) processes new evidence continuously, combines related observations into findings, and assigns a preliminary risk score and severity. The detector also handles audit-only evidence, such as denied access attempts and some permission changes that Watchdog may not fully observe. Its processing position is persisted so normal restarts do not require reprocessing the entire event history.

The rule-based score is a **preliminary alert**, not a final determination of malicious activity. It helps prioritize investigations, but it does not independently establish intent or authorization.

## 4. Agentic AI Investigator

The main AI component is [`src/ai_investigator.py`](../src/ai_investigator.py), which uses the OpenAI API (the evaluated baseline used `gpt-4.1-mini`). Unlike a simple prompt that asks the model to interpret one alert, this investigator can request additional information through a defined set of evidence-retrieval tools.

An investigation starts with a saved finding ID. The agent receives the finding's details, selects relevant tools, reviews their responses, and returns a structured assessment. The process is bounded by configured limits on tool calls and investigation rounds to prevent unlimited searching or API usage.

### Available investigation tools

The tools are implemented in [`src/investigation_tools.py`](../src/investigation_tools.py).

| Tool | Purpose |
| --- | --- |
| `get_finding` | Retrieve the original saved finding from SQLite |
| `get_file_history` | Examine recent Watchdog events for a particular monitored path |
| `get_audit_evidence` | Retrieve the kernel audit record associated with an event ID and time |
| `get_related_audit_activity` | Search nearby audit activity involving the same user |
| `get_live_process` | Inspect a process that is still running, when available |
| `get_incident_context` | Group related audit records to understand a multi-file incident |

The SQLite tools use **read-only database access** and bounded query results. File-history lookups are restricted to the monitored directory. Live process inspection is treated carefully because a historical process may have exited and the operating system may reuse its PID. Historical audit evidence is more reliable for establishing what occurred in the past.

### Structured output

The investigator produces information intended to be understandable and reviewable, including:

- **Classification:** whether the event appears suspicious, benign, or inconclusive.
- **Severity and confidence:** the model's assessment of risk and its stated certainty.
- **Authorization status:** whether approval or legitimacy can actually be established from the evidence.
- **Observed facts and inferences:** what the records show, distinguished from possible explanations.
- **Audit claims:** structured references to specific audit events and their properties.
- **Analysis, recommendations, and limitations:** why the activity deserves attention, what should be investigated next, and what remains unknown.

Keeping these fields separate is important. A successful deletion, for example, can be proven by an audit record; whether the deletion was *approved* generally cannot be proven by that record alone.

## 5. Independent AI Evidence Validation

An LLM can produce a plausible explanation while misreading, omitting, or inventing supporting details. To make these limitations measurable, Deliverable 3 adds [`src/evidence_validator.py`](../src/evidence_validator.py).

After an assessment is generated, the validator compares the model's structured audit claims with the original audit records. It checks properties such as:

- Audit event identity and the associated record;
- System call and access mode;
- Operation success or failure and exit code;
- Process name and referenced file path.

For multi-event incidents, it also checks **incident coverage**: whether the model's cited evidence accounts for the relevant operations identified in the grouped incident. This prevents a report about a five-file deletion from appearing complete if it cites only one of the five operations.

The validation results are stored alongside the AI assessment in SQLite. **Validation of audit fields is not validation of the final classification.** It confirms that certain factual claims match recorded evidence; it does not verify authorization, intent, or every sentence of the generated explanation.

## 6. Persistent Investigation Records

[`src/event_store.py`](../src/event_store.py) continues to maintain filesystem events, findings, and detector state. The AI investigation component adds persistent assessment and validation records in the same SQLite database, `logs/security_events.db`.

This allows investigations to be revisited without rerunning the model. Saved records include the model's assessment, tool-call count, and independent validation outcome. The local SQLite database and operational logs are deliberately excluded from Git because they are runtime data; selected evaluation results are exported separately for reproducibility.

## 7. Testing and Initial Evaluation

Beyond checking individual scenarios, the project conducted repeated AI assessments to study consistency and evidence quality. The preserved initial evaluation consists of **76 AI assessments across 15 experimental cases**, covering the primary suspicious scenarios, benign controls, and additional deletion comparisons.

The evaluation records are included in [`evaluation_results/`](../evaluation_results/):

- [`ai_evaluation_summary.csv`](../evaluation_results/ai_evaluation_summary.csv) — summary by scenario;
- [`ai_evaluation_details.csv`](../evaluation_results/ai_evaluation_details.csv) — individual runs and detailed outputs;
- [`complete_ai_evaluation.csv`](../evaluation_results/complete_ai_evaluation.csv) — consolidated saved assessment data.

The tests examined **classification consistency, evidence-field verification, tool usage, and coverage of related audit events**. They also exposed important limits:

- The LLM sometimes treated normal or explicitly simulated activity as suspicious despite missing proof of malicious intent.
- Directory and filename wording could influence the interpretation of otherwise similar behavior.
- HIGH confidence did not necessarily imply that authorization was verified or that every relevant event was cited.
- Some multi-file incidents were described using incomplete event evidence.

These discrepancies are retained as experimental findings rather than hidden by changing the original assessments. They establish a baseline for the contextual comparison and AI refinements planned for Deliverable 4. The current evaluation does **not** by itself establish real-world detection accuracy or a complete rule-based-versus-AI false-positive/false-negative comparison.

## 8. Dashboard and Operational Integration

A local Flask dashboard was also added as an integration and demonstration feature. It is not required to understand the core AI workflow, but it makes the system easier to operate and inspect.

The [`dashboard/`](../dashboard/) interface can display recent filesystem activity, security findings, severity distributions, saved AI assessments, validation results, and evaluation summaries. It can also launch an investigation for an existing finding and manage the monitor and detector services.

The [`deployment/`](../deployment/) scripts configure the monitor and continuous detector as `systemd` services, so their execution no longer depends on keeping separate terminals open. Their output remains available through `journalctl`.

The dashboard is intentionally a **localhost-only demonstration application**. Privileged operations are handled through a restricted helper; it is not intended to be exposed as a production security console. Installation and operating instructions are provided in [`README_DASHBOARD.md`](../README_DASHBOARD.md).

## 9. Demonstrating the End-to-End Workflow

A representative demonstration is:

1. Start the Watchdog monitor, rule-based detector, and `auditd`.
2. Run a controlled scenario, such as rapid file deletion, under the test environment.
3. Confirm the resulting filesystem notifications and corresponding Linux audit records.
4. Locate the persisted security finding and its initial risk/severity score.
5. Start an AI investigation using the finding ID.
6. Inspect the agent's tool calls and its classification, supporting evidence, recommendations, and limitations.
7. Review the independent audit-field validation and any multi-event coverage results.
8. Open the dashboard to inspect the saved finding and investigation.

For example, to run the deletion scenario from the project root, with the monitor and detector already running:

```bash
sudo PYTHONPATH=src .venv/bin/python src/attack_simulator.py --scenario deletion
```

An existing finding can be investigated through the dashboard or directly using `src/ai_investigator.py` with the appropriate API credentials configured. AI investigations can incur API charges; credentials should remain in the local `.env` file, never in Git.

## 10. Limitations and Next Steps

Deliverable 3 demonstrates an operational **attack → evidence → investigation → assessment** pipeline, but it is still an academic prototype:

- Audit correlation and incident grouping depend on the available records, matching rules, and time windows; they may miss some related behavior.
- The rule-based detector evaluates findings but does not prove an event is malicious.
- The LLM may overinterpret paths, user behavior, or preliminary severity, and may express more confidence than the evidence supports.
- The validator checks structured evidence properties and incident coverage, not organizational authorization or the truth of the model's entire narrative.
- The dashboard is designed for a trusted local VM, not an untrusted multiuser or public deployment.

**Deliverable 4** will focus on refining the AI investigation approach, comparing the preserved baseline against revised configurations, evaluating legitimate versus malicious scenarios, quantifying detection errors, and preparing the final integrated demonstration and report.

## 11. Relevant Files

| Path | Responsibility |
| --- | --- |
| `src/attack_simulator.py` | Controlled filesystem attack scenarios |
| `src/monitor.py` | Watchdog monitoring and event logging |
| `src/audit_parser.py` | Parsing and normalization of Linux audit records |
| `src/correlator.py` | Audit-to-filesystem matching and incident grouping |
| `src/detector.py` | Continuous rule-based detection and risk scoring |
| `src/event_store.py` | SQLite persistence for events and findings |
| `src/investigation_tools.py` | Read-only evidence access for the AI agent |
| `src/ai_investigator.py` | LLM investigation workflow and assessment generation |
| `src/evidence_validator.py` | Independent factual validation and coverage checks |
| `src/evaluation_runner.py` | Repeated evaluation runs and result export |
| `evaluation_results/` | Preserved baseline evaluation data |
| `dashboard/`, `deployment/` | Local interface and systemd service integration |

---

**Summary:** Deliverable 3 transforms the Deliverable 2 event-logging and detection system into a testable, AI-assisted forensic investigation workflow. The system can generate controlled incidents, record and correlate evidence, investigate findings with an LLM using restricted tools, validate factual claims independently, and retain the results for evaluation.
