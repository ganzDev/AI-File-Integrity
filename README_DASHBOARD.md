# AI-File-Integrity · Interactive Dashboard

A local Flask UI for the existing AI-File-Integrity Ubuntu backend. **This package adds files; it does not replace or alter monitor.py, detector.py, audit_parser.py, correlator.py, event_store.py, ai_investigator.py, or evidence_validator.py.**

## Features

- Live overview (event/findings/AI counts, severity distribution, system status)
- Start, stop and restart the **monitor** and **continuous detector** using persistent systemd services
- View auditd state (auditd itself is not controlled through the website)
- Search, filter and inspect persisted findings, Watchdog history, matched kernel audit evidence, process attribution and rule reasons
- Change findings between `OPEN`, `INVESTIGATING` and `RESOLVED`
- Launch paid AI investigation from a chosen finding after confirmation; view output and saved validation
- Browse previous assessments and inspect structured evidence / incident coverage
- View historical 15-case research results (case IDs are documented historical snapshots)
- View raw event stream and recent service journal entries
- Auto-refresh overview every five seconds, findings table every ten seconds

## Requirements

- Ubuntu with systemd and sudo
- Existing `~/AI-File-Integrity` project with a working `.venv`, `src` and `logs/security_events.db`
- Python packages already used by the backend, plus Flask 3.x
- A working `.env` file at project root containing `OPENAI_API_KEY=...` for AI investigations
- Normal desktop user `admin` with sudo privileges; you can use another sudo user by running the installer from that account
- **Local VM / demonstration environment only. No reverse proxy, shared login, or public network exposure.**

## Installation

1. Copy the ZIP to the VM, for example through `/media/sf_vm_folder`. In the **existing project root**:

   ```bash
   cd ~/AI-File-Integrity
   unzip -o /media/sf_vm_folder/AI_File_Integrity_Dashboard.zip
   ```

   The package adds `dashboard/`, `deployment/`, `tests/` and a `README_DASHBOARD.md` file. It should not overwrite any existing `src` files.

2. Install Flask into the existing venv:

   ```bash
   .venv/bin/python -m pip install -r dashboard/requirements.txt
   ```

3. Stop the **manually launched** monitor and detector terminals by pressing `Ctrl+C` in each. **Leave auditd running.** If you already have systemd-managed services for them, stop the old units first. Running duplicate monitors would create duplicate Watchdog events.

4. Install narrowly scoped privileged control helper, systemd units and a sudoers entry:

   ```bash
   sudo bash deployment/install.sh
   ```

   The installer **does not start or enable services**. Inspect `deployment/afi-admin` and `deployment/install.sh` before running; they are privileged configuration code. The helper is installed root-owned at `/usr/local/sbin/afi-admin`. Unit files are installed under `/etc/systemd/system/`. The sudoers rule allows the installer-invoking user to call only this helper with arguments; the helper enforces an explicit command and argument allowlist.

5. Start the backend through systemd:

   ```bash
   sudo systemctl start ai-file-integrity-monitor ai-file-integrity-detector
   systemctl is-active ai-file-integrity-monitor ai-file-integrity-detector auditd
   ```

   Note that detector starts **without `--start-now`**, preserving its existing checkpoint. Do not erase `logs/security_events.db` or `logs/detector.lock`.

6. Run the dashboard **as the normal Ubuntu user**, not root:

   ```bash
   cd ~/AI-File-Integrity
   .venv/bin/python dashboard/app.py
   ```

   Open **http://127.0.0.1:8765** inside the Ubuntu VM. When finished, `Ctrl+C` stops the web server **without stopping the monitor/detector systemd services**.

## Privileges and deployment security

- Flask runs as an unprivileged desktop user and binds to `127.0.0.1` only. No Flask debug mode or shell execution.
- The web app reads the existing database in read-only mode. Privileged actions are mediated by a **root-owned, allowlisted** helper installed by the administrator.
- The helper changes only finding `status`, starts/stops/restarts two named services, retrieves bounded kernel audit records, reads journal entries, or launches the existing investigator for a positive integer finding ID.
- AI credentials are loaded by the privileged helper from the existing project `.env` using a non-executing parser, never sent to the browser.
- POST actions require a per-process CSRF header and JSON payload, and the UI asks for confirmation of paid AI calls and service actions.
- **Do not expose this UI to other users, port-forward it, or run it on the public network.** Root-run backend code lives in the existing project directory, which may be editable by the local admin account. This demo setup is not appropriate for an untrusted multiuser environment.
- The Flask development server is intended for local classroom demonstrations only. For real deployment, additional authentication, hardened service identities, least-privilege audit access, and a production server are required.
- `auditd` remains controlled by the OS and is intentionally not stoppable from the website.
- AI jobs run one at a time in a background dashboard thread. Their output is visible during the current dashboard process lifetime; persisted assessments remain in `security_events.db`. Restarting the Flask server during a running AI job can interrupt its status tracking. Do not restart the UI during an AI run.

## Status and troubleshooting

```bash
sudo systemctl status ai-file-integrity-monitor ai-file-integrity-detector --no-pager
sudo journalctl -u ai-file-integrity-detector -n 40 --no-pager
sudo journalctl -u ai-file-integrity-monitor -n 40 --no-pager
sudo -n /usr/local/sbin/afi-admin logs detector
```

- `Permission denied` when loading SQLite: the dashboard user needs **read permission** on `logs/security_events.db`, and execute permission on its parent folders. Do not recursively chown the project or database; prefer a narrow ACL or a read-only DB copy if needed.
- AI button fails: confirm that `.env` exists in project root and contains `OPENAI_API_KEY`. No `.env` is included in the ZIP.
- Service start fails: check `journalctl`. Existing manually started detector will conflict with the detector lock, and duplicated monitor processes would observe the same changes.
- Flask unavailable: install with the `.venv/bin/python -m pip install` command above.
- `127.0.0.1` refers to the **Ubuntu VM**, not the Windows host. Open the browser in the VM unless you intentionally configure a secure local connection.
- Changing a finding's status changes only workflow metadata. It does **not** modify the original audit, Watchdog or AI assessment evidence.

## Evaluation view

The historical 15-case cohort is mapped to the finding IDs used in the user's evaluation (`2262`, `2323`, `2347`, `2355`, `2357`, `2372`, `2379`, `2400`, `2404`, `2408`, `2492`, `2428`, `2434`, `2445`, `2487`). These are identifiers from the project's *existing* database. If you use a different DB, historical evaluation cases may show zero runs. This view is not an independent ground-truth accuracy calculation; it reports saved classification distributions.

## File layout

```text
dashboard/
    app.py
    requirements.txt
    templates/index.html
    static/style.css
    static/app.js
deployment/
    afi-admin
    install.sh
tests/
    test_dashboard_static.py
README_DASHBOARD.md
```

## Baseline preservation

Keep all existing detection and AI files unchanged. The installer adds services, does not alter SQLite schema, and does not delete historical findings or assessments. If you later compare an improved AI prompt or context-ablation model, use a new evaluation cohort and record version/configuration to avoid mixing baselines.
