"""Controlled attack simulations for Deliverable 3.

The scenarios use realistic business document names in isolated, uniquely named
folders. Names describe simulated subject matter, not evidence of authorization,
intent, or actual business impact.
"""

import pwd
import argparse
import grp
import json
import os
import subprocess
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path


USER = "alice"
FINANCE = Path("/opt/organization/finance")
HR = Path("/opt/organization/hr")
MARKETING = Path("/opt/organization/marketing")
RESULTS = Path("logs/d3_simulations.jsonl")

# Scenario-specific folders avoid misleading generic path names like d3_tests.
# The unique leaf directory prevents one demonstration from overwriting another.
SCENARIO_FOLDERS = {
    "unauthorized_access": "department_budgets",
    "unauthorized_modification": "payroll_review",
    "deletion": "quarterly_reports",
    "permission_change": "budget_planning",
    "compromised_account": "financial_planning",
    "rapid_modification": "monthly_closing",
    "process_interaction": "accounting_records",
}

DELETION_DOCUMENTS = (
    "quarterly_revenue.txt",
    "expense_summary.txt",
    "budget_forecast.txt",
    "vendor_payments.txt",
    "cash_flow.txt",
)

RAPID_MODIFICATION_DOCUMENTS = (
    "monthly_revenue.txt",
    "expense_summary.txt",
    "account_balances.txt",
    "cash_flow.txt",
    "budget_forecast.txt",
)

PROCESS_DOCUMENTS = (
    "ledger_summary.txt",
    "payment_register.txt",
    "income_statement.txt",
    "tax_estimates.txt",
    "finance_overview.txt",
)


def run_as_alice(command):
    """Execute an operation under Alice's Linux account."""
    return subprocess.run(
        ["sudo", "-u", USER, "--", *command],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )


def run_python(code, *arguments):
    """Run isolated Python simulation code as Alice."""
    return run_as_alice([
        "/usr/bin/python3", "-c", code, *map(str, arguments)
    ])


def check_result(result, expect_denied=False):
    if expect_denied:
        return result.returncode != 0 and "Permission denied" in result.stderr
    return result.returncode == 0


def ensure_simulation_directory(folder, group_id, mode):
    """Use only a directory owned by this simulator; never repurpose real data."""
    marker = folder / ".afi_simulation_root"
    if folder.is_symlink():
        raise RuntimeError(f"Refusing symbolic-link scenario directory: {folder}")
    if folder.exists():
        if not folder.is_dir() or not marker.is_file() or marker.is_symlink():
            raise RuntimeError(
                f"Refusing to use existing non-simulation directory: {folder}"
            )
        if marker.read_text().strip() != "AI-File-Integrity simulated data only":
            raise RuntimeError(f"Invalid scenario marker: {folder}")
    else:
        folder.mkdir()
        marker.write_text("AI-File-Integrity simulated data only\n")
    os.chown(folder, 0, group_id)
    folder.chmod(mode)
    return folder


def prepare_directory(scenario):
    """Create a unique Alice-owned Finance directory for this scenario."""
    group_id = grp.getgrnam("finance").gr_gid
    root = ensure_simulation_directory(
        FINANCE / SCENARIO_FOLDERS[scenario], group_id, 0o750
    )
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d")
    work_dir = Path(tempfile.mkdtemp(prefix=f"{stamp}_", dir=root))
    os.chown(work_dir, pwd.getpwnam(USER).pw_uid, group_id)
    work_dir.chmod(0o700)
    return work_dir


def unauthorized_access(run_dir):
    result = run_as_alice(["ls", str(MARKETING)])
    return check_result(result, expect_denied=True), result


def unauthorized_modification(run_dir):
    """Attempt to modify an isolated root-owned HR payroll document."""
    # Users can traverse the directory, but not modify its root-owned file.
    folder = ensure_simulation_directory(HR / "payroll_records", 0, 0o755)
    test_file = folder / f"employee_compensation_{run_dir.name}.txt"
    with test_file.open("x") as file:
        file.write("Simulated HR payroll data\n")
    test_file.chmod(0o600)

    code = """
import sys
with open(sys.argv[1], "a") as file:
    file.write("Updated compensation entry\\n")
"""
    result = run_python(code, test_file)
    return check_result(result, expect_denied=True), result


def deletion(run_dir):
    """Create and rapidly delete five disposable financial documents."""
    code = """
import sys
import time
from pathlib import Path

folder = Path(sys.argv[1])
names = sys.argv[2:]
files = [folder / name for name in names]
for file in files:
    file.write_text("Simulated financial report data\\n")
time.sleep(1)
for file in files:
    file.unlink()
print(f"Deleted {len(files)} financial documents")
"""
    result = run_python(code, run_dir, *DELETION_DOCUMENTS)
    return check_result(result), result


def permission_change(run_dir):
    """Simulate an immediate expansion of permissions on a budget file."""
    code = """
import sys
from pathlib import Path

file = Path(sys.argv[1]) / "budget_summary.txt"
file.write_text("Simulated departmental budget\\n")
file.chmod(0o644)
file.chmod(0o666)
print("Changed budget_summary.txt permissions from 644 to 666")
"""
    result = run_python(code, run_dir)
    return check_result(result), result


def compromised_account(run_dir):
    """Simulate routine Finance file operations followed by forbidden access."""
    code = """
import sys
from pathlib import Path

folder = Path(sys.argv[1])
for name in sys.argv[2:]:
    (folder / name).write_text("Simulated finance activity\\n")
print("Created 3 finance planning documents")
"""
    creation = run_python(
        code, run_dir,
        "budget_summary.txt", "expense_report.txt", "department_forecast.txt"
    )
    if creation.returncode != 0:
        return False, creation
    denied = run_as_alice(["ls", str(MARKETING)])
    return check_result(denied, expect_denied=True), denied


def rapid_modification(run_dir):
    """Modify five existing financial documents in quick succession."""
    code = """
import sys
import time
from pathlib import Path

folder = Path(sys.argv[1])
files = [folder / name for name in sys.argv[2:]]
for file in files:
    file.write_text("Original financial record\\n")
time.sleep(1)
for file in files:
    with file.open("a") as handle:
        handle.write("Updated record\\n")
print(f"Modified {len(files)} financial documents")
"""
    result = run_python(code, run_dir, *RAPID_MODIFICATION_DOCUMENTS)
    return check_result(result), result


def process_interaction(run_dir):
    """Use one Python process to create several accounting documents."""
    code = """
import os
import sys
from pathlib import Path

folder = Path(sys.argv[1])
for name in sys.argv[2:]:
    (folder / name).write_text("Simulated accounting data\\n")
print(f"Python PID: {os.getpid()}")
print("Created 5 accounting documents using one process")
"""
    result = run_python(code, run_dir, *PROCESS_DOCUMENTS)
    return check_result(result), result


SCENARIOS = {
    "unauthorized_access": unauthorized_access,
    "unauthorized_modification": unauthorized_modification,
    "deletion": deletion,
    "permission_change": permission_change,
    "compromised_account": compromised_account,
    "rapid_modification": rapid_modification,
    "process_interaction": process_interaction,
}


def execute_scenario(name):
    """Run one scenario and record the result."""
    run_dir = prepare_directory(name)
    print(f"\nScenario: {name}")
    print(f"Scenario directory: {run_dir}")
    started = datetime.now(timezone.utc).isoformat()
    try:
        passed, result = SCENARIOS[name](run_dir)
        error = result.stderr.strip()
        output = result.stdout.strip()
    except (OSError, subprocess.TimeoutExpired) as exc:
        passed = False
        error = str(exc)
        output = ""
    record = {
        "scenario": name,
        "started_at": started,
        "test_directory": str(run_dir),
        "simulation_passed": passed,
        "stdout": output,
        "stderr": error,
    }
    RESULTS.parent.mkdir(parents=True, exist_ok=True)
    with RESULTS.open("a") as file:
        file.write(json.dumps(record) + "\n")
    print("Simulation:", "PASSED" if passed else "FAILED")
    if output:
        print(output)
    if error:
        print("Process output:", error)
    return passed


def main():
    parser = argparse.ArgumentParser(
        description="Deliverable 3 controlled attack simulator"
    )
    options = parser.add_mutually_exclusive_group(required=True)
    options.add_argument("--list", action="store_true", help="List available scenarios")
    options.add_argument("--scenario", choices=SCENARIOS.keys(), help="Run a selected scenario")
    options.add_argument("--all", action="store_true", help="Run every scenario")
    args = parser.parse_args()
    if args.list:
        print("Available scenarios:")
        for name in SCENARIOS:
            print(f"  {name}")
        return
    if os.geteuid() != 0:
        parser.error("Run this simulator with sudo")
    names = list(SCENARIOS) if args.all else [args.scenario]
    results = [execute_scenario(name) for name in names]
    print(f"\nSimulation summary: {sum(results)}/{len(results)} passed")


if __name__ == "__main__":
    main()
