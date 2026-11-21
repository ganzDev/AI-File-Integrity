
"""Controlled attack simulations for Deliverable 3."""

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
TEST_ROOT = FINANCE / "d3_tests"
RESULTS = Path("logs/d3_simulations.jsonl")


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
        "/usr/bin/python3",
        "-c",
        code,
        *map(str, arguments),
    ])


def check_result(result, expect_denied=False):
    """Check whether the simulated operation behaved as expected."""
    if expect_denied:
        return (
            result.returncode != 0
            and "Permission denied" in result.stderr
        )

    return result.returncode == 0


def prepare_directory():
    """Create a unique, disposable Finance test directory."""
    group_id = grp.getgrnam("finance").gr_gid

    if TEST_ROOT.is_symlink():
        raise RuntimeError("Test root must not be a symbolic link")

    TEST_ROOT.mkdir(exist_ok=True)
    os.chown(TEST_ROOT, 0, group_id)
    TEST_ROOT.chmod(0o750)

    run_dir = Path(
        tempfile.mkdtemp(prefix="run_", dir=TEST_ROOT)
    )

    os.chown(run_dir, pwd.getpwnam(USER).pw_uid, group_id)
    run_dir.chmod(0o700)

    return run_dir


def unauthorized_access(run_dir):
    result = run_as_alice([
        "ls",
        str(MARKETING),
    ])

    return check_result(result, expect_denied=True), result


def unauthorized_modification(run_dir):
    """Attempt to modify a root-owned HR test file."""
    test_file = HR / f"d3_denied_{run_dir.name}.txt"

    # Exclusive creation prevents overwriting existing files.
    with test_file.open("x") as file:
        file.write("Controlled HR test data\n")

    test_file.chmod(0o600)

    code = """
import sys
with open(sys.argv[1], "a") as file:
    file.write("Unauthorized change\\n")
"""

    result = run_python(code, test_file)
    return check_result(result, expect_denied=True), result


def deletion(run_dir):
    """Create and rapidly delete five disposable files."""
    code = """
import sys
import time
from pathlib import Path

folder = Path(sys.argv[1])
files = [folder / f"delete_{i}.txt" for i in range(1, 6)]

for file in files:
    file.write_text("Disposable deletion test\\n")

time.sleep(1)

for file in files:
    file.unlink()

print("Deleted 5 test files")
"""

    result = run_python(code, run_dir)
    return check_result(result), result


def permission_change(run_dir):
    """Change the permissions of a disposable file."""
    code = """
import sys
import time
from pathlib import Path

file = Path(sys.argv[1]) / "permission_test.txt"

# Create the file with its original permissions.
file.write_text("Disposable permission test\\n")
file.chmod(0o644)

# Allow watchdog to register the original permissions.
time.sleep(3)

# Perform the suspicious permission change.
file.chmod(0o666)

# Allow the monitor's permission polling to detect the change.
time.sleep(3)

print("Changed test file permissions from 644 to 666")
"""

    result = run_python(code, run_dir)
    return check_result(result), result

def compromised_account(run_dir):
    """Simulate normal file operations followed by forbidden access."""
    code = """
import sys
from pathlib import Path

folder = Path(sys.argv[1])

for i in range(1, 4):
    (folder / f"account_{i}.txt").write_text(
        f"Simulated account activity {i}\\n"
    )

print("Created 3 Finance files")
"""

    creation = run_python(code, run_dir)

    if creation.returncode != 0:
        return False, creation

    denied = run_as_alice(["ls", str(MARKETING)])

    return check_result(
        denied, expect_denied=True
    ), denied


def rapid_modification(run_dir):
    """Modify five existing files in quick succession."""
    code = """
import sys
import time
from pathlib import Path

folder = Path(sys.argv[1])
files = [folder / f"rapid_{i}.txt" for i in range(1, 6)]

for file in files:
    file.write_text("Original content\\n")

time.sleep(1)

for file in files:
    with file.open("a") as handle:
        handle.write("Modified content\\n")

print("Modified 5 files")
"""

    result = run_python(code, run_dir)
    return check_result(result), result


def process_interaction(run_dir):
    """Use one Python process to modify multiple files."""
    code = """
import os
import sys
from pathlib import Path

folder = Path(sys.argv[1])

for i in range(1, 6):
    file = folder / f"process_{i}.txt"
    file.write_text(f"Python process test {i}\\n")

print(f"Python PID: {os.getpid()}")
print("Created 5 files using one process")
"""

    result = run_python(code, run_dir)
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
    """Run one scenario and record its result."""
    run_dir = prepare_directory()

    print(f"\nScenario: {name}")
    print(f"Test directory: {run_dir}")

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

    options.add_argument(
        "--list",
        action="store_true",
        help="List available scenarios",
    )

    options.add_argument(
        "--scenario",
        choices=SCENARIOS.keys(),
        help="Run a selected scenario",
    )

    options.add_argument(
        "--all",
        action="store_true",
        help="Run every scenario",
    )

    args = parser.parse_args()

    if args.list:
        print("Available scenarios:")
        for name in SCENARIOS:
            print(f"  {name}")
        return

    if os.geteuid() != 0:
        parser.error("Run this simulator with sudo")

    names = (
        list(SCENARIOS)
        if args.all
        else [args.scenario]
    )

    results = [execute_scenario(name) for name in names]

    print(
        f"\nSimulation summary: "
        f"{sum(results)}/{len(results)} passed"
    )


if __name__ == "__main__":
    main()
