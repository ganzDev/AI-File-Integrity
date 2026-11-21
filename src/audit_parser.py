
import os
import re
from pathlib import Path


AUDIT_LOG = Path("/var/log/audit/audit.log")

# x86-64 Linux system call numbers for permission changes.
PERMISSION_SYSCALLS = {
    90: "chmod",
    91: "fchmod",
    268: "fchmodat",
    452: "fchmodat2",
}


def get_access_mode(syscall, flags):
    """Identify read/write intent for Linux open/openat syscalls."""
    if flags is None:
        return None

    # x86_64 syscall numbers: open=2, openat=257
    if syscall not in (2, 257):
        return None

    access = flags & os.O_ACCMODE

    if access == os.O_WRONLY:
        return "WRITE"

    if access == os.O_RDWR:
        return "READ_WRITE"

    if flags & (os.O_CREAT | os.O_TRUNC | os.O_APPEND):
        return "WRITE"

    if access == os.O_RDONLY:
        return "READ"

    return None


def get_permission_mode(syscall, arguments):
    """
    Extract the requested permission mode from a chmod-family syscall.

    x86_64 syscall arguments:
        chmod(path, mode)                  -> a1
        fchmod(fd, mode)                   -> a1
        fchmodat(dirfd, path, mode)        -> a2
        fchmodat2(dirfd, path, mode, flags)-> a2

    Raw Linux audit syscall arguments are hexadecimal.
    """
    if syscall not in PERMISSION_SYSCALLS:
        return None

    argument_index = (
        1 if syscall in (90, 91)
        else 2
    )

    raw_value = arguments.get(f"a{argument_index}")

    if raw_value is None:
        return None

    try:
        mode = int(raw_value, 16)

        # Preserve Unix permission and special-mode bits.
        return oct(mode & 0o7777)

    except ValueError:
        return None


def get_operation(syscall):
    """Classify supported audit system calls."""
    if syscall in PERMISSION_SYSCALLS:
        return "PERMISSION_CHANGED"

    return None


def parse_audit_log(log_path=AUDIT_LOG):
    """Extract file-operation records from the Linux audit log."""
    events = {}

    with open(log_path, "r", encoding="utf-8", errors="replace") as log:
        for line in log:
            match = re.search(
                r"type=(\w+)\s+msg=audit\(([\d.]+):(\d+)\):\s*(.*)",
                line,
            )

            if not match:
                continue

            record_type, timestamp, event_id, payload = match.groups()
            key = (timestamp, event_id)

            if record_type == "SYSCALL":
                syscall_match = re.search(
                    r"\bsyscall=(\d+)", payload
                )

                syscall_number = (
                    int(syscall_match.group(1))
                    if syscall_match else None
                )

                # Extract syscall arguments from raw audit records.
                arguments = {}

                for argument_name in ("a0", "a1", "a2", "a3"):
                    argument_match = re.search(
                        rf"\b{argument_name}=(?:0x)?([0-9a-fA-F]+)",
                        payload,
                    )

                    arguments[argument_name] = (
                        argument_match.group(1)
                        if argument_match else None
                    )

                # Preserve existing open/openat flag extraction.
                flags_argument = (
                    arguments["a1"] if syscall_number == 2
                    else arguments["a2"] if syscall_number == 257
                    else None
                )

                open_flags = (
                    int(flags_argument, 16)
                    if flags_argument is not None
                    else None
                )

                # Extract permission changes from chmod-family calls.
                permission_mode = get_permission_mode(
                    syscall_number,
                    arguments,
                )

                operation = get_operation(syscall_number)

                pid_match = re.search(r"\bpid=(\d+)", payload)
                ppid_match = re.search(r"\bppid=(\d+)", payload)
                auid_match = re.search(r"\bauid=(\d+)", payload)
                uid_match = re.search(r"\buid=(\d+)", payload)
                euid_match = re.search(r"\beuid=(\d+)", payload)

                comm_match = re.search(
                    r'\bcomm="?([^"\s]+)"?', payload
                )
                exe_match = re.search(
                    r'\bexe="?([^"\s]+)"?', payload
                )

                success_match = re.search(
                    r"\bsuccess=(yes|no)", payload
                )
                exit_match = re.search(
                    r"\bexit=(-?\d+)", payload
                )
                key_match = re.search(
                    r'\bkey="?([^"\s]+)"?', payload
                )

                # Preserve PATH records encountered before SYSCALL.
                existing_event = events.get(key, {})
                existing_paths = existing_event.get("paths", [])

                events[key] = {
                    "timestamp": float(timestamp),
                    "event_id": event_id,
                    "pid": (
                        int(pid_match.group(1))
                        if pid_match else None
                    ),
                    "ppid": (
                        int(ppid_match.group(1))
                        if ppid_match else None
                    ),
                    "auid": (
                        int(auid_match.group(1))
                        if auid_match else None
                    ),
                    "uid": (
                        int(uid_match.group(1))
                        if uid_match else None
                    ),
                    "euid": (
                        int(euid_match.group(1))
                        if euid_match else None
                    ),
                    "syscall": syscall_number,
                    "open_flags": open_flags,
                    "access_mode": get_access_mode(
                        syscall_number,
                        open_flags,
                    ),
                    "operation": operation,
                    "permission_mode": permission_mode,
                    "comm": (
                        comm_match.group(1)
                        if comm_match else None
                    ),
                    "exe": (
                        exe_match.group(1)
                        if exe_match else None
                    ),
                    "success": (
                        success_match.group(1)
                        if success_match else None
                    ),
                    "exit_code": (
                        int(exit_match.group(1))
                        if exit_match else None
                    ),
                    "key": (
                        key_match.group(1)
                        if key_match else None
                    ),
                    "paths": existing_paths,
                }

            elif record_type == "PATH":
                path_match = re.search(
                    r'\bname="?([^"\s]+)"?', payload
                )

                if path_match:
                    if key not in events:
                        events[key] = {
                            "timestamp": float(timestamp),
                            "event_id": event_id,
                            "paths": [],
                        }

                    events[key]["paths"].append(
                        path_match.group(1)
                    )

    return list(events.values())


if __name__ == "__main__":
    for event in parse_audit_log():
        if event.get("key") in {
            "org_file_changes",
            "org_file_reads",
            "d3_denied_write",
        }:
            print(event)
