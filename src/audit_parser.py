import re
from pathlib import Path


AUDIT_LOG = Path("/var/log/audit/audit.log")


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
                syscall_match = re.search(r"syscall=(\d+)", payload)
                pid_match = re.search(r"\bpid=(\d+)", payload)
                ppid_match = re.search(r"\bppid=(\d+)", payload)
                auid_match = re.search(r"\bauid=(\d+)", payload)
                uid_match = re.search(r"\buid=(\d+)", payload)
                euid_match = re.search(r"\beuid=(\d+)", payload)
                comm_match = re.search(r'\bcomm="([^"]*)"', payload)
                exe_match = re.search(r'\bexe="([^"]*)"', payload)
                success_match = re.search(r"\bsuccess=(yes|no)", payload)
                exit_match = re.search(r"\bexit=(-?\d+)", payload)
                key_match = re.search(r'\bkey="([^"]*)"', payload)

                events[key] = {
                    "timestamp": float(timestamp),
                    "event_id": event_id,
                    "pid": int(pid_match.group(1)) if pid_match else None,
                    "ppid": int(ppid_match.group(1)) if ppid_match else None,
                    "auid": int(auid_match.group(1)) if auid_match else None,
                    "uid": int(uid_match.group(1)) if uid_match else None,
                    "euid": int(euid_match.group(1)) if euid_match else None,
                    "syscall": int(syscall_match.group(1)) if syscall_match else None,
                    "comm": comm_match.group(1) if comm_match else None,
                    "exe": exe_match.group(1) if exe_match else None,
                    "success": success_match.group(1) if success_match else None,
                    "exit_code": int(exit_match.group(1)) if exit_match else None,
                    "key": key_match.group(1) if key_match else None,
                    "paths": [],
                }

            elif record_type == "PATH":
                path_match = re.search(r'\bname="([^"]*)"', payload)
                if path_match:
                    if key not in events:
                        events[key] = {
                            "timestamp": float(timestamp),
                            "event_id": event_id,
                            "paths": [],
                        }

                    events[key]["paths"].append(path_match.group(1))

    return list(events.values())


if __name__ == "__main__":
    for event in parse_audit_log():
        if event.get("key") in {"org_file_changes", "org_file_reads"}:
            print(event)
