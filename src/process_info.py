import psutil


def get_process_info(pid):
    """Return available information about a process."""
    try:
        process = psutil.Process(pid)

        with process.oneshot():
            return {
                "pid": process.pid,
                "name": process.name(),
                "exe": process.exe(),
                "username": process.username(),
                "cmdline": process.cmdline(),
                "create_time": process.create_time(),
            }

    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return {
            "pid": pid,
            "error": "Process unavailable or access denied",
        }
