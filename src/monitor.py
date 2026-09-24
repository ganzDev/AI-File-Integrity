import time
import hashlib
import os
import stat
from datetime import datetime

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler


WATCH_DIRECTORY = "/opt/organization"
LOG_FILE = "logs/file_events.log"


def log_event(event_type, file_path, details=""):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    log_entry = f"{timestamp} | {event_type} | {file_path}"

    if details:
        log_entry += f" | {details}"

    print(log_entry)

    with open(LOG_FILE, "a") as log:
        log.write(log_entry + "\n")


def calculate_sha256(file_path):
    sha256 = hashlib.sha256()

    try:
        with open(file_path, "rb") as file:
            for chunk in iter(lambda: file.read(4096), b""):
                sha256.update(chunk)

        return sha256.hexdigest()

    except (FileNotFoundError, PermissionError):
        return None


def get_permissions(file_path):
    try:
        file_stat = os.stat(file_path)
        return stat.S_IMODE(file_stat.st_mode)

    except (FileNotFoundError, PermissionError):
        return None


class FileMonitorHandler(FileSystemEventHandler):

    def __init__(self):
        super().__init__()
        self.file_permissions = {}

    def on_created(self, event):
        if not event.is_directory:
            file_hash = calculate_sha256(event.src_path)
            permissions = get_permissions(event.src_path)

            self.file_permissions[event.src_path] = permissions

            log_event(
                "CREATED",
                event.src_path,
                f"SHA256={file_hash} | PERMISSIONS={oct(permissions)}"
            )

    def on_modified(self, event):
        if not event.is_directory:
            file_hash = calculate_sha256(event.src_path)

            log_event(
                "MODIFIED",
                event.src_path,
                f"SHA256={file_hash}"
            )

    def on_deleted(self, event):
        if not event.is_directory:
            self.file_permissions.pop(event.src_path, None)

            log_event(
                "DELETED",
                event.src_path
            )

    def check_permissions(self):
        for file_path in list(self.file_permissions.keys()):
            current_permissions = get_permissions(file_path)
            previous_permissions = self.file_permissions[file_path]

            if current_permissions is None:
                continue

            if current_permissions != previous_permissions:

                log_event(
                    "PERMISSION_CHANGED",
                    file_path,
                    f"OLD={oct(previous_permissions)} | NEW={oct(current_permissions)}"
                )

                self.file_permissions[file_path] = current_permissions


def main():
    os.makedirs("logs", exist_ok=True)

    event_handler = FileMonitorHandler()

    observer = Observer()
    observer.schedule(
        event_handler,
        WATCH_DIRECTORY,
        recursive=True
    )

    observer.start()

    print(f"Monitoring: {WATCH_DIRECTORY}")
    print(f"Logging events to: {LOG_FILE}")
    print("Press Ctrl+C to stop.")

    try:
        while True:
            event_handler.check_permissions()
            time.sleep(1)

    except KeyboardInterrupt:
        observer.stop()

    observer.join()


if __name__ == "__main__":
    main()
