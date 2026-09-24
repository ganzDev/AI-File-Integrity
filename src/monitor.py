import time
import hashlib
import os
import stat

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler


WATCH_DIRECTORY = "/opt/organization"


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

            print(f"[CREATED] {event.src_path}")
            print(f"          SHA-256: {file_hash}")
            print(f"          Permissions: {oct(permissions)}")

    def on_modified(self, event):
        if not event.is_directory:
            file_hash = calculate_sha256(event.src_path)

            print(f"[MODIFIED] {event.src_path}")
            print(f"           SHA-256: {file_hash}")

    def on_deleted(self, event):
        if not event.is_directory:
            self.file_permissions.pop(event.src_path, None)

            print(f"[DELETED] {event.src_path}")

    def check_permissions(self):
        for file_path in list(self.file_permissions.keys()):
            current_permissions = get_permissions(file_path)
            previous_permissions = self.file_permissions[file_path]

            if current_permissions is None:
                continue

            if current_permissions != previous_permissions:
                print(f"[PERMISSION CHANGED] {file_path}")
                print(f"                   Old: {oct(previous_permissions)}")
                print(f"                   New: {oct(current_permissions)}")

                self.file_permissions[file_path] = current_permissions


def main():
    event_handler = FileMonitorHandler()

    observer = Observer()
    observer.schedule(
        event_handler,
        WATCH_DIRECTORY,
        recursive=True
    )

    observer.start()

    print(f"Monitoring: {WATCH_DIRECTORY}")
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
