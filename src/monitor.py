import time
import hashlib

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


class FileMonitorHandler(FileSystemEventHandler):

    def on_created(self, event):
        if not event.is_directory:
            file_hash = calculate_sha256(event.src_path)

            print(f"[CREATED] {event.src_path}")
            print(f"          SHA-256: {file_hash}")

    def on_modified(self, event):
        if not event.is_directory:
            file_hash = calculate_sha256(event.src_path)

            print(f"[MODIFIED] {event.src_path}")
            print(f"           SHA-256: {file_hash}")

    def on_deleted(self, event):
        if not event.is_directory:
            print(f"[DELETED] {event.src_path}")


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
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()

    observer.join()


if __name__ == "__main__":
    main()
