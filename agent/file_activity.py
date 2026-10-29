"""Real-time file activity monitoring for the MalDetect agent.

Watches the user's Desktop, Documents, Downloads, Pictures, Videos and Music folders (found with the Windows
Known Folders API, so OneDrive or other redirected folders are used), plus extra folders from config.json and
from the administrator, including all subfolders. It reports when files and folders are created, modified,
deleted, renamed or moved. Only metadata is sent (paths, names, size, times), never file contents.

How it works:
- watchdog (ReadDirectoryChangesW on Windows) delivers changes as they happen ("realtime" events).
- The agent keeps a list of the files it knows (activity_inventory.json). A delete is held for a moment: if the same
  file (same file ID, or same name and size) shows up in another folder, it is reported as a move instead.
  The file list also tells whether a deleted path was a folder, and which files were inside it.
- At start, every few minutes, and when a folder comes back (USB drive, network share), the folders are compared
  with the file list ("reconciliation" events). This finds changes made while the agent was not running or that
  Windows did not report. Their exact time is usually unknown: it is then sent as null with the time window.
- Events wait in activity_queue.jsonl until the server confirms them, so nothing is lost while the server is
  offline. Each event has a UUID, and the server ignores an event it already has.

Needs the watchdog package (pip install watchdog). Without it, the folders are compared every
activity_poll_seconds instead, and all events are "reconciliation" events.
"""

from __future__ import annotations

import fnmatch
import getpass
import json
import logging
import os
import queue
import stat as stat_module
import threading
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

try:
    from watchdog.events import FileSystemEventHandler
    from watchdog.observers import Observer

    WATCHDOG_ERROR: str | None = None
except ImportError as import_error:  # the agent still works, with polling instead of real-time events
    FileSystemEventHandler = object  # type: ignore[assignment,misc]
    Observer = None  # type: ignore[assignment,misc]
    WATCHDOG_ERROR = str(import_error)

log = logging.getLogger("maldetect.activity")

# Windows Known Folder IDs (KNOWNFOLDERID). The real location is asked from Windows, because these folders are
# often moved, for example to OneDrive (C:\Users\me\OneDrive\Documents) or to another drive.
KNOWN_FOLDERS = {
    "Desktop": "B4BFCC3A-DB2C-424C-B029-7FE99A87C641",
    "Documents": "FDD39AD0-238F-46AF-ADB4-6C85480369C7",
    "Downloads": "374DE290-123F-4565-9164-39C4925E467B",
    "Pictures": "33E28130-4E1E-4676-835A-98395C3BC3BB",
    "Videos": "18989B1D-99B5-455B-841C-AB7C74E4DDFC",
    "Music": "4BD8D571-6D19-48D3-BE97-422220080E43",
}

# Temporary files of browsers, Office and editors. They are not reported; a temporary file that is renamed to a
# real name (a finished download, a document saved by Word) is reported as the real file.
DEFAULT_IGNORE_PATTERNS = [
    "~$*", "~*.tmp", "*.tmp", "*.temp", "*.crdownload", "*.part", "*.partial", "*.download", "*.opdownload",
    "*.!ut", ".~lock.*#", "*.swp", "*.swx", "desktop.ini", "thumbs.db", ".ds_store", "$recycle.bin",
    "system volume information",
]

MOVE_WINDOW_SECONDS = 2.0  # how long a delete waits for the same file to appear elsewhere (a move)
CREATE_HOLD_SECONDS = 2.0  # a new file is reported once it is written, with its final size
MODIFY_DEBOUNCE_SECONDS = 3.0  # many writes to one file within this time become one FILE_MODIFIED
MAX_CHILD_EVENTS = 500  # most FILE_DELETED events sent for the contents of one deleted folder
ROOT_CHECK_SECONDS = 60  # how often unavailable folders are checked again
INVENTORY_SAVE_SECONDS = 30
SEND_INTERVAL_SECONDS = 2.0
SEND_BATCH = 200
MAX_BACKOFF_SECONDS = 300
FILE_ATTRIBUTE_REPARSE_POINT = 0x400
# Symbolic links and junctions are not followed, so a link cannot make a folder be watched twice or loop.
LINK_REPARSE_TAGS = {0xA000000C, 0xA0000003}


def iso_utc(timestamp: float | None) -> str | None:
    """ISO 8601 UTC time with milliseconds (2026-10-29T05:14:15.123Z), or None when the time is not known."""
    if timestamp is None:
        return None
    return datetime.fromtimestamp(timestamp, timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def path_key(path: str) -> str:
    """Comparison key of a path: Windows paths are not case-sensitive."""
    return os.path.normcase(os.path.normpath(path))


def is_inside(key: str, parent_key: str) -> bool:
    return key == parent_key or key.startswith(parent_key.rstrip(os.sep) + os.sep)


def parent_key(key: str) -> str:
    return os.path.dirname(key)


def windows_known_folder(folder_id: str) -> Path | None:
    """Location of a Windows Known Folder for the user running the agent, or None."""
    if os.name != "nt":
        return None
    import ctypes
    from ctypes import wintypes

    class GUID(ctypes.Structure):
        _fields_ = [("Data1", wintypes.DWORD), ("Data2", wintypes.WORD), ("Data3", wintypes.WORD),
                    ("Data4", ctypes.c_ubyte * 8)]

    value = uuid.UUID(folder_id)
    guid = GUID(value.time_low, value.time_mid, value.time_hi_version,
                (ctypes.c_ubyte * 8).from_buffer_copy(value.bytes[8:]))
    shell32 = ctypes.windll.shell32
    ole32 = ctypes.windll.ole32
    shell32.SHGetKnownFolderPath.argtypes = [ctypes.POINTER(GUID), wintypes.DWORD, wintypes.HANDLE,
                                             ctypes.POINTER(ctypes.c_void_p)]
    shell32.SHGetKnownFolderPath.restype = ctypes.c_long
    ole32.CoTaskMemFree.argtypes = [ctypes.c_void_p]
    pointer = ctypes.c_void_p()
    result = shell32.SHGetKnownFolderPath(ctypes.byref(guid), 0, None, ctypes.byref(pointer))
    try:
        if result != 0 or not pointer.value:
            return None
        return Path(ctypes.wstring_at(pointer.value))
    finally:
        if pointer.value:
            ole32.CoTaskMemFree(pointer)


def known_folder_path(label: str) -> Path:
    return windows_known_folder(KNOWN_FOLDERS[label]) or Path.home() / label


def current_user() -> str:
    try:
        user = getpass.getuser()
    except (OSError, KeyError, ImportError):
        return ""
    domain = os.environ.get("USERDOMAIN") if os.name == "nt" else None
    return f"{domain}\\{user}" if domain else user


def parse_recycle_info(data: bytes) -> tuple[str, float] | None:
    """Reads a Recycle Bin $I file: (original path, deletion time as a Unix timestamp), or None."""
    if len(data) < 28:
        return None
    version = int.from_bytes(data[0:8], "little")
    filetime = int.from_bytes(data[16:24], "little")
    if version == 1:  # Windows Vista to 8.1: fixed 260-character path
        raw = data[24:24 + 520]
    elif version == 2:  # Windows 10 and 11: path length, then the path
        length = int.from_bytes(data[24:28], "little")
        raw = data[28:28 + length * 2]
    else:
        return None
    original = raw.decode("utf-16-le", errors="ignore").split("\x00", 1)[0]
    if not original or filetime <= 0:
        return None
    return original, (filetime - 116444736000000000) / 10_000_000


def recycle_bin_index(recycle_dir: str, since: float) -> dict[str, float]:
    """Original path key -> deletion time for items put in this Recycle Bin folder since the given time."""
    found: dict[str, float] = {}
    try:
        user_bins = [entry.path for entry in os.scandir(recycle_dir) if entry.is_dir()]
    except OSError:
        return found
    for user_bin in user_bins:  # one folder per Windows user (SID); other users' folders are not readable
        try:
            entries = list(os.scandir(user_bin))
        except OSError:
            continue
        for entry in entries:
            if not entry.name.upper().startswith("$I"):
                continue
            try:
                if entry.stat().st_mtime < since:
                    continue
                with open(entry.path, "rb") as handle:
                    parsed = parse_recycle_info(handle.read(4096))
            except OSError:
                continue
            if parsed:
                found[path_key(parsed[0])] = parsed[1]
    return found


def file_id(stat_result: os.stat_result, device: int | None = None) -> str | None:
    """Volume and file index (NTFS file ID, or inode). It stays the same when a file is renamed or moved."""
    if not stat_result.st_ino:
        return None
    return f"{device if device is not None else stat_result.st_dev}:{stat_result.st_ino}"


def same_file(old: list, new: list) -> bool:
    """True when two inventory entries are the same file (or folder) under a new name or in a new place.

    The file ID alone is not enough, because a deleted file's ID can be given to a new file. A rename or move
    keeps the size and the modification time, so a file must also match on those. A folder's time changes when
    its contents change, so a folder must match on that time or keep its name.
    """
    if not old[3] or old[3] != new[3] or old[4] != new[4]:
        return False
    if new[4]:
        return old[2] == new[2] or os.path.normcase(os.path.basename(old[0])) == os.path.normcase(os.path.basename(new[0]))
    return old[1] == new[1] and old[2] == new[2]


def is_link(stat_result: os.stat_result) -> bool:
    if stat_module.S_ISLNK(stat_result.st_mode):
        return True
    attributes = getattr(stat_result, "st_file_attributes", 0)
    return bool(attributes & FILE_ATTRIBUTE_REPARSE_POINT) and getattr(stat_result, "st_reparse_tag", 0) in LINK_REPARSE_TAGS


@dataclass
class Root:
    label: str
    path: str
    origin: str  # known, config or admin
    key: str = ""
    status: str = "pending"  # watching, polling, unavailable, error
    message: str | None = None
    watch: object = None
    covered_by: str | None = None  # label of a watched folder that already contains this one
    invalid: bool = False  # not an absolute path: never watched
    last_scan_at: float | None = None  # the saved file list for this folder is complete up to this time

    def __post_init__(self) -> None:
        self.key = path_key(self.path)


@dataclass
class PendingDelete:
    entry: list  # inventory entry: [path, size, mtime_ns, file_id, is_dir]
    time: float
    due: float


@dataclass
class PendingChange:
    path: str
    time: float
    due: float
    first_time: float = 0.0


class Outbox:
    """Events waiting for the server, kept in a JSON lines file so they survive a restart or a crash."""

    def __init__(self, path: Path, limit: int):
        self.path = path
        self.limit = limit
        self.lock = threading.Lock()
        self.items: list[dict] = []
        try:
            with path.open("r", encoding="utf-8") as handle:
                for line in handle:
                    try:
                        self.items.append(json.loads(line))
                    except ValueError:
                        continue  # a line cut off by a crash
        except FileNotFoundError:
            pass
        except OSError as error:
            log.error("Cannot read the activity queue %s: %s", path, error)
        if self.items:
            log.info("%d file activity event(s) from the last run are waiting to be sent.", len(self.items))

    def __len__(self) -> int:
        return len(self.items)

    def add(self, events: list[dict]) -> None:
        with self.lock:
            self.items.extend(events)
            dropped = len(self.items) - self.limit
            if dropped > 0:
                del self.items[:dropped]
                log.warning("The activity queue is full (%d events); the %d oldest event(s) were dropped.", self.limit, dropped)
                self._rewrite()
                return
            try:
                with self.path.open("a", encoding="utf-8") as handle:
                    for event in events:
                        handle.write(json.dumps(event, ensure_ascii=False) + "\n")
            except OSError as error:
                log.error("Cannot write the activity queue %s: %s", self.path, error)

    def peek(self, count: int) -> list[dict]:
        with self.lock:
            return self.items[:count]

    def remove(self, event_ids: set[str]) -> None:
        if not event_ids:
            return
        with self.lock:
            self.items = [event for event in self.items if event.get("event_id") not in event_ids]
            self._rewrite()

    def _rewrite(self) -> None:
        temporary = self.path.with_suffix(".tmp")
        try:
            with temporary.open("w", encoding="utf-8") as handle:
                for event in self.items:
                    handle.write(json.dumps(event, ensure_ascii=False) + "\n")
            temporary.replace(self.path)
        except OSError as error:
            log.error("Cannot write the activity queue %s: %s", self.path, error)


class _WatchHandler(FileSystemEventHandler):
    """Passes watchdog events to the monitor's queue; all work happens in the monitor's own thread."""

    def __init__(self, sink):
        super().__init__()
        self.sink = sink

    def on_any_event(self, event) -> None:
        if event.event_type not in ("created", "deleted", "modified", "moved"):
            return
        self.sink((
            "fs", event.event_type, os.fsdecode(event.src_path), os.fsdecode(event.dest_path or ""),
            bool(event.is_directory), bool(getattr(event, "is_synthetic", False)), time.time(),
        ))


class FileActivityMonitor:
    def __init__(self, client, config: dict, data_dir: Path):
        self.client = client
        self.config = config
        self.recursive = bool(config.get("activity_recursive", True))
        patterns = DEFAULT_IGNORE_PATTERNS + list(config.get("activity_ignore_patterns") or [])
        self.ignore_patterns = [str(pattern).lower() for pattern in patterns]
        self.max_files = int(config.get("activity_max_files", 200000))
        self.reconcile_seconds = max(60, int(float(config.get("activity_reconcile_minutes", 15)) * 60))
        self.poll_seconds = max(5, int(config.get("activity_poll_seconds", 30)))
        self.user_account = current_user()
        # One agent runs per logged-in Windows user, all in the same folder: each user gets their own files.
        suffix = "".join(c if c.isalnum() or c in "-_" else "_" for c in self.user_account.split("\\")[-1])[:60] or "user"
        self.inventory_path = data_dir / str(config.get("activity_inventory_file") or f"activity_inventory_{suffix}.json")
        self.outbox = Outbox(data_dir / str(config.get("activity_queue_file") or f"activity_queue_{suffix}.jsonl"),
                             int(config.get("activity_queue_limit", 20000)))
        self.mode = "realtime" if Observer is not None else "polling"
        self.message: str | None = None if Observer is not None else (
            "The watchdog package is not installed (pip install watchdog): changes are found by comparing the "
            f"folders every {self.poll_seconds} seconds instead of in real time."
        )
        self.raw: queue.Queue = queue.Queue()
        self.stop_event = threading.Event()
        self.lock = threading.Lock()
        self.roots: list[Root] = []
        self.admin_folders: list[str] = []
        self.inventory: dict[str, list] = {}
        self.inventory_saved_at: float | None = None
        self.inventory_dirty = False
        self.pending_deletes: dict[str, PendingDelete] = {}
        self.pending_creates: dict[str, PendingChange] = {}
        self.pending_mods: dict[str, PendingChange] = {}
        self.observer = None
        self.threads: list[threading.Thread] = []
        self.started = False

    # ---- public, called from the agent's main thread -------------------------------------------------------

    def start(self) -> None:
        if self.started:
            return
        self.started = True
        if WATCHDOG_ERROR:
            log.warning(self.message)
        if Observer is not None:
            self.observer = Observer()
            self.observer.start()
        for target, name in ((self._process_loop, "activity-monitor"), (self._send_loop, "activity-sender")):
            thread = threading.Thread(target=target, name=name, daemon=True)
            thread.start()
            self.threads.append(thread)

    def stop(self) -> None:
        """Stops watching, reports what is still held back, and saves the file list for the next start."""
        if not self.started or self.stop_event.is_set():
            return
        self.stop_event.set()
        if self.observer is not None:
            try:
                self.observer.stop()
                self.observer.join(timeout=5)
            except RuntimeError:
                pass
        for thread in self.threads:
            thread.join(timeout=10)

    def set_admin_folders(self, folders: list) -> None:
        """Extra folders chosen by the administrator on the server (sent with each heartbeat response)."""
        cleaned = [str(folder) for folder in folders if isinstance(folder, str) and folder.strip()][:20]
        if cleaned == self.admin_folders:
            return
        self.admin_folders = cleaned
        if self.started:
            self.raw.put(("roots",))

    def status(self) -> dict:
        with self.lock:
            folders = [
                {"label": root.label, "path": root.path, "status": root.status,
                 "message": root.message or (f"Included in {root.covered_by}" if root.covered_by else None)}
                for root in self.roots
            ]
        return {"mode": self.mode, "queued": len(self.outbox), "message": self.message, "folders": folders}

    # ---- folders ----------------------------------------------------------------------------------------------

    def _wanted_roots(self) -> list[Root]:
        roots: list[Root] = []
        for label in self.config.get("activity_known_folders") or list(KNOWN_FOLDERS):
            if label in KNOWN_FOLDERS:
                roots.append(Root(label, str(known_folder_path(label)), "known"))
            else:
                log.warning("Unknown folder name in activity_known_folders: %s", label)
        for origin, folders in (("config", self.config.get("activity_extra_folders") or []), ("admin", self.admin_folders)):
            for folder in folders:
                path = os.path.expandvars(os.path.expanduser(str(folder)))
                name = os.path.basename(os.path.normpath(path)) or path
                roots.append(Root(f"{name} (extra)"[:50], path, origin))
        unique: dict[str, Root] = {}
        for root in roots:
            if not os.path.isabs(root.path):
                root.invalid = True
                root.status, root.message = "error", "Not an absolute path; use a full path such as C:\\Lab\\Shared."
            unique.setdefault(root.key, root)
        return list(unique.values())

    def _apply_roots(self) -> None:
        """Starts watching new folders and stops watching removed ones (only the main roots get a watch)."""
        wanted = self._wanted_roots()
        wanted_keys = {root.key for root in wanted}
        current = {root.key: root for root in self.roots}
        for root in self.roots:
            if root.key not in wanted_keys:
                self._unwatch(root)
        roots = [current.get(root.key, root) for root in wanted]
        with self.lock:
            self.roots = roots
        self._check_roots()

    def _check_roots(self) -> None:
        """Marks missing folders as unavailable and starts watching folders that are (again) available."""
        newly_available: list[Root] = []
        for root in self.roots:
            if root.invalid:
                continue
            if not os.path.isdir(root.path):
                if root.status != "unavailable":
                    self._unwatch(root)
                    root.status = "unavailable"
                    root.message = "Folder does not exist or cannot be reached."
                    log.warning("Cannot monitor %s (%s): the folder does not exist or cannot be reached.", root.label, root.path)
                continue
            if root.status in ("pending", "unavailable", "error"):
                try:
                    os.listdir(root.path)
                except OSError as error:
                    message = f"Cannot read the folder: {error.strerror or error}"
                    if root.message != message:
                        log.warning("Cannot monitor %s (%s): %s", root.label, root.path, error)
                    root.status, root.message = "error", message
                    continue
                newly_available.append(root)
        # A folder inside another watched folder gets no watch of its own, so no change is reported twice.
        active = [root for root in self.roots if root.status in ("watching", "polling") or root in newly_available]
        for root in active:
            container = next((other for other in active if other is not root and self.recursive
                              and is_inside(root.key, other.key) and other.key != root.key), None)
            root.covered_by = container.label if container else None
            if container and root.watch is not None:
                self._unwatch(root)
        for root in newly_available:
            if root.covered_by is None:
                self._watch(root)
            else:
                root.status, root.message = ("watching" if self.observer else "polling"), None
        for root in newly_available:
            self._reconcile(root)

    def _watch(self, root: Root) -> None:
        if self.observer is None:
            root.status, root.message = "polling", None
            return
        try:
            root.watch = self.observer.schedule(_WatchHandler(self.raw.put), root.path, recursive=self.recursive)
            root.status, root.message = "watching", None
            log.info("Monitoring %s: %s", root.label, root.path)
        except (OSError, RuntimeError, ValueError) as error:
            root.watch = None
            root.status, root.message = "error", f"Cannot watch the folder: {error}"
            log.warning("Cannot monitor %s (%s): %s", root.label, root.path, error)

    def _unwatch(self, root: Root) -> None:
        if root.watch is not None and self.observer is not None:
            try:
                self.observer.unschedule(root.watch)
            except (KeyError, OSError, RuntimeError, ValueError):
                pass
        root.watch = None

    def _root_for(self, key: str) -> Root | None:
        matches = [root for root in self.roots if is_inside(key, root.key)]
        return max(matches, key=lambda root: len(root.key)) if matches else None

    def _ignored_name(self, name: str) -> bool:
        lowered = name.lower()
        return any(fnmatch.fnmatchcase(lowered, pattern) for pattern in self.ignore_patterns)

    def _ignored(self, path: str) -> bool:
        """True for temporary files and for anything inside an ignored folder, below the watched folder."""
        root = self._root_for(path_key(path))
        if root is None:
            return True
        relative = os.path.relpath(os.path.normpath(path), os.path.normpath(root.path))
        return any(self._ignored_name(part) for part in Path(relative).parts if part not in (".", ""))

    # ---- inventory ----------------------------------------------------------------------------------------------

    def _load_inventory(self) -> bool:
        try:
            data = json.loads(self.inventory_path.read_text(encoding="utf-8"))
            self.inventory = {key: entry for key, entry in data["entries"].items() if isinstance(entry, list) and len(entry) == 5}
            saved_at = data.get("saved_at")
            self.inventory_saved_at = datetime.fromisoformat(saved_at.replace("Z", "+00:00")).timestamp() if saved_at else None
            return True
        except FileNotFoundError:
            return False
        except (OSError, ValueError, KeyError, TypeError, AttributeError) as error:
            log.error("The saved file list %s cannot be read (%s); a new one is made.", self.inventory_path, error)
            return False

    def _save_inventory(self) -> None:
        temporary = self.inventory_path.with_suffix(".tmp")
        try:
            temporary.write_text(
                json.dumps({"version": 1, "saved_at": iso_utc(time.time()), "entries": self.inventory}, ensure_ascii=False),
                encoding="utf-8",
            )
            temporary.replace(self.inventory_path)
            self.inventory_dirty = False
        except OSError as error:
            log.error("Cannot save the file list %s: %s", self.inventory_path, error)

    def _scan(self, roots: list[Root]) -> tuple[dict[str, list], list[Root]]:
        """Lists every file and folder below the given folders. Returns the entries and the folders that worked."""
        found: dict[str, list] = {}
        scanned: list[Root] = []
        for root in roots:
            try:
                device = os.stat(root.path).st_dev
            except OSError as error:
                root.status, root.message = "unavailable", f"Folder cannot be reached: {error.strerror or error}"
                continue
            stack = [root.path]
            truncated = False
            while stack:
                directory = stack.pop()
                try:
                    iterator = os.scandir(directory)
                except OSError:
                    continue  # a subfolder without permission
                with iterator:
                    for entry in iterator:
                        if self._ignored_name(entry.name):
                            continue
                        try:
                            info = entry.stat(follow_symlinks=False)
                            if is_link(info) or entry.is_symlink():
                                continue
                            is_dir = entry.is_dir(follow_symlinks=False)
                            inode = entry.inode()
                        except OSError:
                            continue
                        found[path_key(entry.path)] = [
                            entry.path, 0 if is_dir else info.st_size, info.st_mtime_ns,
                            f"{device}:{inode}" if inode else None, is_dir,
                        ]
                        if is_dir and self.recursive:
                            stack.append(entry.path)
                if len(found) >= self.max_files:
                    truncated = True
                    break
            if truncated:
                root.message = (f"More than {self.max_files} files: changes made while the agent was off may not all be "
                                "found (real-time events still work).")
                log.warning("%s has more than %d files; the saved file list is incomplete.", root.path, self.max_files)
            scanned.append(root)
        return found, scanned

    def _stat_entry(self, path: str) -> list | None:
        try:
            info = os.stat(path, follow_symlinks=False)
        except OSError:
            return None
        is_dir = stat_module.S_ISDIR(info.st_mode)
        return [path, 0 if is_dir else info.st_size, info.st_mtime_ns, file_id(info), is_dir]

    def _children(self, key: str) -> list[str]:
        prefix = key.rstrip(os.sep) + os.sep
        return [child for child in self.inventory if child.startswith(prefix)]

    def _move_children(self, old_path: str, new_path: str) -> None:
        """Updates the saved paths of everything inside a renamed or moved folder."""
        old_key, new_key = path_key(old_path), path_key(new_path)
        old_length = len(old_path.rstrip("\\/"))
        for child in self._children(old_key):
            entry = self.inventory.pop(child)
            entry[0] = new_path.rstrip("\\/") + entry[0][old_length:]
            self.inventory[new_key + child[len(old_key):]] = entry
        self.inventory_dirty = True

    # ---- events -------------------------------------------------------------------------------------------------

    def _event(self, event_type: str, old: list | None, new: list | None, event_time: float | None,
               source: str = "realtime", time_source: str | None = "realtime", window_start: float | None = None,
               details: str | None = None, detected: float | None = None) -> dict:
        entry = new or old or [None, None, None, None, False]
        is_dir = bool(entry[4])
        if is_dir and event_type.startswith("FILE_"):
            event_type = "FOLDER_" + event_type[5:]
        root = self._root_for(path_key(entry[0])) if entry[0] else None
        event = {
            "event_id": str(uuid.uuid4()),
            "event_type": event_type,
            "source": source,
            "is_directory": is_dir,
            "folder_label": root.label if root else None,
            "old_path": old[0] if old and not event_type.endswith(("_CREATED", "_MODIFIED")) else None,
            "new_path": new[0] if new else None,
            "file_size": None if is_dir else entry[1],
            "user_account": self.user_account,
            "event_time": iso_utc(event_time),
            "time_source": time_source if event_time is not None else None,
            "detected_at": iso_utc(detected or time.time()),
            "window_start": iso_utc(window_start),
            "details": details,
        }
        moved = event["old_path"] and event["new_path"]
        log.info("%s | %s | %s", event_type, f"{old[0]} -> {new[0]}" if moved else entry[0], source)
        return event

    def _emit(self, *events: dict) -> None:
        if events:
            self.outbox.add(list(events))

    def _handle(self, item: tuple) -> None:
        if item[0] == "roots":
            self._apply_roots()
            return
        _, kind, src, dest, is_dir, synthetic, event_time = item
        if synthetic:
            # watchdog's own extra events for the contents of a moved or copied folder; handled via the file list.
            return
        if kind == "moved":
            self._on_moved(src, dest, is_dir, event_time)
        elif kind == "created":
            if not self._ignored(src):
                self._on_created(src, event_time)
        elif kind == "deleted":
            if not self._ignored(src):
                self._on_deleted(src, event_time)
        elif kind == "modified" and not is_dir and not self._ignored(src):
            self._on_modified(src, event_time)

    def _on_created(self, path: str, event_time: float) -> None:
        key = path_key(path)
        entry = self._stat_entry(path)
        replaced = self.pending_deletes.pop(key, None)
        if replaced is not None:
            # Deleted (or renamed to a temporary name) and created again at once: a program saved a new version.
            if entry is not None and not entry[4]:
                self.inventory[key] = entry
                self.inventory_dirty = True
                self._emit(self._event("FILE_MODIFIED", replaced.entry, entry, event_time,
                                       details="Saved as a new copy of the file (replaced)."))
                return
            self.pending_deletes[key] = replaced
        if entry is None:
            return  # already gone again (a short-lived file)
        known = self.inventory.get(key)
        if known is not None and known[3] == entry[3] and known[4] == entry[4]:
            return  # already known: a repeated event, or found when its new folder was listed
        moved_from = self._match_pending_delete(entry)
        if moved_from is not None:
            old = self.pending_deletes.pop(moved_from).entry
            self._record_move(old, entry, event_time)
            return
        self.inventory[key] = entry
        self.inventory_dirty = True
        if entry[4]:
            # A new folder, maybe moved or copied in with files (Windows then reports only the folder): its contents
            # are reported as created too, held back like other new files so each one is reported once.
            contents, _ = self._scan([Root("", path, "temp")])
            details = None
            if len(contents) > MAX_CHILD_EVENTS:
                details = f"The folder holds {len(contents)} items; only the first {MAX_CHILD_EVENTS} are listed."
            self._emit(self._event("FOLDER_CREATED", None, entry, event_time, details=details))
            for index, (child_key, child) in enumerate(sorted(contents.items())):
                known_child = self.inventory.get(child_key)
                if known_child is not None and known_child[3] == child[3]:
                    continue
                self.inventory[child_key] = child
                if index < MAX_CHILD_EVENTS:
                    self.pending_creates[child_key] = PendingChange(child[0], event_time, time.time() + CREATE_HOLD_SECONDS)
            return
        self.pending_creates[key] = PendingChange(path, event_time, time.time() + CREATE_HOLD_SECONDS)

    def _match_pending_delete(self, entry: list) -> str | None:
        if entry[3]:
            for key, pending in self.pending_deletes.items():
                if same_file(pending.entry, entry):
                    return key
        # Without a file ID (for example some network shares): the same name and size, when only one matches.
        name = os.path.normcase(os.path.basename(entry[0]))
        candidates = [key for key, pending in self.pending_deletes.items()
                      if os.path.normcase(os.path.basename(pending.entry[0] or "")) == name
                      and pending.entry[4] == entry[4] and (entry[4] or pending.entry[1] == entry[1])]
        return candidates[0] if len(candidates) == 1 else None

    def _record_move(self, old: list, new: list, event_time: float, source: str = "realtime",
                     window_start: float | None = None) -> None:
        old_key, new_key = path_key(old[0]), path_key(new[0])
        self.inventory.pop(old_key, None)
        self.inventory[new_key] = new
        if new[4]:
            self._move_children(old[0], new[0])
        self.inventory_dirty = True
        same_folder = parent_key(old_key) == parent_key(new_key)
        event_type = "FILE_RENAMED" if same_folder else "FILE_MOVED"
        if source == "realtime":
            self._emit(self._event(event_type, old, new, event_time))
        else:
            self._emit(self._event(event_type, old, new, None, source, None, window_start, RECONCILE_NOTE))

    def _on_deleted(self, path: str, event_time: float) -> None:
        key = path_key(path)
        if key in self.pending_deletes:
            return  # reported twice by Windows
        self.pending_mods.pop(key, None)
        created = self.pending_creates.pop(key, None)
        if created is not None:
            self._finish_create(key, created)
        entry = self.inventory.get(key) or [path, None, None, None, False]
        # A copy to another drive followed by a delete is a move: the new copy has the same name and size.
        name = os.path.normcase(os.path.basename(path))
        for other_key, pending in list(self.pending_creates.items()):
            other = self.inventory.get(other_key)
            if other and os.path.normcase(os.path.basename(other[0])) == name and other[1] == entry[1] and not entry[4]:
                del self.pending_creates[other_key]
                self.inventory.pop(key, None)
                self.inventory_dirty = True
                self._emit(self._event("FILE_MOVED", entry, other, event_time,
                                       details="Copied to the new place, then removed from the old one."))
                return
        self.pending_deletes[key] = PendingDelete(entry, event_time, time.time() + MOVE_WINDOW_SECONDS)

    def _on_moved(self, src: str, dest: str, is_dir: bool, event_time: float) -> None:
        src_key, dest_key = path_key(src), path_key(dest)
        src_ignored, dest_ignored = self._ignored(src), self._ignored(dest)
        if src_ignored and dest_ignored:
            return
        if src_ignored:  # a finished download, or a document saved through a temporary file
            self.inventory.pop(src_key, None)
            self._on_created(dest, event_time)
            return
        if dest_ignored:  # renamed to a temporary name: usually part of saving; otherwise reported as deleted
            self._on_deleted(src, event_time)
            return
        created = self.pending_creates.pop(src_key, None)
        # A file created moments ago (still held back, or already gone when its event was handled) and renamed at
        # once. Excel and other programs save this way: they write a new file and rename it to the document's name.
        brand_new = created is not None or src_key not in self.inventory
        if brand_new and not is_dir:
            self.inventory.pop(src_key, None)
            entry = self._stat_entry(dest)
            replaced = self.pending_deletes.pop(dest_key, None)
            if replaced is not None and entry is not None and not entry[4]:
                self.inventory[dest_key] = entry
                self.inventory_dirty = True
                self._emit(self._event("FILE_MODIFIED", replaced.entry, entry, event_time,
                                       details="Saved as a new copy of the file (replaced)."))
                return
            if replaced is not None:
                self.pending_deletes[dest_key] = replaced
            if entry is not None:
                self.inventory[dest_key] = entry
                self.inventory_dirty = True
            self.pending_creates[dest_key] = created or PendingChange(dest, event_time, 0.0)
            self.pending_creates[dest_key].path = dest
            self.pending_creates[dest_key].due = time.time() + CREATE_HOLD_SECONDS
            return
        modified = self.pending_mods.pop(src_key, None)
        if modified is not None:
            modified.path = dest
            self.pending_mods[dest_key] = modified
        old = self.inventory.get(src_key) or [src, None, None, None, is_dir]
        new = self._stat_entry(dest) or [dest, old[1], old[2], old[3], is_dir]
        self._record_move(old, new, event_time)

    def _on_modified(self, path: str, event_time: float) -> None:
        key = path_key(path)
        now = time.time()
        if key in self.pending_creates:
            self.pending_creates[key].due = now + CREATE_HOLD_SECONDS
            return
        known = self.inventory.get(key)
        if known is not None and known[4]:
            return
        pending = self.pending_mods.get(key)
        if pending is None:
            self.pending_mods[key] = PendingChange(path, event_time, now + MODIFY_DEBOUNCE_SECONDS, event_time)
        else:
            pending.time, pending.due = event_time, now + MODIFY_DEBOUNCE_SECONDS

    def _finish_create(self, key: str, pending: PendingChange) -> None:
        entry = self._stat_entry(pending.path) or self.inventory.get(key)
        if entry is None:
            return
        self.inventory[key] = entry
        self.inventory_dirty = True
        self._emit(self._event("FILE_CREATED", None, entry, pending.time))

    def _finish_modify(self, key: str, pending: PendingChange) -> None:
        entry = self._stat_entry(pending.path)
        if entry is None or entry[4]:
            return
        known = self.inventory.get(key)
        if known is not None and known[1] == entry[1] and known[2] == entry[2]:
            return  # only opened or attributes changed: the content did not change
        self.inventory[key] = entry
        self.inventory_dirty = True
        if known is None:
            self._emit(self._event("FILE_CREATED", None, entry, pending.first_time))
        else:
            self._emit(self._event("FILE_MODIFIED", known, entry, pending.time))

    def _finish_deletes(self, keys: list[str]) -> None:
        if not keys:
            return
        deletes = [(key, self.pending_deletes.pop(key)) for key in keys]
        recycled = self._recycle_bin_items(min(pending.time for _, pending in deletes) - 30, [p.entry[0] for _, p in deletes])
        for key, pending in deletes:
            entry = self.inventory.pop(key, None) or pending.entry
            self.inventory_dirty = True
            how = self._deletion_note(key, recycled)
            events = [self._event("FILE_DELETED", entry, None, pending.time, details=how)]
            children = self._children(key)
            for child in children[:MAX_CHILD_EVENTS]:
                events.append(self._event("FILE_DELETED", self.inventory[child], None, pending.time,
                                          details=f"Inside the deleted folder {os.path.basename(entry[0])}. {how or ''}".strip()))
            if len(children) > MAX_CHILD_EVENTS:
                events[0]["details"] = (f"{how or ''} The folder held {len(children)} items; only the first "
                                        f"{MAX_CHILD_EVENTS} are listed.").strip()
            for child in children:
                del self.inventory[child]
            self._emit(*events)

    def _recycle_bin_base(self, path: str) -> str | None:
        """The Recycle Bin folder of the drive that holds this path (Windows drive letters only)."""
        drive = os.path.splitdrive(path)[0]
        if os.name != "nt" or len(drive) != 2:
            return None
        return drive + "\\$Recycle.Bin"

    def _recycle_bin_items(self, since: float, paths: list[str]) -> dict[str, float] | None:
        bases = {base for base in (self._recycle_bin_base(path) for path in paths) if base}
        if not bases:
            return None
        found: dict[str, float] = {}
        for base in bases:
            found.update(recycle_bin_index(base, since))
        return found

    @staticmethod
    def _deletion_note(key: str, recycled: dict[str, float] | None) -> str | None:
        if recycled is None:
            return None  # not on a Windows drive with a Recycle Bin: the kind of delete is unknown
        probe = key
        while True:
            if probe in recycled:
                when = iso_utc(recycled[probe])
                if probe == key:
                    return f"Moved to the Recycle Bin (at {when})."
                return f"In a folder moved to the Recycle Bin (at {when})."
            parent = parent_key(probe)
            if parent == probe:
                break
            probe = parent
        return "Not in the Recycle Bin: deleted permanently (Shift+Delete, a program, the command line) or moved to a folder that is not monitored."

    def _flush_due(self, everything: bool = False) -> None:
        now = time.time()
        self._finish_deletes([key for key, pending in self.pending_deletes.items() if everything or pending.due <= now])
        for key, pending in list(self.pending_creates.items()):
            if everything or pending.due <= now:
                del self.pending_creates[key]
                self._finish_create(key, pending)
        for key, pending in list(self.pending_mods.items()):
            if everything or pending.due <= now:
                del self.pending_mods[key]
                self._finish_modify(key, pending)

    # ---- reconciliation -----------------------------------------------------------------------------------------

    def _reconcile(self, root: Root) -> None:
        """Compares one folder with the saved file list and reports the differences ("reconciliation" events)."""
        if root.covered_by is not None or root.status not in ("watching", "polling"):
            return
        has_entries = any(is_inside(key, root.key) for key in self.inventory)
        # The change happened after the list was last known to be complete: the previous scan of this folder,
        # or, at start, the time the agent last saved the list.
        window_start = root.last_scan_at or (self.inventory_saved_at if has_entries else None)
        found, scanned = self._scan([root])
        if not scanned:
            return
        detected = time.time()
        # Changes made while scanning are still in the queue: they are handled as real-time events, so those
        # paths are left out here and nothing is reported twice.
        touched: set[str] = set()
        drained: list[tuple] = []
        while True:
            try:
                item = self.raw.get_nowait()
            except queue.Empty:
                break
            drained.append(item)
            if item[0] == "fs":
                touched.update(path_key(path) for path in item[2:4] if path)
        touched.update(self.pending_deletes, self.pending_creates, self.pending_mods)
        old = {key: entry for key, entry in self.inventory.items() if is_inside(key, root.key) and key not in touched}
        new = {key: entry for key, entry in found.items() if key not in touched}
        if window_start is None:
            log.info("%s: saved a list of %d files and folders; changes are reported from now on.", root.label, len(new))
        else:
            self._report_differences(old, new, window_start, detected)
        for key in old:
            self.inventory.pop(key, None)
        self.inventory.update(new)
        self.inventory_dirty = True
        root.last_scan_at = detected
        for item in drained:
            self._handle(item)

    def _report_differences(self, old: dict, new: dict, window_start: float, detected: float) -> None:
        gone = [key for key in old if key not in new]
        added = [key for key in new if key not in old]
        events: list[dict] = []
        # Same file ID in the old and the new list: the file was renamed or moved.
        by_id = {old[key][3]: key for key in gone if old[key][3]}
        moves: list[tuple[str, str]] = []
        for key in added:
            old_key = by_id.get(new[key][3]) if new[key][3] else None
            if old_key is not None and same_file(old[old_key], new[key]):
                del by_id[new[key][3]]
                moves.append((old_key, key))
        moved_old = {old_key for old_key, _ in moves}
        moved_new = {new_key for _, new_key in moves}
        moved_dirs = {(old_key, new_key) for old_key, new_key in moves if new[new_key][4]}
        for old_key, new_key in moves:
            # The contents of a moved folder move with it; only the folder itself is reported.
            if (parent_key(old_key), parent_key(new_key)) in moved_dirs:
                continue
            event_type = "FILE_RENAMED" if parent_key(old_key) == parent_key(new_key) else "FILE_MOVED"
            events.append(self._event(event_type, old[old_key], new[new_key], None, "reconciliation", None,
                                      window_start, RECONCILE_NOTE, detected))
        deleted = [key for key in gone if key not in moved_old]
        recycled = self._recycle_bin_items(window_start - 60, [old[key][0] for key in deleted])
        for key in deleted:
            when = None
            note = self._deletion_note(key, recycled)
            if recycled:
                probe = key
                while probe not in recycled and parent_key(probe) != probe:
                    probe = parent_key(probe)
                when = recycled.get(probe)
            events.append(self._event("FILE_DELETED", old[key], None, when, "reconciliation", "recycle_bin",
                                      window_start, " ".join(filter(None, [RECONCILE_NOTE, note])), detected))
        for key in added:
            if key in moved_new:
                continue
            events.append(self._event("FILE_CREATED", None, new[key], self._creation_time(new[key][0], window_start),
                                      "reconciliation", "file_metadata", window_start, RECONCILE_NOTE, detected))
        for key in old:
            if key in new and not new[key][4] and (old[key][1], old[key][2]) != (new[key][1], new[key][2]):
                modified_at = new[key][2] / 1e9
                events.append(self._event("FILE_MODIFIED", old[key], new[key],
                                          modified_at if window_start <= modified_at <= detected + 5 else None,
                                          "reconciliation", "file_metadata", window_start, RECONCILE_NOTE, detected))
        if events:
            log.info("Found %d change(s) by comparing the folders with the saved file list.", len(events))
            self._emit(*events)

    @staticmethod
    def _creation_time(path: str, window_start: float) -> float | None:
        """Creation time from the file system (Windows), only when it falls inside the window."""
        try:
            info = os.stat(path)
        except OSError:
            return None
        created = getattr(info, "st_birthtime", None)
        if created is None and os.name == "nt":
            created = info.st_ctime
        if created is None or created < window_start or created > time.time() + 5:
            return None  # for example a file copied with its old dates: the real time is not known
        return created

    # ---- threads ------------------------------------------------------------------------------------------------

    def _process_loop(self) -> None:
        try:
            self._load_inventory()
            self._apply_roots()  # also compares the folders with the saved list (start-up reconciliation)
            self._save_inventory()
        except Exception:  # never let the monitor take the download agent down
            log.exception("File activity monitoring could not start.")
            self.mode, self.message = "off", "File activity monitoring could not start; see agent.log."
            return
        next_root_check = time.time() + ROOT_CHECK_SECONDS
        next_reconcile = time.time() + (self.poll_seconds if self.observer is None else self.reconcile_seconds)
        next_save = time.time() + INVENTORY_SAVE_SECONDS
        while not self.stop_event.is_set():
            try:
                try:
                    item = self.raw.get(timeout=0.5)
                    self._handle(item)
                    for _ in range(1000):  # bursts: handle what is waiting before checking timers
                        self._handle(self.raw.get_nowait())
                except queue.Empty:
                    pass
                self._flush_due()
                now = time.time()
                if now >= next_root_check:
                    next_root_check = now + ROOT_CHECK_SECONDS
                    self._check_roots()
                if now >= next_reconcile:
                    next_reconcile = now + (self.poll_seconds if self.observer is None else self.reconcile_seconds)
                    self._flush_due(everything=True)
                    for root in list(self.roots):
                        self._reconcile(root)
                if self.inventory_dirty and now >= next_save:
                    next_save = now + INVENTORY_SAVE_SECONDS
                    self._save_inventory()
            except Exception:
                log.exception("Error in file activity monitoring; continuing.")
        # Stopping: handle what is left, report held-back events, and save the file list for the next start.
        try:
            while True:
                self._handle(self.raw.get_nowait())
        except queue.Empty:
            pass
        except Exception:
            log.exception("Error while stopping file activity monitoring.")
        self._flush_due(everything=True)
        self._save_inventory()

    def _send_loop(self) -> None:
        batch_size = SEND_BATCH
        backoff = 0.0
        while not self.stop_event.wait(SEND_INTERVAL_SECONDS):
            batch = self.outbox.peek(batch_size)
            if not batch:
                continue
            try:
                response = self.client.post_json("activity.php", {"events": batch}, timeout=30)
            except Exception as error:  # ApiError, network errors, bad JSON
                status = getattr(error, "status", None)
                if status == 413:
                    batch_size = max(10, batch_size // 2)
                    continue
                backoff = min(MAX_BACKOFF_SECONDS, max(5.0, backoff * 2))
                log.warning("Sending %d file activity event(s) failed (%s); retrying in %d s. They stay queued.",
                            len(batch), error, backoff)
                self.stop_event.wait(backoff)
                continue
            backoff = 0.0
            done = {str(event_id) for event_id in response.get("accepted", []) + response.get("duplicates", [])}
            for rejected in response.get("rejected", []):
                log.error("The server rejected file activity event %s: %s", rejected.get("event_id"), rejected.get("reason"))
                done.add(str(rejected.get("event_id")))
            if not done:
                log.error("The server confirmed none of the %d file activity event(s); retrying later.", len(batch))
                self.stop_event.wait(MAX_BACKOFF_SECONDS)
                continue
            self.outbox.remove(done)


# The time window itself is sent in window_start and detected_at.
RECONCILE_NOTE = "Found by comparing the folder with the agent's saved file list (for example after the agent was off)."
