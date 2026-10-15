"""MalDetect endpoint agent.

Runs on a PC or laptop, watches the Downloads folder, and reports every finished download
(file name, SHA-256, size, and on Windows the source URL) to the MalDetect server, which checks
it with VirusTotal. Shows a warning when a download is malicious or suspicious.

Uses only the Python standard library (Python 3.9+). Usage:

    python maldetect_agent.py                 # uses config.json next to this script
    python maldetect_agent.py --config other.json
    python maldetect_agent.py --once          # one scan of the folders, then exit (for testing)
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import platform
import socket
import ssl
import sys
import threading
import time
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timezone
from pathlib import Path

AGENT_VERSION = "1.0.0"

# Browsers write partial downloads under these extensions and rename the file when it is complete.
PARTIAL_DOWNLOAD_SUFFIXES = {".crdownload", ".part", ".partial", ".tmp", ".download", ".opdownload", ".!ut"}

DEFAULT_CONFIG = {
    "server_url": "http://192.168.1.10/threat2026",
    "device_token": "",
    "watch_dirs": [],  # empty = the user's Downloads folder
    "poll_seconds": 5,
    "heartbeat_seconds": 60,
    "result_poll_seconds": 30,
    "upload_unknown_files": True,
    "report_existing_files": False,
    "verify_tls": True,
    "state_file": "agent_state.json",
}

log = logging.getLogger("maldetect")


class ApiError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(f"HTTP {status}: {message}")
        self.status = status


class MalDetectClient:
    def __init__(self, server_url: str, token: str, verify_tls: bool):
        self.base = server_url.rstrip("/") + "/api/agent/"
        self.token = token
        self.context = None if verify_tls else ssl._create_unverified_context()

    def _send(self, request: urllib.request.Request) -> dict:
        request.add_header("X-Device-Token", self.token)
        request.add_header("Accept", "application/json")
        try:
            with urllib.request.urlopen(request, timeout=120, context=self.context) as response:
                return json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as error:
            try:
                payload = json.loads(error.read().decode("utf-8"))
            except (ValueError, OSError):
                payload = {}
            raise ApiError(error.code, payload.get("message", error.reason)) from error

    def post_json(self, endpoint: str, body: dict) -> dict:
        request = urllib.request.Request(self.base + endpoint, data=json.dumps(body).encode("utf-8"), method="POST")
        request.add_header("Content-Type", "application/json")
        return self._send(request)

    def get(self, endpoint: str) -> dict:
        return self._send(urllib.request.Request(self.base + endpoint, method="GET"))

    def upload(self, detection_id: int, path: Path) -> dict:
        boundary = uuid.uuid4().hex
        head = (
            f"--{boundary}\r\nContent-Disposition: form-data; name=\"detection_id\"\r\n\r\n{detection_id}\r\n"
            f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"upload.bin\"\r\n"
            "Content-Type: application/octet-stream\r\n\r\n"
        ).encode("utf-8")
        body = head + path.read_bytes() + f"\r\n--{boundary}--\r\n".encode("utf-8")
        request = urllib.request.Request(self.base + "upload.php", data=body, method="POST")
        request.add_header("Content-Type", f"multipart/form-data; boundary={boundary}")
        return self._send(request)


def sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_zone_identifier(path: Path) -> tuple[str | None, str | None]:
    """On Windows, browsers record where a file came from in the Zone.Identifier stream (Mark of the Web)."""
    if os.name != "nt":
        return None, None
    try:
        with open(str(path) + ":Zone.Identifier", "r", encoding="utf-8", errors="ignore") as stream:
            values = dict(line.strip().split("=", 1) for line in stream if "=" in line)
        return values.get("HostUrl"), values.get("ReferrerUrl")
    except OSError:
        return None, None


def alert(title: str, message: str) -> None:
    log.warning("%s: %s", title, message)
    if os.name == "nt":
        import ctypes

        # MB_ICONWARNING | MB_SYSTEMMODAL, shown in a thread so the agent keeps watching.
        threading.Thread(
            target=lambda: ctypes.windll.user32.MessageBoxW(0, message, title, 0x30 | 0x1000), daemon=True
        ).start()


def default_watch_dirs() -> list[Path]:
    return [Path.home() / "Downloads"]


class Agent:
    def __init__(self, config: dict, config_dir: Path):
        self.config = config
        self.client = MalDetectClient(config["server_url"], config["device_token"], config["verify_tls"])
        self.watch_dirs = [Path(os.path.expandvars(os.path.expanduser(d))) for d in config["watch_dirs"]] or default_watch_dirs()
        self.state_path = config_dir / config["state_file"]
        self.state = self._load_state()
        # path -> (size, mtime) from the previous poll; a file is reported once it stops changing.
        self.last_seen: dict[str, tuple[int, float]] = {}
        self.max_upload_bytes = 20 * 1024 * 1024
        self.next_heartbeat = 0.0

    def _load_state(self) -> dict:
        try:
            state = json.loads(self.state_path.read_text(encoding="utf-8"))
            state.setdefault("reported", {})
            state.setdefault("pending", {})
            return state
        except (OSError, ValueError):
            return {"reported": {}, "pending": {}, "initialized": False}

    def _save_state(self) -> None:
        tmp = self.state_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self.state, indent=2), encoding="utf-8")
        tmp.replace(self.state_path)

    @staticmethod
    def _fingerprint(stat: os.stat_result) -> str:
        return f"{stat.st_size}:{int(stat.st_mtime)}"

    def heartbeat(self) -> None:
        if time.time() < self.next_heartbeat:
            return
        self.next_heartbeat = time.time() + self.config["heartbeat_seconds"]
        try:
            response = self.client.post_json(
                "heartbeat.php",
                {"hostname": socket.gethostname(), "os": f"{platform.system()} {platform.release()}", "agent_version": AGENT_VERSION},
            )
            self.max_upload_bytes = int(response.get("max_upload_bytes", self.max_upload_bytes))
        except (ApiError, OSError) as error:
            log.error("Heartbeat failed: %s", error)

    def candidate_files(self):
        for directory in self.watch_dirs:
            try:
                entries = list(os.scandir(directory))
            except OSError as error:
                log.error("Cannot read %s: %s", directory, error)
                continue
            for entry in entries:
                path = Path(entry.path)
                if not entry.is_file(follow_symlinks=False) or path.suffix.lower() in PARTIAL_DOWNLOAD_SUFFIXES or path.name.startswith("~$"):
                    continue
                try:
                    yield path, entry.stat()
                except OSError:
                    continue

    def baseline(self) -> None:
        """On the first run, remember existing files so only new downloads are reported."""
        if self.state.get("initialized") or self.config["report_existing_files"]:
            self.state["initialized"] = True
            return
        for path, stat in self.candidate_files():
            self.state["reported"][str(path)] = self._fingerprint(stat)
        self.state["initialized"] = True
        self._save_state()
        log.info("Baseline saved: %d existing files will not be reported.", len(self.state["reported"]))

    def scan_folders(self) -> None:
        current: dict[str, tuple[int, float]] = {}
        for path, stat in self.candidate_files():
            key = str(path)
            current[key] = (stat.st_size, stat.st_mtime)
            if self.state["reported"].get(key) == self._fingerprint(stat):
                continue
            # Wait until size and modification time are unchanged across two polls (download finished).
            if self.last_seen.get(key) != current[key] or stat.st_size == 0:
                continue
            self.report(path, stat)
        self.last_seen = current
        # Forget files that were deleted so the state file does not grow forever.
        for key in [k for k in self.state["reported"] if k not in current]:
            del self.state["reported"][key]

    def report(self, path: Path, stat: os.stat_result) -> None:
        try:
            sha256 = sha256_of(path)
        except OSError as error:
            log.debug("Cannot read %s yet: %s", path, error)
            return
        source_url, referrer_url = read_zone_identifier(path)
        body = {
            "file_name": path.name,
            "file_path": str(path),
            "file_size": stat.st_size,
            "sha256": sha256,
            "source_url": source_url,
            "referrer_url": referrer_url,
            "downloaded_at": datetime.fromtimestamp(stat.st_mtime, timezone.utc).isoformat(),
        }
        try:
            detection = self.client.post_json("report.php", body)["detection"]
        except (ApiError, OSError, KeyError, ValueError) as error:
            log.error("Report for %s failed, will retry: %s", path.name, error)
            return
        log.info("Reported %s (%s): %s", path.name, sha256[:12], detection.get("risk_level") or detection.get("status"))
        self.state["reported"][str(path)] = self._fingerprint(stat)
        self.handle_detection(detection, path)
        self._save_state()

    def handle_detection(self, detection: dict, path: Path | None) -> None:
        detection_id = str(detection["id"])
        if detection.get("is_threat"):
            alert(
                "MalDetect: dangerous download",
                f"{detection['file_name']}\n\nRisk: {detection.get('risk_level')}\nThreat: {detection.get('threat_name') or 'not named'}\n"
                f"Engines: {detection.get('malicious_count')} malicious, {detection.get('suspicious_count')} suspicious.\n\n"
                "Do not open this file. Your administrator has been notified.",
            )
            self.state["pending"].pop(detection_id, None)
            return
        if detection.get("needs_upload") and path is not None and self.config["upload_unknown_files"]:
            try:
                if path.stat().st_size <= self.max_upload_bytes:
                    detection = self.client.upload(int(detection_id), path)["detection"]
                    log.info("Uploaded %s for analysis.", path.name)
                else:
                    log.info("%s is unknown to VirusTotal and too large to upload.", path.name)
            except (ApiError, OSError, KeyError) as error:
                log.error("Upload of %s failed: %s", path.name, error)
        if not detection.get("is_final"):
            self.state["pending"][detection_id] = str(path) if path else ""
        else:
            self.state["pending"].pop(detection_id, None)

    def poll_pending(self) -> None:
        for detection_id, path in list(self.state["pending"].items()):
            try:
                detection = self.client.get(f"result.php?id={int(detection_id)}")["detection"]
            except ApiError as error:
                if error.status == 404:
                    self.state["pending"].pop(detection_id, None)
                log.error("Result check for #%s failed: %s", detection_id, error)
                continue
            except (OSError, KeyError, ValueError) as error:
                log.error("Result check for #%s failed: %s", detection_id, error)
                continue
            if detection.get("is_final"):
                log.info("Result for %s: %s", detection["file_name"], detection.get("risk_level"))
            self.handle_detection(detection, Path(path) if path else None)
        self._save_state()

    def run(self, once: bool = False) -> None:
        log.info("MalDetect agent %s watching: %s", AGENT_VERSION, ", ".join(map(str, self.watch_dirs)))
        self.heartbeat()
        self.baseline()
        next_result_poll = 0.0
        while True:
            self.heartbeat()
            self.scan_folders()
            if time.time() >= next_result_poll and self.state["pending"]:
                self.poll_pending()
                next_result_poll = time.time() + self.config["result_poll_seconds"]
            if once:
                # A file must be seen twice before it is reported, so do a second pass.
                time.sleep(1)
                self.scan_folders()
                self._save_state()
                return
            time.sleep(self.config["poll_seconds"])


def load_config(path: Path) -> dict:
    try:
        user_config = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        sys.exit(f"Config file not found: {path}. Copy config.example.json to config.json and fill it in.")
    except ValueError as error:
        sys.exit(f"Config file {path} is not valid JSON: {error}")
    config = {**DEFAULT_CONFIG, **user_config}
    if not config["device_token"].startswith("mdt_"):
        sys.exit("device_token is missing. Register this PC in MalDetect (Admin > Devices) and paste its token.")
    return config


def main() -> None:
    parser = argparse.ArgumentParser(description="MalDetect download-monitoring agent")
    parser.add_argument("--config", default=str(Path(__file__).with_name("config.json")))
    parser.add_argument("--once", action="store_true", help="scan once and exit")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    config_path = Path(args.config).resolve()
    try:
        Agent(load_config(config_path), config_path.parent).run(once=args.once)
    except KeyboardInterrupt:
        log.info("Agent stopped.")


if __name__ == "__main__":
    main()
