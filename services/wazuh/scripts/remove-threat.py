#!/usr/bin/env python3
# Copyright (C) 2015-2025, Wazuh Inc.
# All rights reserved.

import os
import sys
import json
import datetime
import pathlib
import shutil

if os.name == "nt":
    LOG_FILE = r"C:\Program Files (x86)\ossec-agent\active-response\active-responses.log"
    DEFAULT_QUARANTINE_DIR = r"C:\Program Files (x86)\ossec-agent\active-response\quarantine"
else:
    LOG_FILE = "/var/ossec/logs/active-responses.log"
    DEFAULT_QUARANTINE_DIR = "/var/ossec/active-response/quarantine"

ADD_COMMAND = 0
DELETE_COMMAND = 1
CONTINUE_COMMAND = 2
ABORT_COMMAND = 3

OS_SUCCESS = 0
OS_INVALID = -1


class Message:
    def __init__(self):
        self.alert = {}
        self.command = OS_INVALID

# Active response scripts typically log to active-responses.log for troubleshooting
def write_debug_file(ar_name: str, msg: str) -> None:
    with open(LOG_FILE, mode="a", encoding="utf-8", errors="replace") as log_file:
        ts = datetime.datetime.now().strftime("%Y/%m/%d %H:%M:%S")
        log_file.write(f"{ts} {ar_name}: {msg}\n")

# Wazuh active-response sends a single JSON line to stdin per invocation
def read_stdin_once() -> str:
    for line in sys.stdin:
        return line
    return ""


def setup_and_check_message(argv) -> Message:
    input_str = read_stdin_once()

    msg_obj = Message()
    try:
        data = json.loads(input_str)
    except ValueError:
        write_debug_file(argv[0], "Decoding JSON has failed, invalid input format")
        msg_obj.command = OS_INVALID
        return msg_obj

    msg_obj.alert = data
    command = data.get("command")

    # Wazuh control messages for active-response use 'add'/'delete' as command values
    if command == "add":
        msg_obj.command = ADD_COMMAND
    elif command == "delete":
        msg_obj.command = DELETE_COMMAND
    else:
        msg_obj.command = OS_INVALID
        write_debug_file(argv[0], f"Not valid command: {command}")

    return msg_obj

# check_keys prevents repeated execution for the same key (dedup / anti-loop)
def send_keys_and_check_message(argv, keys):
    keys_msg = json.dumps(
        {
            "version": 1,
            "origin": {"name": argv[0], "module": "active-response"},
            "command": "check_keys",
            "parameters": {"keys": keys},
        }
    )

    # blog-style: log JSON control message too
    write_debug_file(argv[0], keys_msg)

    print(keys_msg)
    sys.stdout.flush()

    input_str = ""
    while True:
        line = sys.stdin.readline()
        if line:
            input_str = line
            break

    try:
        data = json.loads(input_str)
    except ValueError:
        write_debug_file(argv[0], "Decoding JSON has failed, invalid input format")
        return OS_INVALID

    action = data.get("command")
    if action == "continue":
        return CONTINUE_COMMAND
    if action == "abort":
        return ABORT_COMMAND

    write_debug_file(argv[0], "Invalid value of 'command'")
    return OS_INVALID


def extract_target_path(alert_obj: dict) -> str:
    """
    Prefer syscheck.path if present (blog style).
    Fall back to data.syscheck.path (your malware_api alert style).
    """
    return (
        alert_obj.get("syscheck", {}).get("path")
        or alert_obj.get("data", {}).get("syscheck", {}).get("path")
        or ""
    )


def normalize_target_path(path_str: str) -> str:
    """Fix Windows paths that arrive with a leading slash like '/c:\\users\\...'."""
    if not path_str:
        return path_str
    if os.name == "nt":
        cleaned = path_str.replace("/", "\\")
        # Drop a leading slash when it precedes a drive letter (e.g., /c:\\)
        if cleaned.startswith("\\") and len(cleaned) > 2 and cleaned[1].isalpha() and cleaned[2] == ":":
            cleaned = cleaned.lstrip("\\/")
        return cleaned
    return path_str


def ensure_syscheck_path_for_rules(msg_alert: dict) -> None:
    """
    This makes $(parameters.alert.syscheck.path) work even if the original alert
    only had $(parameters.alert.data.syscheck.path).
    We mutate msg_alert in-memory ONLY for logging.
    """
    pa = msg_alert.get("parameters", {}).get("alert", {})
    if "syscheck" not in pa and "data" in pa and isinstance(pa.get("data"), dict):
        ds = pa["data"].get("syscheck")
        if isinstance(ds, dict):
            # copy into top-level syscheck
            pa["syscheck"] = ds


def quarantine_or_delete(resolved_file: pathlib.Path) -> str:
    # Windows-compatible file deletion
    try:
        if os.name == "nt":
            # On Windows, ensure file is not read-only before deletion
            os.chmod(str(resolved_file), 0o777)
        os.remove(str(resolved_file))
    except PermissionError:
        # If direct deletion fails, try to mark for deletion on reboot (Windows)
        if os.name == "nt":
            import ctypes
            ctypes.windll.kernel32.MoveFileExW(
                str(resolved_file), None, 0x00000004  # MOVEFILE_DELAY_UNTIL_REBOOT
            )
        else:
            raise
    return "deleted"


def main(argv):
    msg = setup_and_check_message(argv)
    if msg.command < 0:
        sys.exit(OS_INVALID)

    if msg.command != ADD_COMMAND:
        sys.exit(OS_SUCCESS)

    # Original alert object (this is what rules will reference via parameters.alert.*)
    alert_obj = msg.alert.get("parameters", {}).get("alert", {})

    file_path = normalize_target_path(extract_target_path(alert_obj))

    # Use hash as check_keys key if present
    malware_hash = (
        alert_obj.get("data", {}).get("malware_api", {}).get("hash")
        or alert_obj.get("data", {}).get("syscheck", {}).get("sha256_after")
        or alert_obj.get("syscheck", {}).get("sha256_after")
        or ""
    )
    key = malware_hash if malware_hash else (file_path or "unknown")

    action = send_keys_and_check_message(argv, [key])
    if action != CONTINUE_COMMAND:
        # IMPORTANT: blog-style logging includes JSON + message
        ensure_syscheck_path_for_rules(msg.alert)
        if action == ABORT_COMMAND:
            write_debug_file(argv[0], json.dumps(msg.alert) + " Aborted")
            sys.exit(OS_SUCCESS)
        write_debug_file(argv[0], json.dumps(msg.alert) + " Error removing threat")
        sys.exit(OS_INVALID)

    try:
        if not file_path:
            raise ValueError("No syscheck path found in alert")

        p = pathlib.Path(file_path)
        # refuse symlinks
        if p.is_symlink():
            raise ValueError("Refusing to act on symlink")

        resolved = p.resolve()
        # Only allow deletion of regular files (no directories/devices)
        if not resolved.is_file():
            raise ValueError("Target is not a regular file")

        action_taken = quarantine_or_delete(resolved)

        ensure_syscheck_path_for_rules(msg.alert)
        write_debug_file(argv[0], json.dumps(msg.alert) + " Successfully removed threat")
        sys.exit(OS_SUCCESS)

    except Exception:
        ensure_syscheck_path_for_rules(msg.alert)
        write_debug_file(argv[0], json.dumps(msg.alert) + " Error removing threat")
        sys.exit(OS_INVALID)


if __name__ == "__main__":
    main(sys.argv)
