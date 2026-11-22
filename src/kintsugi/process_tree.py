"""Best-effort timeout cleanup for an execution's descendants, including setsid children.

The OS sandbox remains the isolation boundary. This module does not grant a
security guarantee against an adversarial process which erases its environment
and deliberately escapes ancestry tracking; use an OS job/cgroup where available.
"""
from __future__ import annotations

import os
import secrets
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, Set, Tuple

EXEC_TOKEN_NAME = "_KINTSUGI_EXEC_TOKEN"


def new_execution_token() -> str:
    return secrets.token_hex(24)


def _linux_snapshot(token: str, uid: int) -> Tuple[Dict[int, int], Set[int]]:
    parents: Dict[int, int] = {}
    marked: Set[int] = set()
    proc = Path("/proc")
    if not proc.is_dir():
        return parents, marked
    expected = f"{EXEC_TOKEN_NAME}={token}".encode("ascii")
    for ent in proc.iterdir():
        if not ent.name.isdigit():
            continue
        pid = int(ent.name)
        if pid < 2 or pid == os.getpid():
            continue
        try:
            if ent.stat().st_uid != uid:
                continue
            stat_text = (ent / "stat").read_text(encoding="ascii")
            after_comm = stat_text.rsplit(") ", 1)[1].split()
            parents[pid] = int(after_comm[1])
            # Read environ only for own UID; never log its contents.
            with (ent / "environ").open("rb") as handle:
                env_bytes = handle.read(128 * 1024)
            if expected in env_bytes.split(b"\x00"):
                marked.add(pid)
        except (OSError, ValueError, IndexError, UnicodeDecodeError):
            continue
    return parents, marked


def _darwin_snapshot(token: str, uid: int) -> Tuple[Dict[int, int], Set[int]]:
    parents: Dict[int, int] = {}
    marked: Set[int] = set()
    try:
        # On macOS BSD ps, uppercase `-E` prints process environment; lowercase `-e` does not.
        res = subprocess.run(
            ["/bin/ps", "-A", "-E", "-ww", "-o", "pid=,ppid=,uid=,command="],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            timeout=3.0, check=False,
        )
        for line in res.stdout.decode("utf-8", errors="replace").splitlines():
            fields = line.strip().split(None, 3)
            if len(fields) < 3:
                continue
            try:
                pid, ppid, owner = map(int, fields[:3])
            except ValueError:
                continue
            if owner != uid or pid < 2 or pid == os.getpid():
                continue
            parents[pid] = ppid
            if len(fields) > 3 and f"{EXEC_TOKEN_NAME}={token}" in fields[3].split():
                marked.add(pid)
    except (OSError, subprocess.TimeoutExpired):
        # Caller will still kill the original process group.
        return parents, marked
    return parents, marked


def _tracked_pids(root_pid: int, token: str, uid: int) -> Set[int]:
    parents, marked = (
        _linux_snapshot(token, uid) if sys.platform.startswith("linux")
        else _darwin_snapshot(token, uid)
    )
    family: Set[int] = {root_pid}
    while True:
        newly_found = {pid for pid, ppid in parents.items() if ppid in family}
        if newly_found.issubset(family):
            break
        family.update(newly_found)
    return (family | marked) - {os.getpid(), 0, 1}


def terminate_execution_tree(root_pid: int, token: str, *, pause_seconds: float = 0.02) -> None:
    """Stop, discover and kill same-UID descendants and token-tagged detached children.

    Non-root processes and an unpredictable 192-bit tag prevent accidental
    selection of unrelated users' processes. SIGKILL is used only on timeout.
    """
    if root_pid <= 1 or not token or len(token) < 32:
        raise ValueError("INVALID_EXECUTION_TREE_TARGET")
    uid = os.getuid()
    tracked = _tracked_pids(root_pid, token, uid)
    for pid in sorted(tracked):
        try:
            os.kill(pid, signal.SIGSTOP)
        except (ProcessLookupError, PermissionError):
            continue
    # Re-snapshot catches a child which called setsid before its parent stopped.
    time.sleep(max(0.0, min(pause_seconds, 0.05)))
    tracked.update(_tracked_pids(root_pid, token, uid))
    for pid in sorted(tracked, reverse=True):
        try:
            os.kill(pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            continue
    try:
        os.killpg(root_pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError) as exc:
        _ = exc
    # Orphaned subprocesses may change PPID; the tag survives a normal exec.
    for _ in range(3):
        remaining = _tracked_pids(root_pid, token, uid)
        remaining.discard(root_pid)
        if not remaining:
            break
        for pid in remaining:
            try:
                os.kill(pid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                continue
        time.sleep(0.015)
