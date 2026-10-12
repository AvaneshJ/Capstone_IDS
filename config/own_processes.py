"""
SentinelAI's own process tree, so sensors never flag (and SOAR never kills) SentinelAI itself.

Roots are this process plus its SentinelAI ancestors (venv launcher, Electron main, supervisor,
NSSM), found by walking up while the parent is one of ROOT_NAMES. A process is "own" when it
or one of its ancestors is a root: Electron renderer/GPU/utility processes, the backend, the
supervisor and anything they launch.

SENTINEL_PROTECTED_PIDS=1,2 adds extra roots (the supervisor sets it for the backend).
"""
from __future__ import annotations

import os
import sys
from functools import lru_cache
from typing import Dict, FrozenSet, Mapping, Optional, Tuple

INSTALL_ROOT = os.path.normcase(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
ROOT_NAMES = frozenset({"python.exe", "pythonw.exe", "electron.exe", "sentinelai.exe",
                        "sentinel-backend.exe", "nssm.exe"})
# Folders of these are SentinelAI's own (python.exe may be a shared system interpreter, so not that)
APP_NAMES = frozenset({"electron.exe", "sentinelai.exe", "sentinel-backend.exe"})
MAX_DEPTH = 12


def _proc_info(pid: int) -> Optional[Tuple[int, str, str, float]]:
    """(ppid, name, exe, create_time) of a live process, or None."""
    try:
        import psutil

        p = psutil.Process(pid)
        with p.oneshot():
            try:
                exe = p.exe() or ""
            except (psutil.Error, OSError):
                exe = ""
            return p.ppid(), (p.name() or "").lower(), exe, p.create_time()
    except Exception:
        return None


def _ppid(pid: int) -> Optional[int]:
    try:
        import psutil

        return psutil.Process(pid).ppid()
    except Exception:
        return None


def _env_pids() -> FrozenSet[int]:
    raw = os.environ.get("SENTINEL_PROTECTED_PIDS", "")
    return frozenset(int(p) for p in raw.split(",") if p.strip().isdigit())


@lru_cache(maxsize=1)
def _roots_and_dirs() -> Tuple[FrozenSet[int], Tuple[str, ...]]:
    roots = {os.getpid()}
    dirs = {os.path.normcase(os.path.dirname(os.path.abspath(sys.executable)))} if getattr(sys, "frozen", False) else set()
    pid = os.getpid()
    info = _proc_info(pid)
    for _ in range(6):
        if info is None or not info[0] or info[0] == pid:
            break
        parent = _proc_info(info[0])
        if parent is None or parent[1] not in ROOT_NAMES or parent[3] > info[3] + 1:
            break
        pid, info = info[0], parent
        roots.add(pid)
        if parent[2] and parent[1] in APP_NAMES:
            dirs.add(os.path.normcase(os.path.dirname(parent[2])))
    return frozenset(roots), tuple(sorted(dirs))


def root_pids() -> FrozenSet[int]:
    return _roots_and_dirs()[0] | _env_pids()


def trusted_dirs() -> Tuple[str, ...]:
    return _roots_and_dirs()[1] + (
        os.path.join(INSTALL_ROOT, ".venv") + os.sep,
        os.path.join(INSTALL_ROOT, "dashboard", "node_modules", "electron", "dist") + os.sep,
    )


def is_own_binary(exe_path: str) -> bool:
    """SentinelAI's own python / Electron / packaged backend executables."""
    if not exe_path:
        return False
    path = os.path.normcase(os.path.abspath(exe_path))
    return any(path.startswith(d if d.endswith(os.sep) else d + os.sep) for d in trusted_dirs())


def is_own_process(pid: object, parents: Optional[Mapping[int, int]] = None) -> bool:
    """True if pid is a SentinelAI root or descends from one. `parents` (pid -> ppid) covers exited processes."""
    try:
        cur = int(pid)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return False
    roots = root_pids()
    seen = set()
    child = None
    for _ in range(MAX_DEPTH):
        if cur in roots:
            return child is None or not _started_after(cur, child)
        if cur <= 4 or cur in seen:
            return False
        seen.add(cur)
        nxt = parents.get(cur) if parents else None
        if nxt is None:
            nxt = _ppid(cur)
        if not nxt:
            return False
        child, cur = cur, nxt
    return False


def _started_after(parent: int, child: int) -> bool:
    """Parent PID reused by a process younger than the child: not really its parent."""
    try:
        import psutil

        return psutil.Process(parent).create_time() > psutil.Process(child).create_time() + 1
    except Exception:
        return False


class ParentMap:
    """pid -> ppid learned from process-sensor rows, so ancestry works after a process exits."""

    LIMIT = 50_000

    def __init__(self) -> None:
        self.parents: Dict[int, int] = {}

    def observe(self, row: Mapping[str, object]) -> None:
        try:
            pid, ppid = int(row.get("pid") or 0), int(row.get("ppid") or 0)  # type: ignore[arg-type]
        except (TypeError, ValueError):
            return
        if pid > 0 and ppid > 0 and pid != ppid:
            if len(self.parents) >= self.LIMIT:
                self.parents.clear()
            self.parents[pid] = ppid

    def is_own(self, pid: object) -> bool:
        return is_own_process(pid, self.parents)
