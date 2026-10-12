"""
One-call process snapshot for Windows (NtQuerySystemInformation / SystemProcessInformation).

psutil reads each process on its own. For processes it can't open (services, protected
and elevated processes when the engine isn't elevated) it falls back to a full system
snapshot per process, so a psutil scan of ~300 processes costs ~300 snapshots. This module
takes one snapshot per scan and returns pid, ppid, name, create time, CPU time and working set
for every process, without opening any process handle.
"""
from __future__ import annotations

import ctypes
import os
import struct
from typing import Dict, List, NamedTuple, Optional

SYSTEM_PROCESS_INFORMATION = 5
STATUS_INFO_LENGTH_MISMATCH = 0xC0000004
FILETIME_UNIX_EPOCH = 116444736000000000

# SYSTEM_PROCESS_INFORMATION field offsets (64-bit Windows)
_NEXT_OFFSET = 0
_CREATE_TIME = 32
_USER_TIME = 40
_KERNEL_TIME = 48
_IMAGE_NAME_LEN = 56
_IMAGE_NAME_BUF = 64
_PID = 80
_PPID = 88
_WORKING_SET = 144

_SPECIAL_NAMES = {0: "System Idle Process", 4: "System"}


class ProcSnapshot(NamedTuple):
    pid: int
    ppid: int
    name: str
    create_time: float  # unix seconds
    cpu_time: float  # user + kernel seconds
    rss: int  # working set bytes


def available() -> bool:
    return os.name == "nt" and struct.calcsize("P") == 8


class SnapshotReader:
    """Reuses one buffer between scans; grows it when the process list gets longer."""

    def __init__(self, initial_size: int = 512 * 1024) -> None:
        self._ntdll = ctypes.WinDLL("ntdll")
        self._query = self._ntdll.NtQuerySystemInformation
        self._query.restype = ctypes.c_ulong
        self._query.argtypes = [ctypes.c_ulong, ctypes.c_void_p, ctypes.c_ulong, ctypes.POINTER(ctypes.c_ulong)]
        self._buf = ctypes.create_string_buffer(initial_size)

    def _fill(self) -> int:
        needed = ctypes.c_ulong(0)
        for _ in range(8):
            status = self._query(SYSTEM_PROCESS_INFORMATION, self._buf, len(self._buf), ctypes.byref(needed))
            if status == 0:
                return needed.value or len(self._buf)
            if status != STATUS_INFO_LENGTH_MISMATCH:
                raise OSError(f"NtQuerySystemInformation failed: 0x{status:08x}")
            self._buf = ctypes.create_string_buffer(max(needed.value, len(self._buf)) + 64 * 1024)
        raise OSError("NtQuerySystemInformation: process list kept growing")

    def read(self) -> List[ProcSnapshot]:
        self._fill()
        raw = self._buf.raw
        base = ctypes.addressof(self._buf)
        out: List[ProcSnapshot] = []
        offset = 0
        while True:
            next_off = struct.unpack_from("<I", raw, offset + _NEXT_OFFSET)[0]
            create, user, kernel = struct.unpack_from("<qqq", raw, offset + _CREATE_TIME)
            name_len = struct.unpack_from("<H", raw, offset + _IMAGE_NAME_LEN)[0]
            name_ptr = struct.unpack_from("<Q", raw, offset + _IMAGE_NAME_BUF)[0]
            pid, ppid = struct.unpack_from("<QQ", raw, offset + _PID)
            rss = struct.unpack_from("<Q", raw, offset + _WORKING_SET)[0]

            name = ""
            if name_ptr and name_len:
                start = name_ptr - base
                if 0 <= start and start + name_len <= len(raw):
                    name = raw[start:start + name_len].decode("utf-16-le", errors="replace")
            name = name or _SPECIAL_NAMES.get(pid, "")
            create_time = (create - FILETIME_UNIX_EPOCH) / 1e7 if create > FILETIME_UNIX_EPOCH else 0.0
            out.append(ProcSnapshot(pid, ppid, name, create_time, (user + kernel) / 1e7, rss))

            if not next_off:
                break
            offset += next_off
        return out


class CpuSampler:
    """psutil-style per-process cpu_percent (100 = one core) from two snapshots."""

    def __init__(self) -> None:
        self._prev: Dict[tuple, float] = {}
        self._prev_at: Optional[float] = None

    def sample(self, procs: List[ProcSnapshot], now: float) -> Dict[tuple, float]:
        elapsed = (now - self._prev_at) if self._prev_at is not None else 0.0
        current: Dict[tuple, float] = {}
        percent: Dict[tuple, float] = {}
        for p in procs:
            key = (p.pid, round(p.create_time, 3))
            current[key] = p.cpu_time
            prev = self._prev.get(key)
            # Like psutil, the first reading of a process is 0.0.
            percent[key] = max(0.0, (p.cpu_time - prev) / elapsed * 100.0) if prev is not None and elapsed > 0 else 0.0
        self._prev, self._prev_at = current, now
        return percent
