"""
Process monitor stub (psutil).

Phase 5: track new processes, unsigned binaries, suspicious parents.
Do not kill processes outside an isolated lab.
"""
from __future__ import annotations

from typing import Any, Dict, List


def list_running_processes(limit: int = 25) -> List[Dict[str, Any]]:
    try:
        import psutil
    except ImportError as exc:
        raise ImportError("Install psutil: pip install psutil") from exc

    rows: List[Dict[str, Any]] = []
    for proc in psutil.process_iter(["pid", "name", "username", "exe"]):
        info = proc.info
        rows.append(
            {
                "pid": info.get("pid"),
                "name": info.get("name"),
                "username": info.get("username"),
                "exe": info.get("exe"),
            }
        )
        if len(rows) >= limit:
            break
    return rows


if __name__ == "__main__":
    for p in list_running_processes(10):
        print(p)
