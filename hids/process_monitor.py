"""
Process monitor (psutil) - Phase 5 HIDS process sensor.

Scans running processes every INTERVAL seconds (fixed rate, scan time included)
and writes process lifecycle events to hids/logs/process_events_YYYY-MM-DD.csv:

  START  a process run was first seen (identity, executable path, command line)
  STATS  resource sample for every running process, every STATS_EVERY seconds
  EXIT   a process run disappeared (lifetime and resource aggregates)
  END    a process was still running when the monitor stopped (same aggregates as EXIT)

A process run is identified by (pid, create_time), so a reused PID is a new run.
EXIT + END rows give exactly one summary row per run (the HIDS model training table).
cpu_* columns are a share of total machine CPU (0-100), not of a single core.
Runs shorter than one scan interval can be missed; catching those needs process-creation events.
Read-only: never kills or modifies processes.

Run from repo root:  python -m hids.process_monitor [--interval 2] [--stats-every 30] [--duration 0]
"""
from __future__ import annotations

import argparse
import csv
import os
import threading
import time
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

INTERVAL = 2.0
STATS_EVERY = 30.0
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
try:
    from config.paths import HIDS_LOG_DIR as _LOG_DIR

    LOG_DIR = str(_LOG_DIR)
except ImportError:  # run as a loose script without the repo root on sys.path
    LOG_DIR = os.path.join(BASE_DIR, "logs")
CMDLINE_MAX = 1000

FIELDS = [
    "timestamp", "time_iso", "event",
    "pid", "ppid", "create_time", "process_name", "parent_name", "parent_alive",
    "exe_path", "cmdline",
    "cpu_percent", "memory_mb",
    "lifetime_s", "samples", "cpu_mean", "cpu_max", "memory_max_mb",
]

RunKey = Tuple[int, float]
StaticReader = Callable[[int], Tuple[str, str]]


def list_running_processes(limit: int = 25) -> List[Dict[str, Any]]:
    """Original stub helper, kept so existing imports don't break."""
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


# -------------------------------------------------------------
# psutil collection
# -------------------------------------------------------------

_snapshot_reader: Any = None
_cpu_sampler: Any = None


def _scan_windows() -> Optional[List[Dict[str, Any]]]:
    """One NtQuerySystemInformation call for every process; None when unavailable."""
    global _snapshot_reader, _cpu_sampler
    from hids import winproc

    if _snapshot_reader is False or not winproc.available():
        return None
    try:
        if _snapshot_reader is None:
            _snapshot_reader, _cpu_sampler = winproc.SnapshotReader(), winproc.CpuSampler()
        procs = _snapshot_reader.read()
    except Exception:
        _snapshot_reader = False
        return None

    ncpu = os.cpu_count() or 1
    cpu = _cpu_sampler.sample(procs, time.monotonic())
    samples: List[Dict[str, Any]] = []
    for p in procs:
        create_time = round(p.create_time, 3)
        samples.append(
            {
                "pid": p.pid,
                "ppid": p.ppid,
                "name": p.name,
                "create_time": create_time,
                "cpu_percent": round(cpu.get((p.pid, create_time), 0.0) / ncpu, 2),
                "memory_mb": round(p.rss / (1024 * 1024), 1),
            }
        )
    return samples


def scan() -> List[Dict[str, Any]]:
    """Cheap per-scan sample of every process (one system snapshot on Windows, else one psutil pass)."""
    fast = _scan_windows()
    if fast is not None:
        return fast

    import psutil

    ncpu = psutil.cpu_count() or 1
    attrs = ["pid", "ppid", "name", "create_time", "cpu_percent", "memory_info"]
    samples: List[Dict[str, Any]] = []
    for p in psutil.process_iter(attrs, ad_value=None):
        info = p.info
        mem = info["memory_info"]
        samples.append(
            {
                "pid": info["pid"],
                "ppid": info["ppid"] or 0,
                "name": info["name"] or "",
                "create_time": round(info["create_time"] or 0.0, 3),
                "cpu_percent": round((info["cpu_percent"] or 0.0) / ncpu, 2),
                "memory_mb": round(mem.rss / (1024 * 1024), 1) if mem else 0.0,
            }
        )
    return samples


def read_static(pid: int) -> Tuple[str, str]:
    """Executable path and command line; read once per run because they never change."""
    import psutil

    try:
        p = psutil.Process(pid)
    except psutil.Error:
        return "", ""
    try:
        exe = p.exe() or ""
    except psutil.Error:
        exe = ""
    try:
        cmdline = " ".join(p.cmdline())[:CMDLINE_MAX]
    except psutil.Error:
        cmdline = ""
    return exe, cmdline


# -------------------------------------------------------------
# Lifecycle tracking (psutil-free, unit-testable)
# -------------------------------------------------------------

@dataclass
class ProcessRun:
    pid: int
    ppid: int
    create_time: float
    name: str
    parent_name: str
    parent_alive: bool
    exe_path: str
    cmdline: str
    last_seen: float
    samples: int = 1
    cpu_sum: float = 0.0
    cpu_n: int = 0
    cpu_max: Optional[float] = None
    last_cpu: Optional[float] = None
    memory_max: float = 0.0
    last_memory: float = 0.0

    def observe(self, cpu: float, memory: float, now: float) -> None:
        self.samples += 1
        self.last_seen = now
        self.cpu_sum += cpu
        self.cpu_n += 1
        self.cpu_max = cpu if self.cpu_max is None else max(self.cpu_max, cpu)
        self.last_cpu = cpu
        self.memory_max = max(self.memory_max, memory)
        self.last_memory = memory


class ProcessTracker:
    """Turns repeated scans into START / STATS / EXIT / END rows."""

    def __init__(self, stats_every: float = STATS_EVERY, exclude_pids: Iterable[int] = ()):
        self.stats_every = stats_every
        self.exclude_pids = set(exclude_pids)
        self.runs: Dict[RunKey, ProcessRun] = {}
        self._last_stats: Optional[float] = None

    def update(self, samples: List[Dict[str, Any]], now: float, read_static: StaticReader) -> List[Dict[str, Any]]:
        rows: List[Dict[str, Any]] = []
        by_pid = {s["pid"]: s for s in samples}
        seen = set()

        for s in samples:
            if s["pid"] in self.exclude_pids:
                continue
            key = (s["pid"], s["create_time"])
            seen.add(key)
            run = self.runs.get(key)
            if run is not None:
                run.observe(s["cpu_percent"], s["memory_mb"], now)
                continue

            # psutil's first cpu_percent reading for a process is always 0.0, so it is not recorded
            parent = by_pid.get(s["ppid"])
            parent_alive = (
                parent is not None
                and s["ppid"] != s["pid"]
                and parent["create_time"] <= s["create_time"]
            )
            exe, cmdline = read_static(s["pid"])
            run = ProcessRun(
                pid=s["pid"],
                ppid=s["ppid"],
                create_time=s["create_time"],
                name=s["name"],
                parent_name=parent["name"] if parent_alive else "",
                parent_alive=parent_alive,
                exe_path=exe,
                cmdline=cmdline,
                last_seen=now,
                memory_max=s["memory_mb"],
                last_memory=s["memory_mb"],
            )
            self.runs[key] = run
            rows.append(self._row(now, "START", run, memory_mb=run.last_memory))

        for key in [k for k in self.runs if k not in seen]:
            rows.append(self._summary_row(now, "EXIT", self.runs.pop(key)))

        if self._last_stats is None:
            self._last_stats = now
        elif now - self._last_stats >= self.stats_every:
            self._last_stats = now
            rows.extend(
                self._row(now, "STATS", run, cpu_percent=run.last_cpu, memory_mb=run.last_memory, with_cmdline=False)
                for run in self.runs.values()
            )
        return rows

    def finish(self, now: float) -> List[Dict[str, Any]]:
        rows = [self._summary_row(now, "END", run) for run in self.runs.values()]
        self.runs.clear()
        return rows

    def _row(
        self,
        now: float,
        event: str,
        run: ProcessRun,
        cpu_percent: Optional[float] = None,
        memory_mb: Optional[float] = None,
        with_cmdline: bool = True,
    ) -> Dict[str, Any]:
        row = dict.fromkeys(FIELDS, "")
        row.update(
            timestamp=round(now, 3),
            time_iso=datetime.fromtimestamp(now).isoformat(timespec="milliseconds"),
            event=event,
            pid=run.pid,
            ppid=run.ppid,
            create_time=run.create_time,
            process_name=run.name,
            parent_name=run.parent_name,
            parent_alive=int(run.parent_alive),
            exe_path=run.exe_path,
            cmdline=run.cmdline if with_cmdline else "",
        )
        if cpu_percent is not None:
            row["cpu_percent"] = cpu_percent
        if memory_mb is not None:
            row["memory_mb"] = memory_mb
        return row

    def _summary_row(self, now: float, event: str, run: ProcessRun) -> Dict[str, Any]:
        row = self._row(now, event, run)
        if run.create_time > 0:
            row["lifetime_s"] = max(0.0,round(run.last_seen - run.create_time, 1))
        row["samples"] = run.samples
        if run.cpu_n:
            row["cpu_mean"] = round(run.cpu_sum / run.cpu_n, 2)
            row["cpu_max"] = run.cpu_max
        row["memory_max_mb"] = run.memory_max
        return row


# -------------------------------------------------------------
# Output
# -------------------------------------------------------------

class DailyCsvWriter:
    """Appends rows to <prefix>_YYYY-MM-DD.csv, switching files at midnight."""

    def __init__(self, log_dir: str = LOG_DIR, prefix: str = "process_events", fields: List[str] = FIELDS):
        self.log_dir = log_dir
        self.prefix = prefix
        self.fields = fields
        self.path: Optional[str] = None
        self._file = None
        self._writer: Optional[csv.DictWriter] = None

    def write(self, rows: List[Dict[str, Any]], now: float) -> None:
        path = os.path.join(self.log_dir, f"{self.prefix}_{datetime.fromtimestamp(now):%Y-%m-%d}.csv")
        if path != self.path or self._file is None:
            self._open(path)
        if rows:
            self._writer.writerows(rows)
            self._file.flush()

    def _open(self, path: str) -> None:
        self.close()
        os.makedirs(self.log_dir, exist_ok=True)
        new_file = not os.path.exists(path) or os.path.getsize(path) == 0
        self._file = open(path, "a", newline="", encoding="utf-8")
        self._writer = csv.DictWriter(self._file, fieldnames=self.fields)
        if new_file:
            self._writer.writeheader()
        self.path = path

    def close(self) -> None:
        if self._file:
            self._file.close()
        self._file = None
        self._writer = None


# -------------------------------------------------------------
# Main loop
# -------------------------------------------------------------

def _emit(on_rows: Optional[Callable[[List[Dict[str, Any]]], None]], rows: List[Dict[str, Any]]) -> None:
    if on_rows and rows:
        on_rows(rows)


def run(
    interval: float = INTERVAL,
    stats_every: float = STATS_EVERY,
    log_dir: str = LOG_DIR,
    duration: float = 0.0,
    on_rows: Optional[Callable[[List[Dict[str, Any]]], None]] = None,
    stop_event: Optional[threading.Event] = None,
) -> None:
    tracker = ProcessTracker(stats_every=stats_every, exclude_pids={os.getpid()})
    out = DailyCsvWriter(log_dir)
    scans = overruns = 0
    start = next_tick = time.monotonic()

    print(f"Monitoring processes every {interval}s (stats every {stats_every}s) -> {log_dir}")
    print("Press Ctrl+C to stop.")
    try:
        while True:
            samples=scan()
            now = time.time()
            rows = tracker.update(samples, now, read_static)
            out.write(rows, now)
            _emit(on_rows, rows)
            scans += 1
            if duration and time.monotonic() - start >= duration:
                break
            if stop_event is not None and stop_event.is_set():
                break
            next_tick += interval
            delay = next_tick - time.monotonic()
            if delay > 0:
                if stop_event is not None:
                    stop_event.wait(delay)
                else:
                    time.sleep(delay)
            else:
                overruns += 1
                next_tick = time.monotonic()
    except KeyboardInterrupt:
        pass
    finally:
        now = time.time()
        rows = tracker.finish(now)
        out.write(rows, now)
        _emit(on_rows, rows)
        out.close()
        print(f"\nStopped after {scans} scans ({overruns} took longer than {interval}s). Log: {out.path}")


def main() -> None:
    parser = argparse.ArgumentParser(description="SentinelAI HIDS process sensor")
    parser.add_argument("--interval", type=float, default=INTERVAL, help="Seconds between scans (default 2)")
    parser.add_argument("--stats-every", type=float, default=STATS_EVERY, help="Seconds between STATS rows (default 30)")
    parser.add_argument("--log-dir", default=LOG_DIR, help="Output folder (default hids/logs)")
    parser.add_argument("--duration", type=float, default=0.0, help="Stop after N seconds (0 = run until Ctrl+C)")
    parser.add_argument("--soar", action="store_true",
                        help="Score each finished run and send anomalous ones to SOAR (dry-run)")
    parser.add_argument("--live-response", action="store_true",
                        help="With --soar, allow SOAR to terminate a process. Default is dry-run.")
    args = parser.parse_args()
    on_rows = None
    bridge = None
    if args.soar:
        from hids.live import HostBridge
        bridge = HostBridge(dry_run=not args.live_response)
        on_rows = bridge.on_process_rows
        print(f"SOAR host response: {'LIVE' if args.live_response else 'dry-run'}")
    try:
        run(interval=args.interval, stats_every=args.stats_every, log_dir=args.log_dir,
            duration=args.duration, on_rows=on_rows)
    finally:
        if bridge is not None:
            bridge.close()


if __name__ == "__main__":
    main()
