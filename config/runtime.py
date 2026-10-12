"""
SentinelAI - runtime resource limits for the background engine.

Call apply_runtime_limits() before numpy / pandas / sklearn / xgboost are imported:

  * Native thread pools (OpenBLAS, OpenMP, MKL) are capped at one thread. The engine scores
    one flow or one process run at a time, so extra threads only add wake-ups, spin-waiting
    and per-thread buffers (OpenBLAS commits ~30 MB per core at import).
  * The process runs at below-normal priority so the user's foreground apps always win.

Environment:
  SENTINEL_ECO=1               eco mode: slower process scans, Windows power throttling
  SENTINEL_PRIORITY=normal     keep normal priority (default: below_normal)
  SENTINEL_NATIVE_THREADS=N    threads for numpy / sklearn / xgboost (default 1)
"""
from __future__ import annotations

import logging
import os

logger = logging.getLogger("SentinelAI.Runtime")

_THREAD_VARS = ("OMP_NUM_THREADS", "OPENBLAS_NUM_THREADS", "MKL_NUM_THREADS", "NUMEXPR_NUM_THREADS")

# Process sensor scan interval (seconds). Runs shorter than this can be missed by the sensor.
PROCESS_SCAN_INTERVAL = 2.0
ECO_PROCESS_SCAN_INTERVAL = 5.0


def eco_mode() -> bool:
    return os.getenv("SENTINEL_ECO", "").strip().lower() in ("1", "true", "yes", "on")


def native_threads() -> int:
    try:
        return max(1, int(os.getenv("SENTINEL_NATIVE_THREADS", "1")))
    except ValueError:
        return 1


def process_scan_interval() -> float:
    return ECO_PROCESS_SCAN_INTERVAL if eco_mode() else PROCESS_SCAN_INTERVAL


def limit_native_threads() -> None:
    threads = str(native_threads())
    for var in _THREAD_VARS:
        os.environ.setdefault(var, threads)
    os.environ.setdefault("OMP_WAIT_POLICY", "PASSIVE")


def lower_priority() -> None:
    if os.getenv("SENTINEL_PRIORITY", "below_normal").strip().lower() == "normal":
        return
    try:
        import psutil

        proc = psutil.Process()
        if os.name == "nt":
            proc.nice(psutil.BELOW_NORMAL_PRIORITY_CLASS)
        else:
            proc.nice(10)
    except Exception as exc:
        logger.debug("Could not lower process priority: %s", exc)


def enable_power_throttling() -> None:
    """Windows 'efficiency mode' (EcoQoS): the scheduler prefers efficient cores / lower clocks."""
    if os.name != "nt":
        return
    try:
        import ctypes
        from ctypes import wintypes

        class _PowerThrottling(ctypes.Structure):
            _fields_ = [("Version", wintypes.ULONG), ("ControlMask", wintypes.ULONG), ("StateMask", wintypes.ULONG)]

        process_power_throttling = 4
        execution_speed = 0x1
        state = _PowerThrottling(1, execution_speed, execution_speed)
        kernel32 = ctypes.windll.kernel32
        kernel32.SetProcessInformation(
            kernel32.GetCurrentProcess(), process_power_throttling, ctypes.byref(state), ctypes.sizeof(state)
        )
    except Exception as exc:
        logger.debug("Could not enable power throttling: %s", exc)


def apply_runtime_limits() -> None:
    limit_native_threads()
    lower_priority()
    if eco_mode():
        enable_power_throttling()
