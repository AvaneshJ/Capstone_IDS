"""
SentinelAI - supervisor (mutual watchdog).

Starts the backend (python main.py server), restarts it when it dies or stops answering,
and reports every unexpected exit to the new backend as a CRITICAL tamper incident.
It also sends "supervisor" heartbeats, so the backend raises an incident if the
supervisor itself is killed.

Run from soar/ (scripts/install_service.ps1 runs this as a Windows service):
  python supervisor.py [--host 127.0.0.1] [--port 8000]
"""
from __future__ import annotations

import argparse
import os
import subprocess
import sys
import threading
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from config.heartbeat import send_heartbeat  # noqa: E402

CHECK_EVERY = 10.0
HUNG_AFTER = 6           # failed liveness checks in a row (60 s) before a forced restart
MAX_BACKOFF = 60.0
STARTUP_GRACE = 120.0


def _alive(api_base: str) -> bool:
    try:
        with urllib.request.urlopen(f"{api_base}/", timeout=5) as resp:
            return resp.status == 200
    except Exception:
        return False


def _start(host: str, port: int) -> subprocess.Popen:
    env = dict(os.environ, PYTHONUNBUFFERED="1",
               SENTINEL_PROTECTED_PIDS=",".join(filter(None, [os.environ.get("SENTINEL_PROTECTED_PIDS", ""), str(os.getpid())])))
    return subprocess.Popen(
        [sys.executable, "main.py", "server", "--host", host, "--port", str(port)],
        cwd=str(ROOT / "soar"), env=env,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )


def _report(api_base: str, finding: dict) -> None:
    deadline = time.time() + STARTUP_GRACE
    while time.time() < deadline:
        if _alive(api_base) and send_heartbeat("supervisor", api_base=api_base, event=finding):
            return
        time.sleep(3)


def supervise(host: str, port: int) -> None:
    api_base = f"http://{host}:{port}"
    backoff = 2.0
    while True:
        proc = _start(host, port)
        started = time.time()
        print(f"[supervisor] backend started (PID {proc.pid})")
        misses = 0
        reason = ""
        while True:
            code = proc.poll()
            if code is not None:
                reason = f"backend PID {proc.pid} exited with code {code}"
                break
            if _alive(api_base):
                misses = 0
                send_heartbeat("supervisor", {"backend_pid": proc.pid}, api_base=api_base)
            elif time.time() - started > STARTUP_GRACE:
                misses += 1
                if misses >= HUNG_AFTER:
                    reason = f"backend PID {proc.pid} stopped answering for {misses * CHECK_EVERY:.0f}s"
                    proc.kill()
                    break
            time.sleep(CHECK_EVERY)

        print(f"[supervisor] {reason}; restarting in {backoff:.0f}s")
        backoff = 2.0 if time.time() - started > 300 else min(backoff * 2, MAX_BACKOFF)
        time.sleep(backoff)
        finding = {
            "kind": "engine_restarted",
            "title": "SentinelAI engine was stopped and restarted by the supervisor",
            "details": reason,
            "mitre_id": "T1562.001",
            "mitre_name": "Impair Defenses: Disable or Modify Tools",
        }
        threading.Thread(target=_report, args=(api_base, finding), daemon=True).start()


def main() -> None:
    parser = argparse.ArgumentParser(description="SentinelAI supervisor: keeps the backend running")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args()
    try:
        supervise(args.host, args.port)
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
