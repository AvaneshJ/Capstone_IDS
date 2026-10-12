"""
Heartbeat client for sensors running outside the backend process (hids.live, the supervisor).
Beats go to POST /api/sensors/heartbeat with the per-install API token; the backend raises a
CRITICAL tamper incident when a sensor that was beating goes quiet.
"""
from __future__ import annotations

import json
import os
import threading
import urllib.error
import urllib.request
from typing import Any, Dict, Optional

from config import security

API_BASE = os.environ.get("SENTINEL_API_BASE", "http://127.0.0.1:8000")
INTERVAL = 20.0


def send_heartbeat(name: str, meta: Optional[Dict[str, Any]] = None, api_base: str = API_BASE,
                   timeout: float = 3.0, event: Optional[Dict[str, Any]] = None) -> bool:
    body = {"sensor": name, "pid": os.getpid(), "meta": meta or {}}
    if event:
        body["event"] = event
    req = urllib.request.Request(
        f"{api_base}/api/sensors/heartbeat",
        data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json", security.TOKEN_HEADER: security.api_token()},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status == 200
    except (urllib.error.URLError, OSError, ValueError):
        return False


class HeartbeatSender:
    def __init__(self, name: str, interval: float = INTERVAL, api_base: str = API_BASE) -> None:
        self.name = name
        self.interval = interval
        self.api_base = api_base
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def start(self) -> "HeartbeatSender":
        self._thread = threading.Thread(target=self._loop, name=f"heartbeat-{self.name}", daemon=True)
        self._thread.start()
        return self

    def _loop(self) -> None:
        while not self._stop.is_set():
            send_heartbeat(self.name, api_base=self.api_base)
            self._stop.wait(self.interval)

    def stop(self) -> None:
        self._stop.set()
