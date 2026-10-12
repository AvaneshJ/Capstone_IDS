"""
SentinelAI - sensor heartbeat watchdog.

Each sensor either beats (timestamp refreshed whenever it does work) or exposes a probe
(e.g. "is my thread alive"). A sensor is silenced when its probe fails or no beat arrived
within its timeout. Each silence is reported once; recovery is reported too.

In-process sensors (live monitor threads) register here directly. Out-of-process sensors
and the supervisor POST /api/sensors/heartbeat and are registered on their first beat.
"""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

DEFAULT_TIMEOUT = 90.0

Probe = Callable[[], bool]


@dataclass
class SensorRecord:
    name: str
    timeout: Optional[float]
    probe: Optional[Probe] = None
    last_seen: float = field(default_factory=time.time)
    registered_at: float = field(default_factory=time.time)
    silenced: bool = False
    silenced_since: Optional[float] = None
    reason: str = ""
    beats: int = 0
    meta: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self, now: float) -> Dict[str, Any]:
        return {
            "name": self.name,
            "state": "silenced" if self.silenced else "alive",
            "last_seen": self.last_seen,
            "seconds_since": round(now - self.last_seen, 1),
            "timeout": self.timeout,
            "silenced_since": self.silenced_since,
            "reason": self.reason,
            "beats": self.beats,
            "meta": self.meta,
        }


class SensorWatchdog:
    def __init__(self, default_timeout: float = DEFAULT_TIMEOUT) -> None:
        self.default_timeout = default_timeout
        self._sensors: Dict[str, SensorRecord] = {}
        self._lock = threading.Lock()

    def register(self, name: str, probe: Optional[Probe] = None, timeout: Optional[float] = -1.0) -> None:
        """timeout=None: probe only (sensor that is legitimately quiet). -1: default timeout."""
        with self._lock:
            self._sensors[name] = SensorRecord(
                name=name,
                timeout=self.default_timeout if timeout == -1.0 else timeout,
                probe=probe,
            )

    def unregister(self, name: str) -> None:
        with self._lock:
            self._sensors.pop(name, None)

    def beat(self, name: str, now: Optional[float] = None, **meta: Any) -> None:
        now = time.time() if now is None else now
        with self._lock:
            rec = self._sensors.get(name)
            if rec is None:
                rec = self._sensors[name] = SensorRecord(name=name, timeout=self.default_timeout)
            rec.last_seen = now
            rec.beats += 1
            if meta:
                rec.meta.update(meta)

    def check(self, now: Optional[float] = None) -> Tuple[List[SensorRecord], List[SensorRecord]]:
        """(newly_silenced, recovered) since the last check."""
        now = time.time() if now is None else now
        silenced, recovered = [], []
        with self._lock:
            records = list(self._sensors.values())
        for rec in records:
            reason = ""
            if rec.probe is not None:
                try:
                    if not rec.probe():
                        reason = "stopped running"
                except Exception as exc:
                    reason = f"probe failed: {exc}"
            if not reason and rec.timeout is not None and now - rec.last_seen > rec.timeout:
                reason = f"no heartbeat for {now - rec.last_seen:.0f}s (limit {rec.timeout:.0f}s)"
            if reason and not rec.silenced:
                rec.silenced, rec.silenced_since, rec.reason = True, now, reason
                silenced.append(rec)
            elif not reason and rec.silenced:
                rec.silenced, rec.silenced_since, rec.reason = False, None, ""
                recovered.append(rec)
        return silenced, recovered

    def status(self, now: Optional[float] = None) -> Dict[str, Any]:
        now = time.time() if now is None else now
        with self._lock:
            sensors = {name: rec.to_dict(now) for name, rec in self._sensors.items()}
        return {
            "sensors": sensors,
            "silenced": sorted(n for n, s in sensors.items() if s["state"] == "silenced"),
        }
