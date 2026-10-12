"""
Connect the HIDS sensors to SOAR.

Two paths, because a stealer is often gone before its process EXIT row exists:

  * File sensor, immediately: a non-owner read of a credential file is sent to
    SOAR with no ML label, so the host agent uses its own rule and can alert
    while the process is still alive.
  * Process sensor, on EXIT/END: the Isolation Forest scores the finished run.
    Only anomalous runs are sent, with label / confidence / anomaly_score.
    If that process already touched a watched file, the file path is attached.

Response stays in dry-run unless --live-response is passed. Dry-run records the
incident and does not terminate the process.

Run both sensors in one process (file sensor only starts when this window is
elevated), from repo root:

  python -m hids.live
  python -m hids.live --duration 600

Or attach one sensor:

  python -m hids.process_monitor --soar
  python -m hids.file_monitor --mode audit --soar
"""
from __future__ import annotations

import argparse
import os
import sys
import threading
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Tuple

from hids.file_monitor import to_host_event
from hids.predict import IsolationForestPredictor, Prediction, explain_run
from hids.tamper_monitor import protected_pids, row_finding

RunKey = Tuple[int, float]


def _run_key(pid: Any, create_time: Any) -> Optional[RunKey]:
    try:
        pid_i = int(pid)
        ct = round(float(create_time), 3)
    except (TypeError, ValueError):
        return None
    if pid_i <= 0:
        return None
    return pid_i, ct


def _owner_flag(row: Mapping[str, Any]) -> Optional[int]:
    owner = row.get("accessor_is_owner")
    if owner in (0, "0", False):
        return 0
    if owner in (1, "1", True):
        return 1
    return None


class HostBridge:
    """Scores process runs and forwards host events to SentinelOrchestrator."""

    def __init__(
        self,
        predictor: Optional[IsolationForestPredictor] = None,
        orchestrator: Any = None,
        dry_run: bool = True,
        db_path: Optional[str] = None,
    ):
        self.predictor = predictor if predictor is not None else IsolationForestPredictor()
        self.dry_run = dry_run
        self.db_path = db_path
        self._orchestrator = orchestrator
        self._files: Dict[RunKey, Dict[str, Any]] = {}
        self._files_by_pid: Dict[int, Dict[str, Any]] = {}
        self._alerted_files: set = set()
        self.on_tamper: Callable[[Dict[str, Any]], Any] = self._print_tamper
        self._protected_pids = protected_pids()
        # Optional: runs it returns False for are not scored unless they touched a watched file.
        self.score_filter: Optional[Callable[[Mapping[str, Any]], bool]] = None

    @staticmethod
    def _print_tamper(finding: Dict[str, Any]) -> None:
        print(f"[hids] TAMPER {finding['title']}: {finding['details']}")

    def _check_tamper(self, row: Mapping[str, Any]) -> None:
        finding = row_finding(row, self._protected_pids, trusted_parents=self._protected_pids)
        if finding is not None:
            try:
                self.on_tamper(finding)
            except Exception as exc:
                print(f"[hids] tamper report failed: {exc}")

    def orchestrator(self) -> Any:
        if self._orchestrator is None:
            soar_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "soar")
            if soar_dir not in sys.path:
                sys.path.insert(0, soar_dir)
            from core.orchestrator import SentinelOrchestrator

            self._orchestrator = SentinelOrchestrator(
                db_path=self.db_path,
                dry_run_host_response=self.dry_run,
                dry_run_firewall=True,
                enable_desktop_alerts=False,
                enable_console_alerts=False,
            )
            self._orchestrator.initialize()
            # Stay offline: the briefing falls back to the local expert text.
            self._orchestrator.llm_agent.gemini_api_key = None
            self._orchestrator.llm_agent.ollama_endpoint = "http://127.0.0.1:9"
        return self._orchestrator

    def close(self) -> None:
        if self._orchestrator is not None and hasattr(self._orchestrator, "shutdown"):
            self._orchestrator.shutdown()

    def on_file_rows(self, rows: Iterable[Mapping[str, Any]]) -> List[Any]:
        incidents = []
        for row in rows:
            self._remember_file(row)
            if not self._should_alert_file(row):
                continue
            event = to_host_event(row)
            if event is None:
                continue
            event["source"] = "hids_file_sensor"
            incidents.append(self._send(event))
        return incidents

    def on_process_rows(self, rows: Iterable[Mapping[str, Any]]) -> List[Any]:
        finished = []
        for row in rows:
            event = str(row.get("event", "")).upper()
            if event == "START":
                self._check_tamper(row)
                continue
            if event not in ("EXIT", "END"):
                continue
            if self.score_filter is not None and not self._file_for_run(row) and not self.score_filter(row):
                continue
            finished.append(row)
        if not finished:
            return []

        # Scoring costs ~40 ms per call (400 trees walked in Python) whatever the row count.
        predict_many = getattr(self.predictor, "predict_many", None)
        predictions = predict_many(finished) if predict_many else [self.predictor.predict(r) for r in finished]
        incidents = []
        for row, prediction in zip(finished, predictions):
            if prediction.is_anomalous:
                incidents.append(self._send(self.process_event(row, prediction)))
        return incidents

    def process_event(self, run: Mapping[str, Any], prediction: Prediction) -> Dict[str, Any]:
        """EXIT/END row + model scores -> the host-event dict SOAR accepts."""
        event: Dict[str, Any] = {
            "pid": int(run.get("pid") or 0),
            "process_name": run.get("process_name") or "",
            "exe_path": run.get("exe_path") or "",
            "parent_name": run.get("parent_name") or "",
            "cpu_percent": float(run.get("cpu_mean") or run.get("cpu_percent") or 0.0),
            "memory_mb": float(run.get("memory_max_mb") or run.get("memory_mb") or 0.0),
            "label": prediction.label,
            "confidence": round(prediction.confidence, 4),
            "anomaly_score": round(prediction.anomaly_score, 4),
            "decision_score": prediction.decision_score,
            "threshold": prediction.threshold,
            "reasons": explain_run(run, prediction.features),
            "source": "hids_isolation_forest",
        }
        file_row = self._file_for_run(run)
        if file_row:
            event["file_path"] = file_row.get("file_path") or ""
            event["file_type"] = file_row.get("file_type") or ""
            event["event_type"] = file_row.get("event_type") or "READ"
        return event

    def _remember_file(self, row: Mapping[str, Any]) -> None:
        pid = row.get("pid")
        try:
            pid_i = int(pid)
        except (TypeError, ValueError):
            return
        if pid_i <= 0:
            return
        self._files_by_pid[pid_i] = dict(row)
        key = _run_key(pid_i, row.get("create_time"))
        if key is not None:
            self._files[key] = dict(row)

    def _file_for_run(self, run: Mapping[str, Any]) -> Optional[Dict[str, Any]]:
        key = _run_key(run.get("pid"), run.get("create_time"))
        if key is not None and key in self._files:
            return self._files[key]
        try:
            return self._files_by_pid.get(int(run.get("pid")))
        except (TypeError, ValueError):
            return None

    def _should_alert_file(self, row: Mapping[str, Any]) -> bool:
        """Immediate path: someone other than the browser touched a watched file."""
        if str(row.get("source", "")).lower() == "poll":
            return False
        if not row.get("pid"):
            return False
        if _owner_flag(row) == 1:
            return False
        if str(row.get("event_type", "")).upper() not in ("READ", "MODIFY", "DELETE", "CREATE"):
            return False
        key = _run_key(row.get("pid"), row.get("create_time")) or (int(row["pid"]), 0.0)
        if key in self._alerted_files:
            return False
        self._alerted_files.add(key)
        return True

    def _send(self, event: Dict[str, Any]) -> Any:
        try:
            incident = self.orchestrator().process_host_event(event)
        except Exception as exc:
            print(f"[hids] SOAR ingest failed: {exc}")
            return None
        action = getattr(getattr(incident, "soar_action", None), "value", "")
        print(
            f"[hids] {event.get('source')} pid {event.get('pid')} "
            f"{event.get('process_name')} -> {incident.classification} "
            f"anomaly {incident.anomaly_score:.2f} action {action}"
        )
        return incident


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the HIDS sensors and forward alerts to SOAR (dry-run)")
    parser.add_argument("--duration", type=float, default=0.0, help="Stop after N seconds (0 = until Ctrl+C)")
    parser.add_argument("--live-response", action="store_true",
                        help="Allow SOAR to terminate a process. Default is dry-run.")
    args = parser.parse_args()

    from hids.file_monitor import is_admin
    from hids.file_monitor import run as run_files
    from hids.process_monitor import run as run_processes

    from config.heartbeat import HeartbeatSender

    bridge = HostBridge(dry_run=not args.live_response)
    print(f"SOAR host response: {'LIVE' if args.live_response else 'dry-run'}")
    heartbeat = HeartbeatSender("hids_live").start()
    file_thread: Optional[threading.Thread] = None
    if is_admin():
        file_thread = threading.Thread(
            target=run_files,
            kwargs={"mode": "audit", "duration": args.duration, "on_rows": bridge.on_file_rows},
            name="hids-file-sensor",
            daemon=True,
        )
        file_thread.start()
    else:
        print("Not elevated: file-read alerts are off. Run this window as Administrator to include them.")
        print("Process EXIT/END scores will still be sent.")
    try:
        run_processes(duration=args.duration, on_rows=bridge.on_process_rows)
    finally:
        heartbeat.stop()
        bridge.close()
        if file_thread is not None:
            file_thread.join(timeout=2.0)


if __name__ == "__main__":
    main()
