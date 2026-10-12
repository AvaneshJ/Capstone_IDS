"""
SentinelAI - FastAPI Backend Server
Provides RESTful APIs and real-time WebSockets for Member 4's React.js SOC Dashboard.
"""

from __future__ import annotations
import os
import sys
import json
import asyncio
import logging
from typing import Dict, List, Any, Optional
from contextlib import asynccontextmanager

from urllib.parse import parse_qs

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Query, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, Field

# Ensure project root is in sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.orchestrator import SentinelOrchestrator
from core.live_monitor import LiveMonitor
from core.self_protection import SelfProtection, auth_enabled
from core.schemas import FlowEvent, Incident, AlertMessage
from database.db_manager import DatabaseManager
from config import security

logger = logging.getLogger("SentinelAI.API")

# Global Orchestrator instance
orchestrator: Optional[SentinelOrchestrator] = None
live_monitor: Optional[LiveMonitor] = None
self_protection: Optional[SelfProtection] = None
_event_loop: Optional[asyncio.AbstractEventLoop] = None

# Reachable without the API token: liveness probe used by the desktop app and the API docs
OPEN_PATHS = {"/", "/docs", "/redoc", "/openapi.json", "/docs/oauth2-redirect"}
DEFAULT_CORS_ORIGINS = [
    "http://localhost:5173", "http://127.0.0.1:5173",
    "http://localhost:4173", "http://127.0.0.1:4173",
    "file://", "null",
]


def cors_origins() -> List[str]:
    extra = [o.strip() for o in os.getenv("SENTINEL_CORS_ORIGINS", "").split(",") if o.strip()]
    return DEFAULT_CORS_ORIGINS + extra


class TokenAuthMiddleware:
    """Requires X-SentinelAI-Token (or ?token= for WebSockets / download links) on every non-open path."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        kind = scope["type"]
        if (
            kind not in ("http", "websocket")
            or not auth_enabled()
            or scope.get("path") in OPEN_PATHS
            or (kind == "http" and scope.get("method") == "OPTIONS")
        ):
            return await self.app(scope, receive, send)

        headers = {k.decode("latin-1").lower(): v.decode("latin-1") for k, v in scope.get("headers", [])}
        supplied = headers.get(security.TOKEN_HEADER.lower())
        if not supplied:
            supplied = (parse_qs(scope.get("query_string", b"").decode("latin-1")).get("token") or [None])[0]
        if security.tokens_equal(supplied, security.api_token()):
            return await self.app(scope, receive, send)

        logger.warning("Rejected unauthenticated %s %s", kind, scope.get("path"))
        if kind == "websocket":
            await send({"type": "websocket.close", "code": 4401})
            return
        response = JSONResponse({"detail": "Missing or invalid API token"}, status_code=401)
        await response(scope, receive, send)


class ConnectionManager:
    """Manages active WebSocket connections from React dashboard clients."""

    def __init__(self):
        self.active_connections: List[WebSocket] = []
        self._lock = asyncio.Lock()

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        async with self._lock:
            self.active_connections.append(websocket)
        logger.info("React Dashboard client connected via WebSocket. Total clients: %d", len(self.active_connections))

    async def disconnect(self, websocket: WebSocket):
        async with self._lock:
            if websocket in self.active_connections:
                self.active_connections.remove(websocket)
        logger.info("React Dashboard client disconnected. Remaining clients: %d", len(self.active_connections))

    async def broadcast_json(self, data: Dict[str, Any]):
        """Send real-time alert payload to all connected frontend clients."""
        async with self._lock:
            dead_connections = []
            for connection in self.active_connections:
                try:
                    await connection.send_json(data)
                except Exception as exc:
                    logger.debug("Failed sending WebSocket message to client: %s", exc)
                    dead_connections.append(connection)
            
            for dead in dead_connections:
                if dead in self.active_connections:
                    self.active_connections.remove(dead)


ws_manager = ConnectionManager()


def broadcast_from_thread(event_type: str, data: Dict[str, Any]) -> None:
    """Called from sensor threads: push an event to dashboard WebSockets on the server loop."""
    if _event_loop is None or _event_loop.is_closed():
        return
    asyncio.run_coroutine_threadsafe(
        ws_manager.broadcast_json({"event_type": event_type, "data": data}), _event_loop
    )


async def alert_broadcaster_worker():
    """Background task pulling alerts from AlertAgent queue and pushing to WebSockets."""
    loop = asyncio.get_event_loop()
    while True:
        try:
            if orchestrator and orchestrator.alert_agent:
                # Read from queue in threadpool to avoid blocking event loop
                alert_dict = await loop.run_in_executor(
                    None,
                    lambda: orchestrator.alert_agent.dashboard_queue.get(timeout=1.0)
                )
                if alert_dict:
                    payload = {
                        "event_type": "THREAT_ALERT",
                        "data": alert_dict
                    }
                    await ws_manager.broadcast_json(payload)
        except Exception:
            await asyncio.sleep(0.1)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifecycle manager: initializes SentinelAI Orchestrator on startup and stops cleanly on exit."""
    global orchestrator, live_monitor, self_protection, _event_loop
    logger.info("Initializing SentinelAI Multi-Agent Backend Server...")
    if auth_enabled():
        logger.info("API token required (header %s). Token file: %s", security.TOKEN_HEADER, security.token_path())
        security.api_token()
    else:
        logger.warning("SENTINEL_AUTH=0: the API is open to every local process.")
    orchestrator = SentinelOrchestrator(
        dry_run_firewall=True,
        dry_run_host_response=True,
        enable_desktop_alerts=False
    )
    orchestrator.initialize()
    _event_loop = asyncio.get_running_loop()

    # Start background WebSocket broadcaster
    broadcast_task = asyncio.create_task(alert_broadcaster_worker())

    # Real-time sensors (network capture + HIDS) feeding the same orchestrator
    self_protection = SelfProtection(orchestrator, notify=broadcast_from_thread)
    live_monitor = LiveMonitor(orchestrator, on_incident=broadcast_from_thread)
    live_monitor.watchdog = self_protection.watchdog
    live_monitor.on_tamper = self_protection.on_finding
    await asyncio.get_running_loop().run_in_executor(None, live_monitor.start)
    await asyncio.get_running_loop().run_in_executor(None, self_protection.start)
    logger.info("FastAPI Backend ready at http://localhost:8000 (Swagger docs: http://localhost:8000/docs)")

    yield

    logger.info("Shutting down SentinelAI Backend Server...")
    if self_protection:
        self_protection.stop()
    if live_monitor:
        live_monitor.stop()
    broadcast_task.cancel()
    if orchestrator:
        orchestrator.shutdown()


# Initialize FastAPI App
app = FastAPI(
    title="SentinelAI — Multi-Agent SOAR Backend API",
    description="RESTful API and Real-Time WebSocket feeds for the SentinelAI SOC Dashboard (React.js).",
    version="1.0.0",
    lifespan=lifespan
)

app.add_middleware(TokenAuthMiddleware)
# Added last so it wraps auth: 401 responses still carry CORS headers for the dashboard
app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins(),
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type", security.TOKEN_HEADER],
)


# -------------------------------------------------------------
# Request & Response Models for Swagger UI
# -------------------------------------------------------------

class FlowIngestRequest(BaseModel):
    src_ip: str = Field("192.168.1.50", description="Source/Attacker IP address")
    dst_ip: str = Field("192.168.1.10", description="Destination/Victim IP address")
    src_port: int = Field(54120, description="Source Port")
    dst_port: int = Field(80, description="Target Port")
    protocol: int = Field(6, description="IP Protocol (6=TCP, 17=UDP, 1=ICMP)")
    flow_duration: float = Field(0.15, description="Flow duration in seconds")
    tot_fwd_pkts: int = Field(4, description="Total forward packets")
    tot_bwd_pkts: int = Field(0, description="Total backward packets")
    fwd_pkt_len_mean: float = Field(24.0, description="Mean forward packet length")
    bwd_pkt_len_mean: float = Field(0.0, description="Mean backward packet length")
    flow_bytes_s: float = Field(2400.0, description="Bytes per second")
    flow_pkts_s: float = Field(140.0, description="Packets per second")
    syn_flag_count: int = Field(4, description="SYN flag count")
    ack_flag_count: int = Field(0, description="ACK flag count")
    rst_flag_count: int = Field(0, description="RST flag count")


class HostEventIngestRequest(BaseModel):
    """Phase 5: HIDS Host event ingestion payload. Sensor fields are required; ML fields are optional."""
    pid: int = Field(..., gt=0, description="Process ID observed by the sensor", examples=[5892])
    process_name: str = Field(..., min_length=1, description="Process executable name", examples=["python.exe"])
    file_path: str = Field(
        ...,
        min_length=1,
        description="File the process accessed",
        examples=["C:\\Users\\User\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Network\\Cookies"],
    )
    exe_path: Optional[str] = Field(None, description="Full executable path (used to verify identity before termination)")
    parent_name: Optional[str] = Field(None, description="Parent process name", examples=["cmd.exe"])
    cpu_percent: float = Field(0.0, description="CPU usage percent")
    memory_mb: float = Field(0.0, description="Memory in megabytes")
    file_type: Optional[str] = Field(None, description="Sensitive target category (auto-detected from path if omitted)")
    event_type: str = Field("READ", description="READ, MODIFY, CREATE, DELETE")
    label: Optional[str] = Field(None, description="Optional ML label from Member 2's model: Normal, Stealer, Ransomware, Malware")
    confidence: Optional[float] = Field(None, ge=0.0, le=1.0, description="Optional ML confidence for label")
    anomaly_score: Optional[float] = Field(None, ge=0.0, le=1.0, description="Optional ML anomaly score")



# -------------------------------------------------------------
# REST API Endpoints for React Frontend
# -------------------------------------------------------------

@app.get("/")
def root():
    """Health check and API metadata endpoint."""
    return {
        "system": "SentinelAI Multi-Agent SOAR Platform",
        "status": "ONLINE",
        "version": "1.0.0",
        "docs_url": "/docs",
        "websocket_feed": "/ws/live-stream"
    }


@app.get("/api/status")
def get_system_status():
    """
    Returns system status, individual agent health matrix, CPU/memory, and uptime.
    """
    if not orchestrator:
        raise HTTPException(status_code=503, detail="Orchestrator not initialized")
    status = orchestrator.get_system_metrics().to_dict()
    status["test_mode"] = bool(orchestrator.firewall_agent.dry_run or orchestrator.host_agent.dry_run)
    if live_monitor:
        status["live"] = live_monitor.status()
    if self_protection:
        status["self_protection"] = self_protection.status()
    return status


class HeartbeatRequest(BaseModel):
    sensor: str = Field(..., min_length=1, max_length=64, description="Sensor name, e.g. hids_live or supervisor")
    pid: Optional[int] = Field(None, description="Process ID of the sender")
    meta: Dict[str, Any] = Field(default_factory=dict)
    event: Optional[Dict[str, Any]] = Field(None, description="Optional tamper finding (kind, title, details, mitre_id)")


@app.post("/api/sensors/heartbeat")
def sensor_heartbeat(req: HeartbeatRequest):
    """Out-of-process sensors and the supervisor check in here; silence raises a CRITICAL tamper incident."""
    if not self_protection:
        raise HTTPException(status_code=503, detail="Self-protection not initialized")
    self_protection.watchdog.beat(req.sensor, pid=req.pid, **req.meta)
    if req.event:
        self_protection.on_finding({**req.event, "pid": req.event.get("pid", req.pid)})
    return {"status": "OK"}


@app.get("/api/selfprotect/status")
def get_self_protection_status():
    """Integrity manifest state, evidence-chain verification, sensor heartbeats and recent tamper events."""
    if not self_protection:
        raise HTTPException(status_code=503, detail="Self-protection not initialized")
    return self_protection.status()


@app.post("/api/selfprotect/verify")
def run_self_protection_checks():
    """Run a full integrity re-hash and evidence-chain verification now."""
    if not self_protection:
        raise HTTPException(status_code=503, detail="Self-protection not initialized")
    self_protection.check_integrity(full=True)
    self_protection.check_chain()
    return self_protection.status()


@app.post("/api/engine/stopping")
def engine_stopping():
    """Called by the desktop app before it stops the engine, so the restart isn't reported as a kill."""
    if self_protection:
        self_protection.mark_planned_stop()
    return {"status": "OK"}


@app.get("/api/live/status")
def get_live_status():
    """
    Real-time sensor status: network capture (Npcap) and HIDS process / file sensors,
    with counters for flows checked, threats found and repeats grouped.
    """
    if not live_monitor:
        raise HTTPException(status_code=503, detail="Live monitor not initialized")
    return live_monitor.status()


@app.get("/api/metrics")
def get_dashboard_kpis():
    """
    Returns high-level KPI cards and aggregated metrics for Member 4's React Dashboard:
    - total_flows_analyzed
    - total_threats_detected
    - active_firewall_blocks
    - average_threat_risk
    - attack_distribution breakdown
    - top_offenders (Top 5 adversary IPs)
    """
    if not orchestrator:
        raise HTTPException(status_code=503, detail="Orchestrator not initialized")
    return orchestrator.db_manager.get_dashboard_summary()


@app.get("/api/incidents")
def get_incidents(
    limit: int = Query(50, ge=1, le=500, description="Maximum number of incidents to return"),
    severity: Optional[str] = Query(None, description="Filter by severity: CRITICAL, HIGH, MEDIUM, LOW")
):
    """
    Returns recent incident history from SQLite database for the Incident Table view.
    """
    if not orchestrator:
        raise HTTPException(status_code=503, detail="Orchestrator not initialized")
    incidents = orchestrator.db_manager.get_recent_incidents(limit=limit, severity=severity)
    return {"count": len(incidents), "incidents": incidents}


@app.get("/api/incidents/{incident_id}")
def get_incident_detail(incident_id: str):
    """
    Returns full forensic breakdown, MITRE ATT&CK data, and GenAI SOC summary for a specific incident.
    """
    if not orchestrator:
        raise HTTPException(status_code=503, detail="Orchestrator not initialized")
    incident_row = orchestrator.db_manager.get_incident_by_id(incident_id)
    if not incident_row:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")
    
    # Parse stored raw JSON if available
    raw_json = incident_row.get("raw_json")
    if raw_json:
        try:
            return json.loads(raw_json)
        except Exception:
            pass
    return incident_row


@app.get("/api/blocks")
def get_blocked_ips():
    """
    Returns all active and historically mitigated firewall rules for the Blocked IPs table.
    """
    if not orchestrator:
        raise HTTPException(status_code=503, detail="Orchestrator not initialized")
    active_blocks = orchestrator.db_manager.get_active_blocks()
    return {"count": len(active_blocks), "blocked_ips": active_blocks}


@app.post("/api/blocks/unblock/{rule_id}")
def manual_unblock_ip(rule_id: str):
    """
    Manual unblock trigger allowing SOC analysts to lift a firewall ban directly from the React UI.
    """
    if not orchestrator:
        raise HTTPException(status_code=503, detail="Orchestrator not initialized")
    success = orchestrator.firewall_agent.unblock_ip(rule_id)
    if not success:
        raise HTTPException(status_code=400, detail=f"Failed to unblock rule {rule_id}")
    return {"status": "SUCCESS", "message": f"Firewall rule {rule_id} successfully lifted"}


@app.post("/api/flows/ingest")
async def ingest_flow_event(flow_req: FlowIngestRequest):
    """
    Ingest a single network flow event via HTTP POST.
    Runs the full multi-agent pipeline (Detection -> Threat -> Risk -> Decision -> Firewall -> Alert -> LLM).
    Broadcasts the alert immediately to all connected React WebSockets.
    """
    if not orchestrator:
        raise HTTPException(status_code=503, detail="Orchestrator not initialized")
    
    flow_dict = flow_req.model_dump()
    incident = orchestrator.process_flow(flow_dict)

    # Broadcast real-time incident event to WebSockets
    await ws_manager.broadcast_json({
        "event_type": "NEW_INCIDENT",
        "data": incident.to_dict()
    })

    return {
        "status": "PROCESSED",
        "incident_id": incident.incident_id,
        "attack_type": incident.detection.attack_type,
        "risk_score": incident.risk.score,
        "severity": incident.risk.severity.value,
        "action_taken": incident.action_plan.action_type.value,
        "firewall_rule": incident.firewall_rule.to_dict() if incident.firewall_rule else None,
        "llm_summary": incident.llm_explanation.summary if incident.llm_explanation else None
    }


@app.post("/api/host/events/ingest")
async def ingest_host_event(host_req: HostEventIngestRequest):
    """
    Phase 5: Ingest host telemetry event (from monitor.py / watcher.py or ML).
    Correlates process & sensitive file access, executes automated process kill if stealer,
    and broadcasts to WebSockets.
    """
    if not orchestrator:
        raise HTTPException(status_code=503, detail="Orchestrator not initialized")

    host_dict = host_req.model_dump(exclude_none=True)
    incident = orchestrator.process_host_event(host_dict)

    # Broadcast real-time host incident to WebSockets
    await ws_manager.broadcast_json({
        "event_type": "NEW_HOST_INCIDENT",
        "data": incident.to_dict()
    })

    return {
        "status": "PROCESSED",
        "incident_id": incident.incident_id,
        "classification": incident.classification,
        "risk_score": incident.risk_score,
        "severity": incident.severity.value,
        "soar_action": incident.soar_action.value,
        "action_status": incident.action_status,
        "mitre": f"{incident.mitre_technique_id} - {incident.mitre_technique_name}",
        "remediation_notes": incident.remediation_notes,
        "llm_summary": incident.llm_explanation.summary if incident.llm_explanation else None
    }


@app.get("/api/host/incidents")
def get_host_incidents(
    limit: int = Query(50, ge=1, le=500, description="Maximum number of host incidents to return"),
    classification: Optional[str] = Query(None, description="Filter by classification: Stealer, Normal, Ransomware")
):
    """
    Phase 5: Returns recent host incidents from SQLite database.
    """
    if not orchestrator:
        raise HTTPException(status_code=503, detail="Orchestrator not initialized")
    db = orchestrator.db_manager
    incidents = db.get_recent_host_incidents(limit=limit, classification=classification)
    followups = db.get_host_followups([i["incident_id"] for i in incidents])
    for inc in incidents:
        inc["followups"] = followups.get(inc["incident_id"], [])
    return {"count": len(incidents), "host_incidents": incidents}


class TrustRequest(BaseModel):
    scope: str = Field("auto", pattern="^(auto|publisher|file)$",
                       description="publisher = everything validly signed by this publisher, file = this exact file")


def _host_process(incident_id: str):
    from core.schemas import HostProcessInfo

    if not orchestrator:
        raise HTTPException(status_code=503, detail="Orchestrator not initialized")
    row = orchestrator.db_manager.get_host_incident(incident_id)
    if not row:
        raise HTTPException(status_code=404, detail=f"Host incident {incident_id} not found")
    try:
        proc = (json.loads(row.get("raw_json") or "{}").get("process")) or {}
    except ValueError:
        proc = {}
    return HostProcessInfo(
        pid=int(proc.get("pid") or row.get("pid") or 0),
        process_name=str(proc.get("process_name") or row.get("process_name") or "").lower(),
        parent_name=str(proc.get("parent_name") or ""),
        exe_path=str(proc.get("exe_path") or ""),
    )


def _trust_changed(action: str, details: str) -> None:
    orchestrator.db_manager.save_audit_log(agent_name="User", action=action, details=details, level="INFO")
    if live_monitor:
        live_monitor.reload_trust_rules()


@app.get("/api/trust")
def list_trusted_programs():
    """Programs the user marked as safe; their host alerts are suppressed."""
    if not orchestrator:
        raise HTTPException(status_code=503, detail="Orchestrator not initialized")
    rules = orchestrator.db_manager.get_trusted_programs()
    return {"count": len(rules), "rules": rules}


@app.delete("/api/trust/{rule_id}")
def remove_trusted_program(rule_id: int):
    if not orchestrator:
        raise HTTPException(status_code=503, detail="Orchestrator not initialized")
    if not orchestrator.db_manager.remove_trusted_program(rule_id):
        raise HTTPException(status_code=404, detail=f"Trust rule {rule_id} not found")
    _trust_changed("TRUST_REMOVED", f"rule={rule_id}")
    return {"status": "SUCCESS"}


@app.post("/api/host/incidents/{incident_id}/trust")
def trust_host_program(incident_id: str, req: TrustRequest = TrustRequest()):
    """Mark the program behind a host alert as safe (false positive) and stop alerting on it."""
    from hids import trust

    process = _host_process(incident_id)
    exe = process.exe_path
    if not exe or not os.path.isfile(exe):
        raise HTTPException(status_code=400, detail="The program's file can't be found any more, so it can't be identified safely.")

    rule, why_not = trust.rule_for(exe, req.scope)
    if rule is None:
        raise HTTPException(status_code=400, detail=why_not)

    saved = orchestrator.db_manager.add_trusted_program(rule["kind"], rule["value"], rule["label"], incident_id)
    if not saved:
        raise HTTPException(status_code=500, detail="Could not save the trust rule.")
    orchestrator.db_manager.add_host_followup(incident_id, "MARKED_SAFE", "OK", rule["label"])
    _trust_changed("TRUST_ADDED", f"{rule['kind']}={rule['value']} from {incident_id} ({exe})")
    return {"status": "SUCCESS", "rule": saved}


@app.post("/api/host/incidents/{incident_id}/terminate")
def terminate_host_program(incident_id: str):
    """Really stop the process behind a host alert, even in test mode (identity-checked against the alert)."""
    process = _host_process(incident_id)
    outcome, detail = orchestrator.host_agent.terminate_process(process)
    messages = {
        "SUCCESS": f"{process.process_name} (PID {process.pid}) was stopped.",
        "ALREADY_EXITED": f"{process.process_name} had already closed.",
        "IDENTITY_MISMATCH": f"Not stopped: PID {process.pid} now belongs to a different program ({detail}).",
        "REFUSED": f"Not stopped: {detail}.",
    }
    message = messages.get(outcome, f"Could not stop {process.process_name}: {detail}")
    action = "TERMINATED" if outcome == "SUCCESS" else f"TERMINATE_{outcome}"
    orchestrator.db_manager.add_host_followup(incident_id, action, outcome, message)
    orchestrator.db_manager.save_audit_log(
        agent_name="User", action=f"TERMINATE_PROCESS ({outcome})",
        details=f"PID={process.pid}, Process={process.process_name}, Exe={process.exe_path}, Incident={incident_id}",
        level="WARNING",
    )
    return {"status": outcome, "message": message}



@app.post("/api/reports/generate")
def generate_soc_report():
    """
    Trigger on-demand PDF SOC Executive Summary Report compilation.
    """
    if not orchestrator:
        raise HTTPException(status_code=503, detail="Orchestrator not initialized")
    pdf_path = orchestrator.report_agent.generate_soc_summary_pdf()
    filename = os.path.basename(pdf_path)
    return {
        "status": "GENERATED",
        "filename": filename,
        "download_url": f"/api/reports/download/{filename}"
    }


@app.get("/api/reports/download/{filename}")
def download_report(filename: str):
    """
    Download a compiled PDF report.
    """
    if not orchestrator:
        raise HTTPException(status_code=503, detail="Orchestrator not initialized")
    reports_dir = os.path.abspath(orchestrator.report_agent.reports_dir)
    file_path = os.path.abspath(os.path.join(reports_dir, filename))
    if os.path.dirname(file_path) != reports_dir or not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="Report file not found")
    return FileResponse(file_path, media_type="application/pdf", filename=filename)


# -------------------------------------------------------------
# WebSocket Endpoint for React Real-Time Feeds
# -------------------------------------------------------------

@app.websocket("/ws/live-stream")
async def websocket_live_stream(websocket: WebSocket):
    """
    WebSocket endpoint for React.js frontend.
    Streams live alerts, detections, and risk score updates in real time.
    """
    await ws_manager.connect(websocket)
    try:
        # Send initial connection confirmation & current KPIs
        if orchestrator:
            summary = orchestrator.db_manager.get_dashboard_summary()
            await websocket.send_json({
                "event_type": "CONNECTED",
                "message": "Connected to SentinelAI Real-Time Threat Stream",
                "kpis": summary
            })

        while True:
            # Keep connection alive and accept optional commands from React
            data = await websocket.receive_text()
            try:
                msg = json.loads(data)
                if msg.get("action") == "PING":
                    await websocket.send_json({"event_type": "PONG"})
            except Exception:
                pass
    except WebSocketDisconnect:
        await ws_manager.disconnect(websocket)
    except Exception as exc:
        logger.debug("WebSocket exception: %s", exc)
        await ws_manager.disconnect(websocket)
