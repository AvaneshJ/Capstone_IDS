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

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Query, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, Field

# Ensure project root is in sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.orchestrator import SentinelOrchestrator
from core.schemas import FlowEvent, Incident, AlertMessage
from database.db_manager import DatabaseManager

logger = logging.getLogger("SentinelAI.API")

# Global Orchestrator instance
orchestrator: Optional[SentinelOrchestrator] = None


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
    global orchestrator
    logger.info("Initializing SentinelAI Multi-Agent Backend Server...")
    orchestrator = SentinelOrchestrator(
        dry_run_firewall=True,
        enable_desktop_alerts=False
    )
    orchestrator.initialize()

    # Start background WebSocket broadcaster
    broadcast_task = asyncio.create_task(alert_broadcaster_worker())
    logger.info("FastAPI Backend ready at http://localhost:8000 (Swagger docs: http://localhost:8000/docs)")

    yield

    logger.info("Shutting down SentinelAI Backend Server...")
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

# Enable CORS for React (Vite: 5173, CRA/Next: 3000, etc.)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
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
    metrics = orchestrator.get_system_metrics()
    return metrics.to_dict()


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
    file_path = os.path.join(orchestrator.report_agent.reports_dir, filename)
    if not os.path.exists(file_path):
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
