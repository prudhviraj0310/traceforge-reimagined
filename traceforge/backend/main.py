"""
TRACEFORGE FastAPI Application
Orchestration layer connecting Next.js dashboard, FalkorDB Graph Engine, and FastMCP Agent.
"""

import asyncio
import json
import logging
import os
from typing import Dict, Any, Optional
from fastapi import FastAPI, HTTPException, Header, Query, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from traceforge.engine.db import db_engine
from traceforge.engine.seed import seed_enterprise_environment
from traceforge.agent.investigator import investigator

logger = logging.getLogger("traceforge.api")
logging.basicConfig(level=logging.INFO)

ENVIRONMENT = os.getenv("TRACEFORGE_ENV", "development").lower()
API_KEY = os.getenv("TRACEFORGE_API_KEY")
ADMIN_KEY = os.getenv("TRACEFORGE_ADMIN_KEY")
if ENVIRONMENT == "production" and (not API_KEY or not ADMIN_KEY):
    raise RuntimeError("TRACEFORGE_API_KEY and TRACEFORGE_ADMIN_KEY are required in production.")
API_KEY = API_KEY or "traceforge-local-demo-key"
ADMIN_KEY = ADMIN_KEY or API_KEY

def require_api_key(x_traceforge_key: Optional[str] = Header(default=None)) -> str:
    if not x_traceforge_key or x_traceforge_key not in {API_KEY, ADMIN_KEY}:
        raise HTTPException(status_code=401, detail="Valid X-Traceforge-Key header required.")
    return x_traceforge_key

def require_admin_key(x_traceforge_key: Optional[str] = Header(default=None)) -> str:
    if not x_traceforge_key or x_traceforge_key != ADMIN_KEY:
        raise HTTPException(status_code=403, detail="Administrator authorization required.")
    return x_traceforge_key

from contextlib import asynccontextmanager

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Ensure seed data exists on startup
    if len(db_engine.node_store) == 0:
        seed_enterprise_environment()
    yield

app = FastAPI(
    title="TRACEFORGE Threat Intelligence API",
    version="1.0.0",
    description="Autonomous AI Threat Investigation & Incident Response Engine powered by FalkorDB & MCP",
    lifespan=lifespan
)

# Enable CORS for Next.js frontend with explicit origin security
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:8000",
        "http://127.0.0.1:8000"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory investigation results cache
investigation_cache: Dict[str, Dict[str, Any]] = {}

class IngestAlertRequest(BaseModel):
    name: str
    rule: str
    severity: str
    target_workload_id: str
    description: str

class InvestigateRequest(BaseModel):
    alert_id: str
    auto_remediate: bool = False

@app.get("/api/health", dependencies=[Depends(require_api_key)])
def get_health():
    return {
        "status": "healthy",
        "service": "TRACEFORGE Core API",
        "is_connected_to_live_falkordb": db_engine.is_connected,
        "falkordb_host": db_engine.host,
        "falkordb_port": db_engine.port,
        "graph_name": db_engine.graph_name,
        "nodes_loaded": len(db_engine.node_store),
        "relationships_loaded": len(db_engine.edge_store)
    }

@app.get("/api/graph", dependencies=[Depends(require_api_key)])
def get_graph():
    """Returns full graph formatted for Cytoscape.js canvas."""
    return db_engine.get_full_graph_visualization_data()

@app.get("/api/alerts", dependencies=[Depends(require_api_key)])
def list_alerts():
    """Returns all security alerts."""
    alerts = []
    for nid, data in db_engine.node_store.items():
        if data.get("label") == "Alert":
            alerts.append(data)
    # Sort critical first
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    alerts.sort(key=lambda x: severity_order.get(x.get("severity", "LOW"), 4))
    return alerts

@app.post("/api/seed", dependencies=[Depends(require_admin_key)])
def reseed_environment():
    """Resets and re-seeds the enterprise test environment in FalkorDB."""
    res = seed_enterprise_environment()
    investigation_cache.clear()
    return res

@app.post("/api/alerts", dependencies=[Depends(require_admin_key)])
def ingest_alert(req: IngestAlertRequest):
    """Ingest a new security alert dynamically."""
    import uuid
    workload = db_engine.node_store.get(req.target_workload_id)
    if not workload or workload.get("label") != "Workload":
        raise HTTPException(status_code=422, detail="target_workload_id must reference an existing Workload.")
    if req.severity.upper() not in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}:
        raise HTTPException(status_code=422, detail="severity must be CRITICAL, HIGH, MEDIUM, or LOW.")
    alert_id = f"ALERT-{uuid.uuid4().hex[:6].upper()}"
    props = {
        "rule": req.rule,
        "severity": req.severity,
        "target_workload_id": req.target_workload_id,
        "description": req.description,
        "status": "unresolved"
    }
    db_engine.add_node(alert_id, "Alert", req.name, props)
    db_engine.add_edge(alert_id, req.target_workload_id, "DETECTED_ON", {"severity": req.severity})
    return {"alert_id": alert_id, "status": "ingested"}

@app.post("/api/investigate", dependencies=[Depends(require_api_key)])
def run_investigation(req: InvestigateRequest, x_traceforge_key: str = Header(default="")):
    """Executes the autonomous agent investigation on an alert."""
    if req.auto_remediate and x_traceforge_key != ADMIN_KEY:
        raise HTTPException(status_code=403, detail="Administrator authorization required for remediation.")
    try:
        result = investigator.investigate(req.alert_id, auto_remediate=req.auto_remediate)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    investigation_cache[req.alert_id] = result
    return result

@app.get("/api/investigate/{alert_id}", dependencies=[Depends(require_api_key)])
def get_investigation_result(alert_id: str):
    """Retrieves cached investigation results."""
    if alert_id in investigation_cache:
        return investigation_cache[alert_id]
    raise HTTPException(status_code=404, detail="Investigation has not been run for this alert.")

@app.get("/api/investigate/stream/{alert_id}")
async def stream_investigation(
    alert_id: str,
    access_key: Optional[str] = Query(default=None, alias="key"),
):
    """
    Server-Sent Events (SSE) streaming endpoint:
    Streams each agent reasoning step, Cypher execution, and remediation in real-time!
    """
    if access_key not in {API_KEY, ADMIN_KEY}:
        raise HTTPException(status_code=401, detail="Valid reader key required for investigation stream.")

    async def event_generator():
        queue = asyncio.Queue()

        def on_event(ev):
            queue.put_nowait(ev)

        # Run investigator in background task
        loop = asyncio.get_event_loop()
        future = loop.run_in_executor(
            None,
            lambda: investigator.investigate(
                alert_id,
                auto_remediate=access_key == ADMIN_KEY,
                event_callback=on_event,
            )
        )

        while not future.done() or not queue.empty():
            try:
                ev = await asyncio.wait_for(queue.get(), timeout=0.3)
                yield f"data: {json.dumps(ev)}\n\n"
            except asyncio.TimeoutError:
                await asyncio.sleep(0.1)

        final_res = await future
        investigation_cache[alert_id] = final_res
        yield f"data: {json.dumps({'step': 'STREAM_END', 'status': 'completed', 'result': final_res})}\n\n"

    return StreamingResponse(event_generator(), media_type="text/event-stream")

@app.get("/api/blast-radius/{node_id}", dependencies=[Depends(require_api_key)])
def get_node_blast_radius(node_id: str):
    """Computes blast radius for a given node."""
    return db_engine.calculate_blast_radius(node_id)

class CypherQueryRequest(BaseModel):
    query: str
    params: Optional[Dict[str, Any]] = None

@app.post("/api/query", dependencies=[Depends(require_api_key)])
def execute_cypher(req: CypherQueryRequest):
    """Executes a validated read-only OpenCypher query."""
    try:
        results = db_engine.execute_query(req.query, req.params)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"query": req.query, "count": len(results), "results": results}

@app.get("/api/centrality", dependencies=[Depends(require_api_key)])
def get_centrality(top_k: int = 10):
    """Returns top bridge nodes ranked by Brandes betweenness centrality."""
    return db_engine.calculate_betweenness_centrality(top_k)
