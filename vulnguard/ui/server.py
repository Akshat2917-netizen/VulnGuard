"""
FastAPI WebSocket/SSE backend for the VulnGuard dashboard.

Provides real-time scan status, agent state transitions, and metric data.
"""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timezone
from typing import Any

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

logger = logging.getLogger(__name__)

# In-memory event store (replaced by DB in production)
_scan_results: dict[str, dict] = {}
_active_connections: list[WebSocket] = []


def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    app = FastAPI(
        title="VulnGuard AI Dashboard",
        version="0.1.0",
        description="Real-time vulnerability detection and remediation dashboard",
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # ── REST endpoints ────────────────────────────────────

    @app.get("/api/health")
    async def health():
        return {"status": "ok", "timestamp": datetime.now(timezone.utc).isoformat()}

    @app.get("/api/scan/status")
    async def scan_status():
        """Current pipeline status for all active scans."""
        return JSONResponse({"scans": _scan_results})

    @app.get("/api/results/{scan_id}")
    async def get_result(scan_id: str):
        """Get results for a specific scan."""
        result = _scan_results.get(scan_id)
        if not result:
            return JSONResponse({"error": "Scan not found"}, status_code=404)
        return JSONResponse(result)

    @app.get("/api/metrics")
    async def get_metrics():
        """Aggregate metrics across all scans."""
        total = len(_scan_results)
        vuln_found = sum(1 for r in _scan_results.values() if r.get("vulnerability_found"))
        patched = sum(1 for r in _scan_results.values() if r.get("judge_verdict") == "PASS")
        return JSONResponse({
            "total_scans": total,
            "vulnerabilities_found": vuln_found,
            "patches_validated": patched,
            "patch_rate": patched / max(vuln_found, 1),
        })

    @app.post("/upload")
    async def upload_target(file: UploadFile = File(...)):
        code = (await file.read()).decode("utf-8")
        from vulnguard.data.parser import parse_python_file
        import tempfile
        import os
        with tempfile.NamedTemporaryFile(delete=False, suffix=".py") as f:
            f.write(code.encode("utf-8"))
            temp_path = f.name
            
        try:
            chunks = parse_python_file(temp_path, code)
        finally:
            os.remove(temp_path)
            
        functions = []
        for chunk in chunks:
            functions.append({
                "id": f"{file.filename}:{chunk.function_name}",
                "name": chunk.function_name,
                "code": chunk.raw_source,
                "language": chunk.language,
                "file_path": file.filename,
                "start_byte": chunk.start_byte,
                "end_byte": chunk.end_byte,
                "imports": chunk.imports,
                "callees": chunk.callees,
            })
        return {"functions": functions}

    # ── WebSocket for real-time events ────────────────────

    @app.websocket("/ws/events")
    async def ws_events(websocket: WebSocket):
        await websocket.accept()
        _active_connections.append(websocket)
        try:
            while True:
                # Keep connection alive; events are pushed via broadcast
                data = await websocket.receive_text()
                # Client can send ping/commands
                if data == "ping":
                    await websocket.send_json({"type": "pong"})
        except WebSocketDisconnect:
            _active_connections.remove(websocket)

    @app.websocket("/ws/scan")
    async def ws_scan(websocket: WebSocket):
        await websocket.accept()
        try:
            data = await websocket.receive_text()
            func = json.loads(data)
            
            await websocket.send_json({"type": "status", "message": f"Starting scan for {func.get('name', 'function')}..."})
            
            # 1. Run ML Triage
            try:
                from vulnguard.models.risk_scorer import RiskScorer
                from vulnguard.config import cfg
                scorer = RiskScorer()
                triage_result = scorer.score(func.get("code", ""), func.get("language", "python"))
                score = triage_result.risk_score
                threshold = scorer.optimal_threshold
                is_high_risk = score >= threshold or triage_result.bypass_reason is not None
            except Exception as e:
                # Fallback if model not trained
                score = 100.0
                is_high_risk = True

            await websocket.send_json({"type": "triage_result", "score": round(score, 1), "is_high_risk": is_high_risk})
            
            # If low risk, skip agents
            if not is_high_risk:
                await websocket.send_json({"type": "status", "message": "Low risk. Skipping deep agent analysis."})
                await websocket.send_json({"type": "complete"})
                return
            
            from vulnguard.agents.graph import compile_graph
            from vulnguard.agents.state import initial_state
            
            state = initial_state(
                function_id=func.get("id", "unknown"),
                code=func.get("code", ""),
                language=func.get("language", "python"),
                risk_score=score,
                context_bundle={},
                file_path=func.get("file_path", ""),
                repo_root="",
            )
            
            graph_app = compile_graph()
            
            import asyncio
            def run_graph_sync():
                for step in graph_app.stream(state):
                    yield step
                    
            loop = asyncio.get_running_loop()
            
            # Since generator blocks, we can just run it in a thread and await its queue
            # But graph_app.astream should work if langgraph version supports it.
            # We'll use astream directly:
            async for step in graph_app.astream(state):
                for node_name, node_state in step.items():
                    await websocket.send_json({
                        "type": "agent_update",
                        "agent": node_name,
                        "state": node_state
                    })
                    
            await websocket.send_json({"type": "complete"})
            
        except WebSocketDisconnect:
            pass
        except Exception as e:
            logger.error(f"Error in ws_scan: {e}")
            await websocket.send_json({"type": "error", "message": str(e)})

    return app


async def broadcast_event(event_type: str, data: dict):
    """Push an event to all connected WebSocket clients."""
    message = json.dumps({"type": event_type, "data": data, "timestamp": datetime.now(timezone.utc).isoformat()})
    disconnected = []
    for ws in _active_connections:
        try:
            await ws.send_text(message)
        except Exception:
            disconnected.append(ws)
    for ws in disconnected:
        _active_connections.remove(ws)


def store_scan_result(scan_id: str, result: dict):
    """Store a scan result (called from the pipeline)."""
    _scan_results[scan_id] = result
