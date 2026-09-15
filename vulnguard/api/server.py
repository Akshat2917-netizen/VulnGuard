import asyncio
import json
import logging
import time
from pathlib import Path
from typing import Any, AsyncGenerator

from fastapi import FastAPI, File, UploadFile, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from vulnguard.config import cfg
from vulnguard.models.risk_scorer import RiskScorer
from vulnguard.data.parser import parse_python_file
from vulnguard.data.context_gatherer import gather_context
from vulnguard.agents.graph import initial_state, compile_graph

logger = logging.getLogger(__name__)

app = FastAPI(title="VulnGuard API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

class UploadResponse(BaseModel):
    filename: str
    functions: list[dict[str, Any]]

# Global scorer instance
try:
    scorer = RiskScorer()
    logger.info("RiskScorer model loaded successfully for API")
except FileNotFoundError:
    logger.warning("RiskScorer model not found. API will fail to predict risk.")
    scorer = None

@app.post("/upload", response_model=UploadResponse)
async def upload_code(file: UploadFile = File(...)):
    """Upload a file, parse functions, and return them."""
    # Read file content
    content = await file.read()
    
    # Save to a temporary location to simulate repository context
    tmp_dir = Path("tmp_workspace")
    tmp_dir.mkdir(exist_ok=True)
    file_path = tmp_dir / file.filename
    file_path.write_bytes(content)
    
    # Parse functions
    chunks = parse_python_file(str(file_path), content.decode("utf-8"))
    functions = []
    for chunk in chunks:
        functions.append({
            "id": f"{file.filename}:{chunk.function_name}",
            "name": chunk.function_name,
            "language": chunk.language,
            "code": chunk.raw_source,
            "start_byte": chunk.start_byte,
            "end_byte": chunk.end_byte,
            "file_path": str(file_path.absolute()),
        })
        
    return UploadResponse(filename=file.filename, functions=functions)

@app.websocket("/ws/scan")
async def scan_websocket(websocket: WebSocket):
    await websocket.accept()
    
    try:
        # Wait for the client to send the function payload
        data = await websocket.receive_text()
        func_data = json.loads(data)
        
        func_id = func_data["id"]
        code = func_data["code"]
        language = func_data["language"]
        file_path = Path(func_data["file_path"])
        
        # 1. ML Triage
        await websocket.send_json({"type": "status", "message": "ML Triage scoring function..."})
        
        risk_score = 0.0
        if scorer:
            risk_score = scorer.predict(code, language)
        else:
            risk_score = 50.0 # Mock fallback
            
        is_high_risk = risk_score >= cfg.agent.threshold_score
        
        await websocket.send_json({
            "type": "triage_result",
            "score": round(risk_score, 2),
            "threshold": round(cfg.agent.threshold_score, 2),
            "is_high_risk": is_high_risk
        })
        
        if not is_high_risk:
            await websocket.send_json({"type": "complete", "message": "Function is low risk. No agent analysis needed."})
            return
            
        await asyncio.sleep(1) # Visual pause
        
        # 2. Gather Context
        await websocket.send_json({"type": "status", "message": "Gathering repository context..."})
        ctx = gather_context(file_path, code, language, file_path.parent)
        
        # 3. LangGraph Streaming
        await websocket.send_json({"type": "status", "message": "Launching Multi-Agent Pipeline..."})
        
        # Initialize state
        state = initial_state(
            function_id=func_id,
            code=code,
            language=language,
            risk_score=risk_score,
            context_bundle=ctx.to_dict(),
            file_path=str(file_path),
            repo_root=str(file_path.parent),
            start_byte=func_data["start_byte"],
            end_byte=func_data["end_byte"],
            max_attempts=cfg.agent.max_retry_attempts,
        )
        state["timestamps"] = {"pipeline_start": time.time()}
        
        # Compile graph and stream async
        graph_app = compile_graph()
        
        # We use astream to get node outputs as they complete
        async for output in graph_app.astream(state):
            # output is a dict with key = node_name, value = node_state
            for node_name, node_state in output.items():
                await websocket.send_json({
                    "type": "agent_update",
                    "agent": node_name,
                    "state": node_state
                })
                
        await websocket.send_json({"type": "complete", "message": "Pipeline complete."})
        
    except WebSocketDisconnect:
        logger.info("WebSocket disconnected")
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
        await websocket.send_json({"type": "error", "message": str(e)})
