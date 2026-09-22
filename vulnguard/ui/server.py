"""FastAPI backend for repository uploads and real-time VulnGuard scans."""

from __future__ import annotations

import io
import json
import logging
import shutil
import stat
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from fastapi import FastAPI, File, HTTPException, UploadFile, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from vulnguard.config import cfg
from vulnguard.ui.store import ScanStore

logger = logging.getLogger(__name__)

_MAX_UPLOAD_BYTES = 25 * 1024 * 1024
_MAX_EXTRACTED_BYTES = 50 * 1024 * 1024
_MAX_ARCHIVE_FILES = 500


def _inside(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except ValueError:
        return False


async def _read_upload(file: UploadFile) -> bytes:
    chunks = []
    total = 0
    while chunk := await file.read(1024 * 1024):
        total += len(chunk)
        if total > _MAX_UPLOAD_BYTES:
            raise HTTPException(status_code=413, detail="Upload exceeds the 25 MB limit")
        chunks.append(chunk)
    return b"".join(chunks)


def _save_upload(content: bytes, filename: str, upload_root: Path) -> tuple[str, Path, list[Path], bool]:
    """Persist a source file or safely extract a ZIP repository."""
    from vulnguard.data.parser import supported_extensions

    if len(content) > _MAX_UPLOAD_BYTES:
        raise ValueError("Upload exceeds the 25 MB limit")

    upload_id = uuid4().hex
    target_root = upload_root / upload_id
    safe_name = Path(filename).name

    if Path(safe_name).suffix.lower() in supported_extensions():
        target_root.mkdir(parents=True)
        target = target_root / safe_name
        target.write_bytes(content)
        return upload_id, target_root, [target], False

    if not safe_name.lower().endswith(".zip"):
        raise ValueError("Unsupported source file; upload Python, C/C++, Java, JavaScript, or ZIP")

    try:
        archive = zipfile.ZipFile(io.BytesIO(content))
    except zipfile.BadZipFile as exc:
        raise ValueError("The uploaded ZIP archive is invalid") from exc

    members = [member for member in archive.infolist() if not member.is_dir()]
    if len(members) > _MAX_ARCHIVE_FILES:
        raise ValueError("ZIP archive contains too many files")
    if sum(member.file_size for member in members) > _MAX_EXTRACTED_BYTES:
        raise ValueError("ZIP archive expands beyond the 50 MB limit")

    for member in members:
        mode = member.external_attr >> 16
        if stat.S_ISLNK(mode):
            raise ValueError("ZIP archive may not contain symbolic links")
        if not _inside((target_root / member.filename).resolve(), target_root):
            raise ValueError("ZIP archive contains an unsafe path")

    target_root.mkdir(parents=True)
    with archive:
        for member in members:
            destination = (target_root / member.filename).resolve()
            destination.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(member) as source, destination.open("wb") as output:
                shutil.copyfileobj(source, output)

    children = list(target_root.iterdir())
    repo_root = children[0] if len(children) == 1 and children[0].is_dir() else target_root
    from vulnguard.data.parser import iter_source_files

    source_files = sorted(iter_source_files(repo_root))
    if not source_files:
        raise ValueError("ZIP repository contains no supported source files")
    return upload_id, repo_root, source_files, True


def _scan_paths(func: dict[str, Any], upload_root: Path) -> tuple[Path, Path | None]:
    file_path = Path(str(func.get("file_path", ""))).resolve()
    if not file_path.is_file() or not _inside(file_path, upload_root):
        raise ValueError("Scan target is outside the managed upload directory")

    repo_value = str(func.get("repo_root", ""))
    if not repo_value:
        return file_path, None
    repo_root = Path(repo_value).resolve()
    if not repo_root.is_dir() or not _inside(repo_root, upload_root) or not _inside(file_path, repo_root):
        raise ValueError("Repository root is invalid")
    return file_path, repo_root


def create_app(
    db_path: str | Path | None = None,
    upload_root: str | Path | None = None,
) -> FastAPI:
    """Create and configure the dashboard API."""
    scan_store = ScanStore(db_path or cfg.project_root / "data" / "vulnguard.db")
    managed_uploads = Path(upload_root or cfg.project_root / "data" / "uploads").resolve()
    managed_uploads.mkdir(parents=True, exist_ok=True)

    app = FastAPI(
        title="VulnGuard AI Dashboard",
        version="0.2.0",
        description="Real-time vulnerability detection and remediation dashboard",
    )
    app.state.scan_store = scan_store
    app.state.upload_root = managed_uploads
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.get("/api/health")
    async def health():
        return {"status": "ok", "timestamp": datetime.now(timezone.utc).isoformat()}

    @app.get("/api/scan/status")
    async def scan_status():
        return JSONResponse({"scans": scan_store.list()})

    @app.get("/api/results/{scan_id}")
    async def get_result(scan_id: str):
        result = scan_store.get(scan_id)
        if not result:
            return JSONResponse({"error": "Scan not found"}, status_code=404)
        return JSONResponse(result)

    @app.get("/api/metrics")
    async def get_metrics():
        return JSONResponse(scan_store.metrics())

    @app.post("/upload")
    async def upload_target(file: UploadFile = File(...)):
        content = await _read_upload(file)
        try:
            upload_id, repo_root, source_files, is_repository = _save_upload(
                content, file.filename or "upload.py", managed_uploads
            )
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

        from vulnguard.data.parser import parse_file, read_source_file

        functions = []
        for source_path in source_files:
            code = read_source_file(source_path)
            relative_path = source_path.relative_to(repo_root).as_posix()
            for chunk in parse_file(str(source_path), code):
                functions.append(
                    {
                        "id": f"{relative_path}:{chunk.function_name}",
                        "name": chunk.function_name,
                        "code": chunk.raw_source,
                        "language": chunk.language,
                        "file_path": str(source_path),
                        "relative_path": relative_path,
                        "repo_root": str(repo_root) if is_repository else "",
                        "start_byte": chunk.start_byte,
                        "end_byte": chunk.end_byte,
                        "imports": chunk.imports,
                        "callees": chunk.callees,
                    }
                )
        return {
            "upload_id": upload_id,
            "repository": is_repository,
            "files_scanned": len(source_files),
            "functions": functions,
        }

    @app.websocket("/ws/scan")
    async def ws_scan(websocket: WebSocket):
        await websocket.accept()
        scan_id = uuid4().hex
        aggregate: dict[str, Any] = {"scan_id": scan_id, "pipeline_status": "STARTING"}
        try:
            func = json.loads(await websocket.receive_text())
            file_path, repo_root = _scan_paths(func, managed_uploads)
            source_bytes = file_path.read_bytes()
            start_byte = int(func.get("start_byte", -1))
            end_byte = int(func.get("end_byte", -1))
            if not (0 <= start_byte < end_byte <= len(source_bytes)):
                raise ValueError("Function byte range is invalid")
            source_code = source_bytes[start_byte:end_byte].decode("utf-8", errors="replace")
            if source_code != func.get("code"):
                raise ValueError("Function source does not match the uploaded file")
            aggregate.update(
                function_id=func.get("id", "unknown"),
                file_path=str(file_path),
                repo_root=str(repo_root or ""),
            )
            scan_store.save(scan_id, aggregate)
            await websocket.send_json(
                {
                    "type": "status",
                    "scan_id": scan_id,
                    "message": f"Starting scan for {func.get('name', 'function')}...",
                }
            )

            try:
                from vulnguard.models.risk_scorer import RiskScorer

                scorer = RiskScorer()
                triage_result = scorer.score(source_code, func.get("language", "python"))
                score = triage_result.risk_score
                threshold = scorer.optimal_threshold
                is_high_risk = score >= threshold or triage_result.bypass_reason is not None
            except Exception as exc:
                logger.warning("ML triage unavailable; routing to agents: %s", exc)
                score = 100.0
                threshold = cfg.triage.risk_threshold
                is_high_risk = True

            aggregate.update(risk_score=score, pipeline_status="TRIAGE")
            scan_store.save(scan_id, aggregate)
            await websocket.send_json(
                {
                    "type": "triage_result",
                    "scan_id": scan_id,
                    "score": round(score, 1),
                    "threshold": threshold,
                    "is_high_risk": is_high_risk,
                }
            )

            if not is_high_risk:
                aggregate.update(pipeline_status="COMPLETE", vulnerability_found=False)
                scan_store.save(scan_id, aggregate)
                await websocket.send_json(
                    {"type": "complete", "scan_id": scan_id, "message": "Low risk; agent analysis skipped."}
                )
                return

            from vulnguard.agents.graph import compile_graph
            from vulnguard.agents.state import initial_state
            from vulnguard.data.context_gatherer import gather_context

            context = gather_context(
                source_code,
                file_path=file_path,
                repo_root=repo_root or file_path.parent,
                language=func.get("language", "python"),
            )
            await websocket.send_json(
                {
                    "type": "context_result",
                    "scan_id": scan_id,
                    "imports": len(context.imports),
                    "callees": len(context.callee_signatures),
                    "warnings": context.warnings,
                    "token_count": context.token_count,
                }
            )

            state = initial_state(
                function_id=func.get("id", "unknown"),
                code=source_code,
                language=func.get("language", "python"),
                risk_score=score,
                context_bundle=context.to_dict(),
                file_path=str(file_path),
                repo_root=str(repo_root or ""),
                start_byte=start_byte,
                end_byte=end_byte,
            )
            aggregate.update(state)
            graph_app = compile_graph()
            async for step in graph_app.astream(state):
                for node_name, node_state in step.items():
                    aggregate.update(node_state)
                    scan_store.save(scan_id, aggregate)
                    await websocket.send_json(
                        {
                            "type": "agent_update",
                            "scan_id": scan_id,
                            "agent": node_name,
                            "state": node_state,
                        }
                    )

            if aggregate.get("pipeline_status") == "RED_COMPLETE" and not aggregate.get("vulnerability_found"):
                aggregate["pipeline_status"] = "COMPLETE"
            aggregate["completed_at"] = datetime.now(timezone.utc).isoformat()
            scan_store.save(scan_id, aggregate)
            await websocket.send_json({"type": "complete", "scan_id": scan_id})
        except WebSocketDisconnect:
            aggregate["pipeline_status"] = "DISCONNECTED"
            scan_store.save(scan_id, aggregate)
        except Exception as exc:
            logger.exception("Error in ws_scan")
            aggregate.update(pipeline_status="ERROR", error_logs=str(exc))
            scan_store.save(scan_id, aggregate)
            await websocket.send_json({"type": "error", "scan_id": scan_id, "message": str(exc)})

    return app
