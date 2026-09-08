"""Authenticated, local-by-default dashboard API with defensive middleware."""

from __future__ import annotations

import hmac
import time
from collections import defaultdict, deque
from importlib.resources import files
from pathlib import Path
from typing import Any

from secgraphai.core import Report
from secgraphai.lifecycle import regression_bundle
from secgraphai.policy import Effect, PolicyEngine, Rule
from secgraphai.self_security import run_self_audit
from secgraphai.storage import Storage


def create_app(
    *,
    database: str | Path,
    token: str,
    bind_host: str = "127.0.0.1",
    max_body_bytes: int = 2_000_000,
    rate_limit: int = 120,
):
    if not token or len(token) < 16:
        raise ValueError("dashboard token must contain at least 16 characters")
    if bind_host not in {"127.0.0.1", "localhost", "::1"}:
        raise ValueError("remote dashboard binding requires an external authenticated proxy")
    from fastapi import (
        Depends,
        FastAPI,
        Header,
        HTTPException,
        Request,
        WebSocket,
        WebSocketDisconnect,
    )
    from fastapi.responses import FileResponse
    from fastapi.staticfiles import StaticFiles

    app = FastAPI(title="SecGraphAI", docs_url=None, redoc_url=None)
    storage = Storage(database)
    targets: list[dict[str, Any]] = []
    policies: list[dict[str, Any]] = []
    request_times: dict[str, deque[float]] = defaultdict(deque)
    static_root = files("secgraphai").joinpath("static")
    app.mount("/static", StaticFiles(directory=str(static_root)), name="static")

    def authenticate(authorization: str = Header(default="")) -> None:
        supplied = authorization.removeprefix("Bearer ")
        if not hmac.compare_digest(supplied, token):
            raise HTTPException(status_code=401, detail="unauthorized")

    @app.middleware("http")
    async def secure_response(request: Request, call_next):
        content_length = request.headers.get("content-length")
        if content_length and int(content_length) > max_body_bytes:
            from fastapi.responses import JSONResponse

            return JSONResponse({"detail": "request too large"}, status_code=413)
        key = request.client.host if request.client else "local"
        now = time.monotonic()
        recent = request_times[key]
        while recent and now - recent[0] > 60:
            recent.popleft()
        if len(recent) >= rate_limit:
            from fastapi.responses import JSONResponse

            return JSONResponse({"detail": "rate limit exceeded"}, status_code=429)
        recent.append(now)
        response = await call_next(request)
        response.headers.update(
            {
                "Content-Security-Policy": "default-src 'self'; object-src 'none'; frame-ancestors 'none'",
                "X-Content-Type-Options": "nosniff",
                "X-Frame-Options": "DENY",
                "Referrer-Policy": "no-referrer",
                "Cache-Control": "no-store",
            }
        )
        return response

    @app.get("/health")
    @app.get("/api/v1/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/", include_in_schema=False)
    def dashboard_index():
        return FileResponse(str(static_root.joinpath("index.html")))

    @app.get("/api/v1/targets", dependencies=[Depends(authenticate)])
    def list_targets() -> list[dict[str, Any]]:
        return targets

    @app.post("/api/v1/targets", dependencies=[Depends(authenticate)])
    def add_target(target: dict[str, Any]) -> dict[str, Any]:
        if not target.get("id") or not target.get("type"):
            raise HTTPException(status_code=422, detail="target requires id and type")
        targets.append(target)
        return target

    @app.get("/api/v1/scans", dependencies=[Depends(authenticate)])
    def list_scans(limit: int = 100, offset: int = 0) -> list[dict[str, Any]]:
        return [item.model_dump(mode="json") for item in storage.list(limit=limit, offset=offset)]

    @app.post("/api/v1/scans", dependencies=[Depends(authenticate)])
    def save_scan(document: dict[str, Any]) -> dict[str, str]:
        report = Report.model_validate(document)
        storage.save(report)
        return {"scan_id": report.scan_id}

    @app.get("/api/v1/scans/{scan_id}", dependencies=[Depends(authenticate)])
    def scan(scan_id: str) -> dict[str, Any]:
        report = storage.get(scan_id)
        if report is None:
            raise HTTPException(status_code=404, detail="not found")
        return report.model_dump(mode="json")

    @app.get("/api/v1/findings", dependencies=[Depends(authenticate)])
    def findings() -> list[dict[str, Any]]:
        return [
            finding.model_dump(mode="json")
            for report in storage.list(limit=1000)
            for finding in report.findings
        ]

    @app.get("/api/v1/findings/{finding_id}", dependencies=[Depends(authenticate)])
    def finding(finding_id: str) -> dict[str, Any]:
        item = storage.finding(finding_id)
        if item is None:
            raise HTTPException(status_code=404, detail="not found")
        return item.model_dump(mode="json")

    @app.post("/api/v1/findings/{finding_id}/replay", dependencies=[Depends(authenticate)])
    def replay(finding_id: str) -> dict[str, str]:
        item = storage.finding(finding_id)
        if item is None:
            raise HTTPException(status_code=404, detail="not found")
        return regression_bundle(item)

    @app.get("/api/v1/graph", dependencies=[Depends(authenticate)])
    def graph() -> dict[str, Any]:
        reports = storage.list(limit=1)
        return reports[0].graph if reports else {"nodes": [], "edges": []}

    @app.get("/api/v1/attack-paths", dependencies=[Depends(authenticate)])
    def attack_paths() -> list[Any]:
        return list(graph().get("risk_paths", []))

    @app.get("/api/v1/policies", dependencies=[Depends(authenticate)])
    def list_policies() -> list[dict[str, Any]]:
        return policies

    @app.post("/api/v1/policies/test", dependencies=[Depends(authenticate)])
    def test_policy(document: dict[str, Any]) -> dict[str, Any]:
        rules = [
            Rule(
                str(item["id"]),
                Effect(item["effect"]),
                dict(item.get("match", {})),
                str(item.get("reason", "")),
                int(item.get("priority", 0)),
            )
            for item in document.get("rules", [])
        ]
        summary = PolicyEngine(rules, shadow=True).summarize(document.get("events", []))
        return {
            "total": summary.total,
            "would_block": summary.would_block,
            "would_require_approval": summary.would_require_approval,
            "allowed": summary.allowed,
            "decisions": [item.__dict__ for item in summary.decisions],
        }

    @app.get("/api/v1/reports", dependencies=[Depends(authenticate)])
    def reports() -> list[dict[str, Any]]:
        return [
            {"scan_id": item.scan_id, "summary": item.summary()}
            for item in storage.list(limit=1000)
        ]

    @app.post("/api/v1/reports", dependencies=[Depends(authenticate)])
    def create_report(document: dict[str, Any]) -> dict[str, str]:
        return save_scan(document)

    @app.get("/api/v1/self-audit", dependencies=[Depends(authenticate)])
    @app.post("/api/v1/self-audit", dependencies=[Depends(authenticate)])
    def self_audit() -> dict[str, object]:
        return run_self_audit(database=database).as_dict()

    @app.websocket("/api/v1/events")
    async def events(websocket: WebSocket) -> None:
        if not hmac.compare_digest(websocket.query_params.get("token", ""), token):
            await websocket.close(code=4401)
            return
        await websocket.accept()
        try:
            while True:
                await websocket.send_json({"type": "heartbeat", "time": time.time()})
                await websocket.receive_text()
        except WebSocketDisconnect:
            pass

    return app
