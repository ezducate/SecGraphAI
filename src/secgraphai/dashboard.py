"""Authenticated, local-by-default dashboard API with defensive middleware."""

import asyncio
import hmac
import time
import uuid
from collections import defaultdict, deque
from collections.abc import Awaitable, Callable
from importlib.resources import files
from pathlib import Path
from typing import Any

from secgraphai.config import Mode
from secgraphai.core import Report, Verdict
from secgraphai.intelligence import OWASP_PROFILES, CoverageState, coverage_matrix
from secgraphai.lifecycle import regression_bundle
from secgraphai.policy import Effect, PolicyEngine, Rule
from secgraphai.scanner import SecGraph
from secgraphai.self_security import run_self_audit
from secgraphai.storage import Storage


class EventBroker:
    """Bounded in-process fan-out for authenticated dashboard live updates."""

    def __init__(self, *, queue_size: int = 100) -> None:
        self.queue_size = queue_size
        self.subscribers: set[asyncio.Queue[dict[str, Any]]] = set()

    def subscribe(self) -> asyncio.Queue[dict[str, Any]]:
        queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=self.queue_size)
        self.subscribers.add(queue)
        return queue

    def unsubscribe(self, queue: asyncio.Queue[dict[str, Any]]) -> None:
        self.subscribers.discard(queue)

    async def publish(self, event: dict[str, Any]) -> None:
        for queue in tuple(self.subscribers):
            if queue.full():
                queue.get_nowait()
            queue.put_nowait(event)


def create_app(
    *,
    database: str | Path,
    token: str,
    bind_host: str = "127.0.0.1",
    max_body_bytes: int = 2_000_000,
    rate_limit: int = 120,
    scan_runner: Callable[[dict[str, Any]], Awaitable[Report]] | None = None,
):
    if not token or len(token) < 16:
        raise ValueError("dashboard token must contain at least 16 characters")
    if bind_host not in {"127.0.0.1", "localhost", "::1"}:
        raise ValueError("remote dashboard binding requires an external authenticated proxy")
    from fastapi import (
        BackgroundTasks,
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
    broker = EventBroker()
    app.state.event_broker = broker
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
        return storage.list_documents("targets")

    @app.post("/api/v1/targets", dependencies=[Depends(authenticate)])
    def add_target(target: dict[str, Any]) -> dict[str, Any]:
        if not target.get("id") or not target.get("type"):
            raise HTTPException(status_code=422, detail="target requires id and type")
        storage.put_document("targets", str(target["id"]), target)
        return target

    @app.get("/api/v1/scans", dependencies=[Depends(authenticate)])
    def list_scans(limit: int = 100, offset: int = 0) -> list[dict[str, Any]]:
        return [item.model_dump(mode="json") for item in storage.list(limit=limit, offset=offset)]

    @app.post("/api/v1/scans", dependencies=[Depends(authenticate)])
    async def save_scan(document: dict[str, Any]) -> dict[str, str]:
        report = Report.model_validate(document)
        storage.save(report)
        await broker.publish(
            {"type": "scan.completed", "scan_id": report.scan_id, "summary": report.summary()}
        )
        return {"scan_id": report.scan_id}

    async def run_configured_scan(request: dict[str, Any]) -> Report:
        target_id = str(request.get("target_id", ""))
        target = storage.get_document("targets", target_id)
        if target is None:
            raise ValueError("target not found")
        target_config = target.get("configuration", target)
        if not isinstance(target_config, dict):
            raise ValueError("target configuration must be an object")
        raw_modules = request.get("modules", ["prompt-injection", "agent"])
        if not isinstance(raw_modules, list) or not all(
            isinstance(item, str) for item in raw_modules
        ):
            raise ValueError("modules must be a list of strings")
        return await SecGraph(
            target=target_config,
            mode=Mode(str(request.get("mode", Mode.SAFE.value))),
        ).scan(
            modules=raw_modules,
            strategy="adaptive",
            attack_budget=min(1000, max(1, int(request.get("attack_budget", 20)))),
        )

    async def execute_job(job_id: str, request: dict[str, Any]) -> None:
        running = {"id": job_id, "state": "RUNNING", "target_id": request.get("target_id")}
        storage.put_document("jobs", job_id, running)
        await broker.publish({"type": "scan.running", **running})
        try:
            report = await (scan_runner or run_configured_scan)(request)
            storage.save(report)
            complete = {
                "id": job_id,
                "state": "COMPLETED",
                "target_id": request.get("target_id"),
                "scan_id": report.scan_id,
                "summary": report.summary(),
            }
            storage.put_document("jobs", job_id, complete)
            await broker.publish({"type": "scan.completed", **complete})
        except Exception as exc:
            failed = {
                "id": job_id,
                "state": "FAILED",
                "target_id": request.get("target_id"),
                "error": type(exc).__name__,
            }
            storage.put_document("jobs", job_id, failed)
            await broker.publish({"type": "scan.failed", **failed})

    @app.post("/api/v1/scan-jobs", dependencies=[Depends(authenticate)], status_code=202)
    async def start_scan_job(
        document: dict[str, Any], background_tasks: BackgroundTasks
    ) -> dict[str, str]:
        target_id = document.get("target_id")
        if not isinstance(target_id, str) or not target_id:
            raise HTTPException(status_code=422, detail="scan job requires target_id")
        if storage.get_document("targets", target_id) is None:
            raise HTTPException(status_code=404, detail="target not found")
        job_id = f"SG-JOB-{uuid.uuid4().hex[:12].upper()}"
        queued = {"id": job_id, "state": "QUEUED", "target_id": target_id}
        storage.put_document("jobs", job_id, queued)
        await broker.publish({"type": "scan.queued", **queued})
        background_tasks.add_task(execute_job, job_id, document)
        return {"job_id": job_id, "state": "QUEUED"}

    @app.get("/api/v1/scan-jobs/{job_id}", dependencies=[Depends(authenticate)])
    def scan_job(job_id: str) -> dict[str, Any]:
        job = storage.get_document("jobs", job_id)
        if job is None:
            raise HTTPException(status_code=404, detail="not found")
        return job

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
        stored = storage.attack_paths()
        return stored or list(graph().get("risk_paths", []))

    @app.get("/api/v1/policies", dependencies=[Depends(authenticate)])
    def list_policies() -> list[dict[str, Any]]:
        return storage.list_documents("policies")

    @app.post("/api/v1/policies", dependencies=[Depends(authenticate)])
    def add_policy(document: dict[str, Any]) -> dict[str, Any]:
        if not document.get("id") or not isinstance(document.get("rules", []), list):
            raise HTTPException(status_code=422, detail="policy requires id and rules")
        storage.put_document("policies", str(document["id"]), document)
        return document

    @app.post("/api/v1/policies/test", dependencies=[Depends(authenticate)])
    def test_policy(document: dict[str, Any]) -> dict[str, Any]:
        rules = [
            Rule(
                str(item["id"]),
                Effect(item["effect"]),
                dict(item.get("match", {})),
                str(item.get("reason", "")),
                int(item.get("priority", 0)),
                dict(item.get("options", {})),
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
    async def create_report(document: dict[str, Any]) -> dict[str, str]:
        return await save_scan(document)

    @app.get("/api/v1/self-audit", dependencies=[Depends(authenticate)])
    @app.post("/api/v1/self-audit", dependencies=[Depends(authenticate)])
    def self_audit() -> dict[str, object]:
        return run_self_audit(database=database).as_dict()

    @app.get("/api/v1/vulnerabilities", dependencies=[Depends(authenticate)])
    def vulnerabilities() -> list[dict[str, Any]]:
        result: dict[str, dict[str, Any]] = {}
        for report in storage.list(limit=1000):
            for finding_item in report.findings:
                for cve_id in finding_item.cve_ids:
                    result.setdefault(
                        cve_id,
                        {
                            "id": cve_id,
                            "finding_ids": [],
                            "known_exploited": finding_item.known_exploited,
                        },
                    )["finding_ids"].append(finding_item.id)
        return list(result.values())

    @app.get("/api/v1/owasp-coverage", dependencies=[Depends(authenticate)])
    def owasp_coverage(profile: str = "llm-2026") -> dict[str, object]:
        if profile not in OWASP_PROFILES:
            raise HTTPException(status_code=404, detail="unknown OWASP profile")
        state_by_verdict = {
            Verdict.VERIFIED_VIOLATION: CoverageState.VERIFIED_FINDING,
            Verdict.LIKELY_VIOLATION: CoverageState.PARTIAL,
            Verdict.BLOCKED_BY_CONTROL: CoverageState.VERIFIED_CONTROL,
            Verdict.TEST_ERROR: CoverageState.TEST_ERROR,
            Verdict.PASS: CoverageState.TESTED,
            Verdict.INCONCLUSIVE: CoverageState.PARTIAL,
            Verdict.OUT_OF_SCOPE: CoverageState.NOT_APPLICABLE,
        }
        observed = [
            (category.split(":", 1)[0], state_by_verdict[finding_item.verdict])
            for report in storage.list(limit=1000)
            for finding_item in report.findings
            for categories in finding_item.mappings.values()
            for category in categories
        ]
        return coverage_matrix(profile, observed)

    @app.websocket("/api/v1/events")
    async def live_events(websocket: WebSocket) -> None:
        authorization = websocket.headers.get("authorization", "").removeprefix("Bearer ")
        protocols = [
            item.strip() for item in websocket.headers.get("sec-websocket-protocol", "").split(",")
        ]
        protocol_token = (
            protocols[1] if len(protocols) == 2 and protocols[0] == "secgraphai" else ""
        )
        supplied = authorization or protocol_token
        if not hmac.compare_digest(supplied, token):
            await websocket.close(code=4401)
            return
        await websocket.accept(subprotocol="secgraphai" if protocol_token else None)
        queue = broker.subscribe()
        try:
            while True:
                try:
                    event = await asyncio.wait_for(queue.get(), timeout=15)
                except TimeoutError:
                    event = {"type": "heartbeat", "time": time.time()}
                await websocket.send_json(event)
        except (WebSocketDisconnect, RuntimeError):
            pass
        finally:
            broker.unsubscribe(queue)

    return app
