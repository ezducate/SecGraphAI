"""Optional authenticated, local-by-default dashboard service."""

from __future__ import annotations

import hmac
from pathlib import Path

from secgraphai.storage import Storage


def create_app(*, database: str | Path, token: str, bind_host: str = "127.0.0.1"):
    if not token or len(token) < 16:
        raise ValueError("dashboard token must contain at least 16 characters")
    if bind_host not in {"127.0.0.1", "localhost", "::1"}:
        raise ValueError("remote dashboard binding is disabled")
    from fastapi import Depends, FastAPI, Header, HTTPException

    app = FastAPI(title="SecGraphAI", docs_url=None, redoc_url=None)
    storage = Storage(database)

    def authenticate(authorization: str = Header(default="")) -> None:
        supplied = authorization.removeprefix("Bearer ")
        if not hmac.compare_digest(supplied, token):
            raise HTTPException(status_code=401, detail="unauthorized")

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/api/scans/{scan_id}", dependencies=[Depends(authenticate)])
    def scan(scan_id: str) -> dict[str, object]:
        report = storage.get(scan_id)
        if report is None:
            raise HTTPException(status_code=404, detail="not found")
        return report.model_dump(mode="json")

    return app
