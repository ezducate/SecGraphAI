"""Provider-independent OpenAI-compatible model adapter."""

from __future__ import annotations

import os
from typing import Any, Sequence

import httpx


class ModelError(RuntimeError):
    pass


class Model:
    def __init__(self, *, base_url: str, model: str, api_key: str | None = None,
                 api_key_env: str | None = None, timeout: float = 30,
                 max_response_bytes: int = 2_000_000) -> None:
        self.base_url = base_url.rstrip("/")
        self.model = model
        self._api_key = api_key
        self.api_key_env = api_key_env
        self.timeout = httpx.Timeout(timeout, connect=min(timeout, 10))
        self.max_response_bytes = max_response_bytes

    def _key(self) -> str | None:
        return self._api_key or (os.environ.get(self.api_key_env) if self.api_key_env else None)

    async def complete(self, messages: Sequence[dict[str, str]], **parameters: Any) -> str:
        headers = {"Accept": "application/json"}
        if key := self._key():
            headers["Authorization"] = f"Bearer {key}"
        payload = {"model": self.model, "messages": list(messages), **parameters}
        try:
            async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=False) as client:
                async with client.stream("POST", f"{self.base_url}/chat/completions",
                                         json=payload, headers=headers) as response:
                    response.raise_for_status()
                    data = await response.aread()
                    if len(data) > self.max_response_bytes:
                        raise ModelError("model response exceeds configured size limit")
        except httpx.HTTPError as exc:
            raise ModelError(f"model request failed: {type(exc).__name__}") from exc
        try:
            parsed = httpx.Response(200, content=data).json()
            return str(parsed["choices"][0]["message"]["content"])
        except (KeyError, IndexError, TypeError, ValueError) as exc:
            raise ModelError("invalid OpenAI-compatible response") from exc

    def __repr__(self) -> str:
        return f"Model(base_url={self.base_url!r}, model={self.model!r}, api_key='***')"

