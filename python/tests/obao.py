"""Unit-test support for the OpenBao modules: an httpx mock router fed by recorded fixtures.

``tests/fixtures/<function>.<case>.json`` are real responses recorded from
``openbao/openbao:2.7.2`` (secrets replaced by ``<redacted>``).
"""

from __future__ import annotations

import dataclasses
import json
from collections import defaultdict, deque
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlsplit

import httpx

import grow_openbao as sdk
from _support import fast_retry

FIXTURES = Path(__file__).parent / "fixtures"
BASE = "http://bao.test"
TOKEN = "s.unit-test-root-token"


def fixture(name: str) -> dict[str, Any]:
    """The recorded exchange ``{request, response}`` of ``fixtures/<name>.json``."""
    data: dict[str, Any] = json.loads((FIXTURES / f"{name}.json").read_text(encoding="utf-8"))
    return data


@dataclasses.dataclass
class Reply:
    status: int = 200
    body: Any = None
    headers: dict[str, str] = dataclasses.field(default_factory=dict)
    error: Exception | None = None


def fx(name: str) -> Reply:
    """A :class:`Reply` from a recorded fixture."""
    resp = fixture(name)["response"]
    headers = {}
    for line in resp.get("headers") or []:
        key, _, value = line.partition(":")
        headers[key.strip()] = value.strip()
    return Reply(resp["status"], resp.get("body"), headers)


def ok(data: Any = None, **envelope: Any) -> Reply:
    """A 200 envelope with ``data`` (and extra envelope fields)."""
    body = {"request_id": "r", "lease_id": "", "renewable": False, "lease_duration": 0}
    body.update({"data": data, "wrap_info": None, "warnings": None, "auth": None})
    body.update(envelope)
    return Reply(200, body)


def err(status: int, *messages: str, headers: dict[str, str] | None = None) -> Reply:
    return Reply(status, {"errors": list(messages)}, headers or {})


NO_CONTENT = Reply(204, None)


@dataclasses.dataclass
class Seen:
    method: str
    path: str
    query: dict[str, str]
    headers: httpx.Headers
    body: bytes

    @property
    def json(self) -> Any:
        return json.loads(self.body) if self.body else None


class Router:
    """Routes ``(METHOD, /v1/path)`` to queued replies; unmatched requests answer 404."""

    def __init__(self) -> None:
        self.routes: dict[tuple[str, str], deque[Reply]] = defaultdict(deque)
        self.sticky: dict[tuple[str, str], Reply] = {}
        self.seen: list[Seen] = []

    def on(self, method: str, path: str, *replies: Reply | str) -> Router:
        """Queue replies (a fixture name or :class:`Reply`); the last one repeats."""
        items = [fx(r) if isinstance(r, str) else r for r in replies]
        key = (method.upper(), "/v1/" + path.lstrip("/"))
        self.routes[key].extend(items[:-1])
        self.sticky[key] = items[-1]
        return self

    def __call__(self, request: httpx.Request) -> httpx.Response:
        url = urlsplit(str(request.url))
        body = request.read()
        self.seen.append(
            Seen(request.method, url.path, dict(parse_qsl(url.query)), request.headers, body)
        )
        key = (request.method, url.path)
        queue = self.routes.get(key)
        reply = queue.popleft() if queue else self.sticky.get(key, Reply(404, {"errors": []}))
        if reply.error is not None:
            raise reply.error
        if isinstance(reply.body, str):
            content = reply.body.encode()
            ctype = reply.headers.get("Content-Type", "text/plain")
        elif reply.body is None:
            content = b""
            ctype = "application/json"
        else:
            content = json.dumps(reply.body).encode()
            ctype = "application/json"
        headers = {k: v for k, v in reply.headers.items() if k.lower() != "content-type"}
        headers["Content-Type"] = ctype
        return httpx.Response(reply.status, headers=headers, content=content)

    def last(self, method: str | None = None, path: str | None = None) -> Seen:
        for seen in reversed(self.seen):
            if (method is None or seen.method == method) and (
                path is None or seen.path == "/v1/" + path.lstrip("/")
            ):
                return seen
        raise AssertionError(f"no request {method} {path}; saw {[s.path for s in self.seen]}")

    def paths(self) -> list[str]:
        return [f"{s.method} {s.path}" for s in self.seen]


def config(**kw: Any) -> sdk.OpenBaoConfig:
    kw.setdefault("retry", fast_retry())
    kw.setdefault("token", TOKEN)
    return sdk.OpenBaoConfig(url=BASE, **kw)


def client(router: Router, **kw: Any) -> sdk.OpenBaoClient:
    return sdk.OpenBaoClient(config(**kw), http_transport=httpx.MockTransport(router))


def aclient(router: Router, **kw: Any) -> sdk.AsyncOpenBaoClient:
    return sdk.AsyncOpenBaoClient(config(**kw), http_transport=httpx.MockTransport(router))
