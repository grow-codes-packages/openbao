"""OpenBao client (sync + async): health, ping, version, close, config, raw requests."""

from __future__ import annotations

import asyncio
import time
from typing import Any

import pytest

import grow_openbao as sdk
from _support import MockServer, closed_port_url, make_config
from _support import Reply as SReply
from obao import BASE, NO_CONTENT, TOKEN, Reply, Router, aclient, client, err, ok

HEALTH = "/v1/sys/health"


def real_client(url: str, **kw: Any) -> sdk.OpenBaoClient:
    return sdk.OpenBaoClient(make_config(url, **kw))


def real_aclient(url: str, **kw: Any) -> sdk.AsyncOpenBaoClient:
    return sdk.AsyncOpenBaoClient(make_config(url, **kw))


# --------------------------------------------------------------------------- sync


def test_health_ping_version_with_fixtures() -> None:
    r = Router().on("GET", "sys/health", "health.active")
    r.on("GET", "auth/token/lookup-self", "ping.lookup-self")
    with client(r) as c:
        health = c.health()
        assert health.healthy and health.status == "active"
        assert health.details["version"] == "2.7.2"
        assert health.details["sealed"] == "false"
        assert c.ping() >= 0
        assert c.server_version() == "2.7.2"
        assert TOKEN not in repr(c)
    h = r.last("GET", "sys/health")
    assert h.query == {
        "uninitcode": "200",
        "sealedcode": "200",
        "standbycode": "200",
        "performancestandbycode": "200",
    }
    assert "x-vault-token" not in h.headers
    assert r.last("GET", "auth/token/lookup-self").headers["x-vault-token"] == TOKEN
    assert r.last().headers["user-agent"].startswith("grow-codes-openbao/")


@pytest.mark.parametrize(
    ("fixture", "status"),
    [
        ("health.sealed", "sealed"),
        ("health.uninitialized", "uninitialized"),
    ],
)
def test_health_states(fixture: str, status: str) -> None:
    r = Router().on("GET", "sys/health", fixture)
    with client(r) as c:
        h = c.health()
    assert (h.healthy, h.status) == (False, status)


def test_health_standby_and_errors() -> None:
    body = {
        "initialized": True,
        "sealed": False,
        "standby": True,
        "version": "2.7.2",
        "cluster_name": "c1",
    }
    r = Router().on("GET", "sys/health", ok(None), Reply(200, body))
    with client(r) as c:
        first = c.health()  # 200 envelope-shaped body: treated as uninitialised
        assert first.status == "uninitialized"
        second = c.health()
        assert (second.status, second.details["clusterName"]) == ("standby", "c1")
    body["performance_standby"] = True
    r = Router().on("GET", "sys/health", Reply(200, body))
    with client(r) as c:
        assert c.health().status == "perfstandby"
    r = Router().on("GET", "sys/health", err(500, "boom"))
    with client(r) as c:
        h = c.health()
    assert (h.healthy, h.status, h.details["httpStatus"]) == (False, "unreachable", "500")
    r = Router().on("GET", "sys/health", Reply(200, None))
    with client(r) as c:
        assert c.health().status == "unreachable"  # empty body is an unexpected response
    r = Router().on("GET", "sys/health", err(400, "bad"))
    with client(r) as c:
        assert c.health().status == "unreachable"
    assert len([s for s in r.seen if s.path == HEALTH]) == 1  # health never retries


def test_core_health_unreachable() -> None:
    """core.health.unreachable"""
    c = real_client(closed_port_url())
    status = c.health()
    assert status.healthy is False
    assert status.status == "unreachable"
    assert "error" in status.details


def test_health_timeout_is_unreachable(server: MockServer) -> None:
    server.enqueue(HEALTH, SReply(200, delay=1.0))
    c = real_client(server.url, request_timeout=0.1)
    assert c.health().status == "unreachable"


def test_health_raises_only_cancelled_and_config(server: MockServer) -> None:
    c = real_client(server.url)
    c.close()
    with pytest.raises(sdk.CancelledError):
        c.health()
    token = sdk.CancelToken()
    token.cancel()
    with pytest.raises(sdk.CancelledError):
        real_client(server.url).health(cancel=token)
    with pytest.raises(sdk.CancelledError):
        real_client(server.url).ping(cancel=token)
    with pytest.raises(sdk.CancelledError):
        real_client(server.url).server_version(cancel=token)


def test_cancellable_scope(server: MockServer) -> None:
    server.enqueue("/v1/secret/data/a", SReply(200, delay=2.0))
    c = real_client(server.url, kv_version=2)
    token = sdk.CancelToken()
    started = time.monotonic()
    import threading

    threading.Timer(0.1, token.cancel).start()
    with c.cancellable(token), pytest.raises(sdk.CancelledError):
        c.kv().read("a")
    assert time.monotonic() - started < 1.5


def test_ping_bad_credentials() -> None:
    r = Router().on("GET", "auth/token/lookup-self", "ping.invalid-token")
    with client(r) as c, pytest.raises(sdk.AuthenticationError) as info:
        c.ping()
    assert info.value.http_status == 403
    assert TOKEN not in str(info.value)


def test_server_version_missing_is_unsupported() -> None:
    r = Router().on("GET", "sys/health", Reply(200, {"initialized": True}))
    with client(r) as c, pytest.raises(sdk.UnsupportedError):
        c.server_version()


def test_core_close_idempotent() -> None:
    """core.close.idempotent"""
    c = client(Router())
    stopped: list[int] = []

    class Res:
        def stop(self) -> None:
            stopped.append(1)

    c.resources.register(Res())
    assert not c.closed
    c.close()
    c.close()
    assert c.closed and stopped == [1]
    c.resources.register(Res())  # registering after close stops immediately
    assert stopped == [1, 1]
    with pytest.raises(sdk.CancelledError):
        c.ping()


def test_from_env_kv_settings() -> None:
    cfg = sdk.OpenBaoConfig.from_env(
        {
            "GROW_OPENBAO_KV_MOUNT": "kv1",
            "GROW_OPENBAO_KV_VERSION": "1",
            "GROW_OPENBAO_SECRETS_PATH": "/apps/web/",
        }
    )
    assert (cfg.kv_mount, cfg.kv_version, cfg.secrets_path, cfg.value_field) == (
        "kv1",
        1,
        "apps/web",
        "value",
    )
    assert sdk.OpenBaoConfig.from_env({"GROW_OPENBAO_KV_VERSION": "0"}).kv_version is None
    assert sdk.OpenBaoConfig.from_env({"GROW_OPENBAO_KV_MOUNT": "y"}, kv_mount="x").kv_mount == "x"
    with pytest.raises(sdk.ConfigError, match="GROW_OPENBAO_KV_VERSION"):
        sdk.OpenBaoConfig.from_env({"GROW_OPENBAO_KV_VERSION": "3"})
    with pytest.raises(sdk.ConfigError):
        sdk.OpenBaoConfig(value_field=" ").validate()
    with pytest.raises(sdk.ConfigError):
        sdk.OpenBaoConfig(secrets_path=1).validate()  # type: ignore[arg-type]
    with sdk.OpenBaoClient(sdk.OpenBaoConfig(url=BASE, secrets_path="base", value_field="v")) as c:
        p = c.secrets()
        assert (p.path, p.value_field) == ("base", "v")
        assert c.secrets(path="other").path == "other"


def test_from_env_and_vendor_variables(monkeypatch: pytest.MonkeyPatch) -> None:
    env = {
        "BAO_ADDR": "http://b:8200",
        "VAULT_ADDR": "http://v:8200",
        "VAULT_TOKEN": "vt-123",
        "BAO_NAMESPACE": "team",
        "VAULT_CACERT": "/ca.pem",
        "BAO_SKIP_VERIFY": "true",
        "VAULT_CLIENT_CERT": "/c.pem",
        "BAO_CLIENT_KEY": "/k.pem",
    }
    cfg = sdk.OpenBaoConfig.from_env(env)
    assert cfg.url == "http://b:8200"
    assert cfg.token is not None and cfg.token.reveal() == "vt-123"
    assert cfg.namespace == "team"
    assert cfg.tls.ca_cert_path == "/ca.pem" and cfg.tls.insecure_skip_verify
    assert (cfg.tls.client_cert_path, cfg.tls.client_key_path) == ("/c.pem", "/k.pem")
    env["GROW_OPENBAO_URL"] = "http://grow:8200"
    env["GROW_OPENBAO_TOKEN"] = "gt-456"
    env["GROW_OPENBAO_NAMESPACE"] = "grow"
    cfg = sdk.OpenBaoConfig.from_env(env, namespace="explicit")
    assert (cfg.url, cfg.token.reveal() if cfg.token else None, cfg.namespace) == (
        "http://grow:8200",
        "gt-456",
        "explicit",
    )
    assert "gt-456" not in repr(cfg)
    assert sdk.OpenBaoConfig.from_env({}).url == sdk.DEFAULT_URL
    with pytest.raises(sdk.ConfigError):
        sdk.OpenBaoConfig.from_env({"GROW_OPENBAO_URL": "nope://x"})
    with pytest.raises(sdk.ConfigError):
        sdk.OpenBaoConfig(token="   ").validate()
    with pytest.raises(sdk.ConfigError):
        sdk.OpenBaoConfig(kv_mount="/").validate()
    with pytest.raises(sdk.ConfigError):
        sdk.OpenBaoConfig(kv_version=3).validate()  # type: ignore[arg-type]
    assert sdk.OpenBaoConfig(namespace="").namespace is None
    monkeypatch.setenv("GROW_OPENBAO_URL", BASE)
    with sdk.OpenBaoClient() as c:
        assert c.config.url == BASE
    with sdk.OpenBaoClient.from_env({"BAO_ADDR": BASE}) as c:
        assert c.token is None


def test_namespace_header_and_set_token() -> None:
    r = Router().on("GET", "secret/data/a", "kvV2.read.ok")
    with client(r, namespace="team", kv_version=2) as c:
        c.kv().read("a")
        assert r.last().headers["x-vault-namespace"] == "team"
        c.set_token("other-token")
        assert c.token is not None and c.token.reveal() == "other-token"
        c.kv().read("a")
        assert r.last().headers["x-vault-token"] == "other-token"
        c.set_token(None)
        c.kv().read("a")
        assert "x-vault-token" not in r.last().headers


def test_error_messages_redact_tokens() -> None:
    r = Router().on("GET", "secret/data/a", err(400, f"bad token {TOKEN} and other-secret-value"))
    with client(r, kv_version=2) as c:
        c.set_token("other-secret-value")
        with pytest.raises(sdk.ValidationError) as info:
            c.kv().read("a")
    assert TOKEN not in str(info.value)
    assert "other-secret-value" not in str(info.value)


def test_raw_request_and_wrap() -> None:
    r = Router()
    r.on("GET", "sys/mounts", "admin.listMounts.ok")
    r.on("GET", "secret/data/sdk/allowed/hello", "wrapping.wrapResponse.kv2")
    r.on("POST", "custom/path", NO_CONTENT)
    r.on("GET", "sys/policies/acl", "admin.listPolicies.ok")
    with client(r) as c:
        res = c.request("GET", "sys/mounts")
        assert res.status == 200 and res.data is not None and "secret/" in res.data
        wrapped = c.request("GET", "/secret/data/sdk/allowed/hello", wrap_ttl_s=30)
        assert wrapped.wrap_info is not None and wrapped.data is None
        assert r.last().headers["x-vault-wrap-ttl"] == "30s"
        empty = c.request(
            "POST",
            "custom/path",
            json={"a": 1},
            params={"q": "1"},
            headers={"X-Extra": "1"},
            idempotent=True,
        )
        assert empty.status == 204 and empty.data is None and empty.warnings == []
        assert r.last().json == {"a": 1} and r.last().query == {"q": "1"}
        listed = c.request("GET", "sys/policies/acl", list=True)
        assert r.last().query == {"list": "true"}
        assert listed.data is not None and "default" in listed.data["keys"]


def test_unexpected_bodies() -> None:
    r = Router().on("GET", "secret/data/a", Reply(200, [1, 2]), Reply(200, "not json"))
    with client(r, kv_version=2) as c:
        with pytest.raises(sdk.UnavailableError, match="not a JSON object"):
            c.kv().read("a")
        with pytest.raises(sdk.ValidationError, match="invalid JSON"):
            c.kv().read("a")


def test_parallel_metadata_reads_use_threads() -> None:
    from grow_openbao._api import Parallel, SyncRunner

    r = Router()
    with client(r) as c:
        runner: SyncRunner = c._runner

        def sub(n: int) -> Any:
            yield from ()
            return n * 2

        def op() -> Any:
            values = yield Parallel([sub(1), sub(2), sub(3)], 2)
            empty = yield Parallel([], 2)
            return values, empty

        assert runner.run(op()) == ([2, 4, 6], [])


# --------------------------------------------------------------------------- async


async def test_async_client_core() -> None:
    r = Router().on("GET", "sys/health", "health.active")
    r.on("GET", "auth/token/lookup-self", "ping.lookup-self")
    r.on("GET", "sys/mounts", "admin.listMounts.ok")
    async with aclient(r) as c:
        assert (await c.health()).healthy
        assert await c.ping() >= 0
        assert await c.server_version() == "2.7.2"
        assert (await c.request("GET", "sys/mounts")).data is not None
        assert TOKEN not in repr(c)
        assert c.resources is not None
    await c.close()
    assert c.closed
    with pytest.raises(sdk.CancelledError):
        await c.health()
    r2 = Router().on("GET", "sys/health", err(503, "sealed"))
    async with aclient(r2) as c2:
        assert (await c2.health()).status == "unreachable"
    async with sdk.AsyncOpenBaoClient.from_env({"BAO_ADDR": BASE}) as c3:
        assert c3.config.url == BASE


async def test_async_health_unreachable() -> None:
    """core.health.unreachable (async)"""
    c = real_aclient(closed_port_url())
    status = await c.health()
    assert (status.healthy, status.status) == (False, "unreachable")
    await c.aclose()


async def test_async_health_cancel(server: MockServer, monkeypatch: pytest.MonkeyPatch) -> None:
    server.enqueue(HEALTH, SReply(200, delay=2.0))
    c = real_aclient(server.url)
    task = asyncio.ensure_future(c.health())
    await asyncio.sleep(0.1)
    task.cancel()
    with pytest.raises(sdk.CancelledError):
        await task
    await c.aclose()
    monkeypatch.setenv("GROW_OPENBAO_URL", server.url)
    c3 = sdk.AsyncOpenBaoClient()
    assert c3.config.url == server.url
    await c3.aclose()


async def test_async_runner_parallel_sleep_and_errors() -> None:
    from grow_openbao._api import Call, Parallel, Sleep

    r = Router().on("GET", "x", err(404))
    async with aclient(r) as c:

        def sub(n: int) -> Any:
            yield Sleep(0)
            return n

        def op() -> Any:
            values = yield Parallel([sub(1), sub(2)], 1)
            try:
                yield Call("GET", "x", "x")
            except sdk.NotFoundError:
                return values
            return None

        assert await c._runner.run(op()) == [1, 2]


async def test_async_cancel_inside_operation() -> None:
    import httpx as _httpx

    async def slow(request: _httpx.Request) -> _httpx.Response:
        await asyncio.sleep(5)
        return _httpx.Response(200)

    c = sdk.AsyncOpenBaoClient(
        make_config(BASE, kv_version=2), http_transport=_httpx.MockTransport(slow)
    )
    task = asyncio.ensure_future(c.kv().read("a"))
    await asyncio.sleep(0.05)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    await c.aclose()


# --------------------------------------------------------------------------- polling


def test_poll_until() -> None:
    values = iter([None, [], [1]])
    assert sdk.poll_until(lambda: next(values), interval_s=0.001) == [1]
    attempts = iter([0, 1, 2, 3])
    assert sdk.poll_until(lambda: next(attempts), predicate=lambda v: v >= 2, interval_s=0) == 2
    errors = iter([sdk.UnavailableError("flaky"), "ok"])

    def flaky() -> str:
        item = next(errors)
        if isinstance(item, Exception):
            raise item
        return item

    assert sdk.poll_until(flaky, interval_s=0) == "ok"
    with pytest.raises(sdk.NotFoundError):
        sdk.poll_until(lambda: (_ for _ in ()).throw(sdk.NotFoundError("gone")))
    started = time.monotonic()
    with pytest.raises(sdk.TimeoutError, match=r"wait\.thing") as info:
        sdk.poll_until(
            lambda: (_ for _ in ()).throw(sdk.UnavailableError("down")),
            timeout_s=0.05,
            interval_s=0.01,
            operation="wait.thing",
        )
    assert isinstance(info.value.cause, sdk.UnavailableError)
    assert time.monotonic() - started < 1.0
    with pytest.raises(sdk.TimeoutError):
        sdk.poll_until(lambda: None, timeout_s=0.02, interval_s=0.005)


async def test_apoll_until() -> None:
    values = iter([None, "", "done"])

    async def fetch() -> str | None:
        return next(values)

    assert await sdk.apoll_until(fetch, interval_s=0.001) == "done"

    async def failing() -> str:
        raise sdk.UnavailableError("down")

    with pytest.raises(sdk.TimeoutError):
        await sdk.apoll_until(failing, timeout_s=0.03, interval_s=0.01)

    async def fatal() -> str:
        raise sdk.AuthenticationError("no")

    with pytest.raises(sdk.AuthenticationError):
        await sdk.apoll_until(fatal)

    async def numbers() -> int:
        return 5

    assert await sdk.apoll_until(numbers, predicate=lambda n: n == 5) == 5


def test_resource_registry() -> None:
    reg = sdk.ResourceRegistry()
    calls: list[str] = []

    class Good:
        def stop(self) -> None:
            calls.append("good")

    class Bad:
        def stop(self) -> None:
            raise RuntimeError("ignored")

    good, bad = Good(), Bad()
    reg.register(bad)
    reg.register(good)
    reg.unregister(good)
    reg.unregister(good)
    reg.register(good)
    assert isinstance(good, sdk.Stoppable)
    assert not reg.closed
    reg.stop_all()
    reg.stop_all()
    assert reg.closed and calls == ["good"]
    reg.register(bad)  # stopped immediately, error ignored


def test_get_logger_is_silent() -> None:
    logger = sdk.get_logger()
    assert logger.name == sdk.LOGGER_NAME == "grow_openbao"
    assert any(type(h).__name__ == "NullHandler" for h in logger.handlers)
