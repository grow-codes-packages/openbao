"""SecretsProvider over KV (DECISIONS.md #1, #2, #6), lifecycle helpers and wire helpers."""

from __future__ import annotations

import base64
import datetime as dt
from typing import Any

import pytest

import grow_openbao as sdk
from grow_openbao import _api
from grow_openbao.testing import lifecycle
from obao import NO_CONTENT, Reply, Router, aclient, client, err, ok


def v2_secret(data: dict[str, Any], version: int = 1) -> Reply:
    return ok(
        {
            "data": data,
            "metadata": {
                "version": version,
                "created_time": "",
                "deletion_time": "",
                "destroyed": False,
            },
        }
    )


def v2_meta(current: int = 2, deleted: bool = False, tags: dict[str, str] | None = None) -> Reply:
    versions = {
        str(n): {"created_time": "2026-11-18T20:28:54Z", "deletion_time": "", "destroyed": False}
        for n in range(1, current + 1)
    }
    if deleted:
        versions[str(current)]["deletion_time"] = "2026-11-18T21:00:00Z"
    return ok(
        {
            "cas_required": False,
            "created_time": "2026-11-18T20:28:54.1Z",
            "updated_time": "2026-11-18T20:30:00Z",
            "current_version": current,
            "oldest_version": 1,
            "max_versions": 0,
            "delete_version_after": "0s",
            "custom_metadata": tags,
            "versions": versions,
        }
    )


def test_get_set_values_and_versions() -> None:
    r = Router()
    r.on("GET", "secret/data/app/plain", v2_secret({"value": "hello"}, 3))
    r.on(
        "GET",
        "secret/data/app/bin",
        v2_secret({"value": base64.b64encode(b"\xff").decode(), "encoding": "base64"}),
    )
    r.on("GET", "secret/data/app/badb64", v2_secret({"value": "***", "encoding": "base64"}))
    r.on("GET", "secret/data/app/multi", v2_secret({"u": "x", "p": "y"}))
    r.on("GET", "secret/data/app/num", v2_secret({"value": 42}))
    r.on("GET", "secret/data/app/gone", "kvV2.read.deleted")
    r.on("POST", "secret/data/app/plain", ok({"version": 4}))
    r.on("POST", "secret/data/other/x", ok({"version": 1}))
    r.on("POST", "secret/metadata/app/plain", NO_CONTENT)
    with client(r, kv_version=2) as c:
        p = c.secrets(path="/app/")
        assert p.path == "app" and p.value_field == "value"
        assert p.full_path("x") == "app/x" and p.full_path("x", path="") == "x"
        assert p.full_path("", path="base") == "base"
        v = p.get("plain")
        assert v is not None and v.reveal() == "hello" and v.version == "3"
        assert p.get("plain", version="2") is not None
        assert r.last().query == {"version": "2"}
        with pytest.raises(sdk.ValidationError):
            p.get("plain", version="latest")
        with pytest.raises(sdk.ValidationError):
            p.get("plain", version="0")
        assert p.get("bin").reveal_bytes() == b"\xff"  # type: ignore[union-attr]
        with pytest.raises(sdk.ValidationError):
            p.get("badb64")
        assert p.get_json("multi") == {"u": "x", "p": "y"}
        assert p.get_number("num") == 42
        assert p.get("gone") is None and not p.exists("gone")
        assert p.set("plain", "text", cas=3, tags={"t": "1"}) == "4"
        assert r.last("POST", "secret/data/app/plain").json == {
            "data": {"value": "text"},
            "options": {"cas": 3},
        }
        assert r.last().json == {"custom_metadata": {"t": "1"}}
        p.set("plain", b"\x00\x01")
        assert r.last().json == {"data": {"value": "AAE=", "encoding": "base64"}}
        p.set("plain", {"a": 1})
        assert r.last().json == {"data": {"value": '{"a":1}'}}
        p.set("plain", "café".encode("latin-1"))  # non UTF-8 bytes → base64
        assert r.last().json["data"]["encoding"] == "base64"
        assert p.set("x", "v", path="other") == "1"


def test_base_set_utf8_bytes_stored_as_text() -> None:
    from grow_openbao._secrets import SetOptions

    r = Router().on("POST", "secret/data/x", ok({"version": 1}))
    r.on("POST", "secret/data/y", ok({"version": 1}))
    with client(r, kv_version=2) as c:
        p = c.secrets()
        assert p._put_secret("x", "hé".encode(), SetOptions()) == "1"
        assert r.last().json == {"data": {"value": "hé"}}
        assert p._put_secret("y", b"\xff", SetOptions()) == "1"
        assert r.last().json["data"]["encoding"] == "base64"


def test_list_get_all_metadata_v2() -> None:
    r = Router()
    r.on("GET", "secret/metadata/app/", ok({"keys": ["b", "a", "deleted", "sub/"]}))
    r.on("GET", "secret/metadata/app/a", v2_meta(2, tags={"team": "x"}))
    r.on("GET", "secret/metadata/app/b", v2_meta(1))
    r.on("GET", "secret/metadata/app/deleted", v2_meta(1, deleted=True))
    r.on("GET", "secret/data/app/a", v2_secret({"value": "A"}, 2))
    r.on("GET", "secret/data/app/b", v2_secret({"value": "B"}))
    r.on("GET", "secret/metadata/app/missing", "kvV2.readMetadata.ok")
    with client(r, kv_version=2) as c:
        p = c.secrets()
        metas = p.list("app")
        assert [m.name for m in metas] == ["app/a", "app/b"]
        a = metas[0]
        assert a.path == "app" and a.version == "2" and a.tags == {"team": "x"} and a.versions == 2
        assert a.created_at == dt.datetime(2026, 11, 18, 20, 28, 54, 100000, tzinfo=dt.timezone.utc)
        assert a.extra == {
            "maxVersions": "0",
            "casRequired": "false",
            "deleteVersionAfter": "0s",
            "oldestVersion": "1",
        }
        values = p.get_all("app")
        assert {k: v.reveal() for k, v in values.items()} == {"app/a": "A", "app/b": "B"}
        env: dict[str, str] = {}
        assert p.load_env("app", prefix="X_", environ=env) == {"X_A": "app/a", "X_B": "app/b"}
        assert env == {"X_A": "A", "X_B": "B"}
        meta = p.metadata("a", path="app")
        assert meta is not None and meta.name == "a" and meta.path == "app"
        assert p.metadata("nothing") is None


def test_list_and_metadata_v1() -> None:
    r = Router()
    r.on("GET", "kv1/", ok({"keys": ["one", "dir/"]}))
    r.on("GET", "kv1/one", "kvV1.read.ok")
    with client(r, kv_version=1, kv_mount="kv1") as c:
        p = c.secrets()
        assert [(m.name, m.path, m.version) for m in p.list()] == [("one", None, None)]
        assert p.metadata("one") == sdk.SecretMetadata(name="one")
        assert p.metadata("two") is None
        v = p.get("one")
        assert v is not None and v.version is None
        with pytest.raises(sdk.ValidationError):  # DECISIONS §9: provider + v1 + version
            p.get("one", version="1")
        with pytest.raises(sdk.UnsupportedError):
            p.set("one", "x", cas=0)
        with pytest.raises(sdk.UnsupportedError):
            p.set("one", "x", tags={"a": "b"})


def test_delete_paths() -> None:
    r = Router()
    r.on("GET", "secret/data/a", v2_secret({"value": "1"}), err(404))
    r.on("DELETE", "secret/data/a", NO_CONTENT)
    r.on("GET", "secret/metadata/a", v2_meta(2), v2_meta(2), err(404))
    r.on("POST", "secret/delete/a", NO_CONTENT)
    r.on("DELETE", "secret/metadata/a", NO_CONTENT)
    with client(r, kv_version=2) as c:
        p = c.secrets()
        p.delete("a")
        p.delete("a", versions=["1", "2"])
        assert r.last().json == {"versions": [1, 2]}
        p.delete("a", permanent=True)
        with pytest.raises(sdk.NotFoundError):
            p.delete("a", permanent=True)
        with pytest.raises(sdk.NotFoundError):
            p.delete("a")
    r = Router().on("GET", "secret/metadata/a", v2_meta(1))
    with client(r, kv_version=2) as c, pytest.raises(sdk.ValidationError):
        c.secrets().delete("a", versions=["x"])
    r = Router().on("GET", "kv1/a", "kvV1.read.ok", err(404)).on("DELETE", "kv1/a", NO_CONTENT)
    with client(r, kv_version=1, kv_mount="kv1") as c:
        c.secrets().delete("a")
        with pytest.raises(sdk.NotFoundError):
            c.secrets().delete("a")


def test_watch_stopped_by_client_close() -> None:
    r = Router().on("GET", "secret/data/w", v2_secret({"value": "1"}))
    c = client(r, kv_version=2)
    handle = c.secrets().watch("w", 60, lambda new, old: None)
    c.close()
    assert handle.stopped


async def test_async_provider() -> None:
    r = Router()
    r.on("GET", "sys/internal/ui/mounts/secret/x", "mountDetect.kv2")
    r.on("GET", "secret/data/x", *([v2_secret({"value": "1"}, 1)] * 3), err(404))
    r.on("POST", "secret/data/x", ok({"version": 2}))
    r.on("GET", "secret/metadata/x", v2_meta(1))
    r.on("GET", "secret/metadata/", ok({"keys": ["x"]}))
    r.on("DELETE", "secret/data/x", NO_CONTENT)
    async with aclient(r) as c:
        p = c.secrets()
        assert p.path == "" and p.value_field == "value" and p.full_path("x") == "x"
        assert (await p.get_string("x")) == "1"
        assert await p.set("x", "2") == "2"
        assert await p.set("x", b"\xff") == "2"
        assert (await p.metadata("x")) is not None
        assert [m.name for m in await p.list()] == ["x"]
        assert len(await p.get_all()) == 1
        await p.delete("x")
        assert await p.get("x") is None


# --------------------------------------------------------------------------- lifecycle


def test_lifecycle_sync() -> None:
    r = Router()
    r.on("GET", "sys/init", "init.status")
    r.on("PUT", "sys/init", "init.shamir", "init.already-initialized", ok({}))
    r.on("PUT", "sys/unseal", "unseal.ok", "unseal.invalid-key")
    r.on("PUT", "sys/seal", "seal.testing")
    r.on("GET", "sys/health", "health.sealed", err(503, "sealed"), "health.active")
    with client(r) as c:
        assert isinstance(lifecycle.init_status(c), bool)
        assert "x-vault-token" not in r.last().headers
        res = lifecycle.init(c)
        assert r.last().json == {"secret_shares": 1, "secret_threshold": 1}
        assert len(res.keys) == 1 and res.root_token.reveal() == "<redacted>"
        assert "<redacted>" not in repr(res)
        with pytest.raises(sdk.ValidationError):
            lifecycle.init(c, recovery_shares=1)
        assert r.last().json == {"recovery_shares": 1, "recovery_threshold": 1}
        with pytest.raises(sdk.UnavailableError, match="root_token"):
            lifecycle.init(c, recovery_threshold=2)
        assert not lifecycle.unseal(c, sdk.Secret("abcd")).sealed
        with pytest.raises(sdk.ValidationError):
            lifecycle.unseal(c, "zz")
        with pytest.raises(sdk.ValidationError):
            lifecycle.unseal(c)
        lifecycle.seal(c)
        assert r.last().headers["x-vault-token"]
        h = lifecycle.wait_for_active(c, interval_s=0.001)
        assert h.state == "active"
    r = Router().on("GET", "sys/health", "health.sealed")
    with client(r) as c, pytest.raises(sdk.TimeoutError):
        lifecycle.wait_for_active(c, timeout_s=0.02, interval_s=0.005)
    r = Router().on("GET", "sys/health", err(400, "bad"))
    with client(r) as c, pytest.raises(sdk.ValidationError):
        lifecycle.wait_for_active(c)


async def test_lifecycle_async() -> None:
    r = Router()
    r.on("GET", "sys/init", "init.status")
    r.on("PUT", "sys/init", "init.shamir")
    r.on("PUT", "sys/unseal", "unseal.ok")
    r.on("PUT", "sys/seal", NO_CONTENT)
    r.on("GET", "sys/health", "health.active")
    async with aclient(r) as c:
        assert isinstance(await lifecycle.ainit_status(c), bool)
        assert (await lifecycle.ainit(c, secret_shares=3, secret_threshold=2)).keys
        assert r.last().json == {"secret_shares": 3, "secret_threshold": 2}
        assert not (await lifecycle.aunseal(c, reset=True)).sealed
        assert r.last().json == {"reset": True}
        await lifecycle.aseal(c)
        assert (await lifecycle.await_for_active(c)).state == "active"


# --------------------------------------------------------------------------- helpers


def test_wire_helpers() -> None:
    assert _api.encode_path("kv1", "/a b/", "", "c/d") == "kv1/a%20b/c/d"
    assert _api.duration_string(1.2) == "2s"
    assert _api.duration_string(dt.timedelta(minutes=1)) == "60s"
    for bad in (-1, float("inf")):
        with pytest.raises(sdk.ValidationError):
            _api.duration_string(bad)
    assert _api.opt_duration(None) is None
    assert _api.seconds(True) == 0 and _api.seconds("3") == 0 and _api.seconds(3) == 3.0
    assert _api.parse_vault_duration("720h0m0s") == 720 * 3600
    assert _api.parse_vault_duration("1m30s") == 90
    assert _api.parse_vault_duration("1.5h") == 5400
    assert _api.parse_vault_duration("250ms") == 0.25
    assert _api.parse_vault_duration(45) == 45 and _api.parse_vault_duration("45") == 45
    for bad in (None, "", True, "x1s", "1sx", [1]):
        assert _api.parse_vault_duration(bad) is None
    utc = dt.timezone.utc
    assert _api.parse_time("2026-11-18T20:28:54.768226646Z") == dt.datetime(
        2026, 11, 18, 20, 28, 54, 768226, tzinfo=utc
    )
    assert _api.parse_time("2026-11-18T22:28:54+02:00") == dt.datetime(
        2026, 11, 18, 20, 28, 54, tzinfo=utc
    )
    assert _api.parse_time("2026-11-18T20:28:54-01:30") == dt.datetime(
        2026, 11, 18, 21, 58, 54, tzinfo=utc
    )
    assert _api.parse_time(1795033751) == dt.datetime.fromtimestamp(1795033751, tz=utc)
    for bad in ("", 0, None, True, "nope", "2026-13-40T00:00:00Z", "0001-01-01T00:00:00Z", -5):
        assert _api.parse_time(bad) is None
    assert _api.from_b64(_api.to_b64("hi")) == b"hi"
    with pytest.raises(sdk.ValidationError):
        _api.from_b64("***")
    assert _api.opt_b64(None) is None
    assert _api.strings(None) == [] and _api.strings(["a", 1]) == ["a"]
    assert _api.string_map(None) == {}
    assert _api.string_map({"a": "b", "n": 1, "x": None, "o": {"k": [1]}}) == {
        "a": "b",
        "n": "1",
        "o": '{"k":[1]}',
    }
    assert _api.text(1) == "" and _api.integer(True) == 0 and _api.integer(2.0) == 2
    assert _api.integer("2") == 0
    assert _api.opt_secret("") is None and _api.opt_secret("x") == sdk.Secret("x")
    assert repr(_api.UNSET) == "UNSET"
    with pytest.raises(sdk.ValidationError):
        _api.require_text(None, "name", "op")  # type: ignore[arg-type]


def test_error_mapping() -> None:
    m = _api.map_vault_error
    base = sdk.ValidationError(
        "x: check-and-set parameter did not match (HTTP 400)", http_status=400
    )
    assert isinstance(m(base), sdk.ConflictError)
    assert isinstance(
        m(sdk.ValidationError("x", http_status=400), login=True), sdk.AuthenticationError
    )
    assert isinstance(
        m(sdk.PermissionDeniedError("missing client token", http_status=403)),
        sdk.AuthenticationError,
    )
    assert isinstance(m(sdk.ValidationError("unsupported", http_status=405)), sdk.UnsupportedError)
    assert isinstance(m(sdk.UnsupportedError("not init", http_status=501)), sdk.UnavailableError)
    same = sdk.NotFoundError("gone", http_status=404)
    assert m(same) is same
    plain = sdk.UnavailableError("net")
    assert m(plain) is plain
    already = sdk.AuthenticationError("bad", http_status=401)
    assert m(already, login=True) is already
    rate = sdk.RateLimitError("slow", http_status=429, retry_after=3)
    assert m(rate) is rate


def test_session_remember_and_request() -> None:
    s = _api.Session(None, None)
    s.remember(None, "ab", "long-secret", sdk.Secret("other-secret"))
    assert set(s.known_secrets(["base"])) == {"base", "long-secret", "other-secret"}
    req = s.request(_api.Call("GET", "x", "op", token="t", list=True, params={"a": 1}))
    assert req.headers == {"X-Vault-Token": "t"} and req.params == {"a": 1, "list": "true"}
    req = s.request(_api.Call("GET", "x", "op"))
    assert req.headers == {} and req.params is None
