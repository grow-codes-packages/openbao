"""KV v1 + v2 + auto-detected mounts (recorded fixtures)."""

from __future__ import annotations

import datetime as dt

import pytest

import grow_openbao as sdk
from obao import NO_CONTENT, Router, aclient, client, err, ok

V2 = "secret/data/app/db"


def test_kv_v2_read_write_patch() -> None:
    r = Router()
    r.on("GET", V2, "kvV2.read.ok")
    r.on("POST", V2, "kvV2.write.no-options", "kvV2.write.cas-mismatch")
    r.on("PATCH", V2, "kvV2.patch.ok")
    with client(r) as c:
        kv = c.kv_v2()
        secret = kv.read("app/db", version=1)
        assert secret.data == {"a": "1", "b": "2"}
        assert secret.metadata is not None and secret.metadata.version == 1
        assert secret.metadata.created_time == dt.datetime(
            2026, 11, 18, 20, 28, 54, 768226, tzinfo=dt.timezone.utc
        )
        assert secret.metadata.deletion_time is None and not secret.metadata.destroyed
        assert "'1'" not in repr(secret)
        assert r.last().query == {"version": "1"}
        meta = kv.write("app/db", {"k": "v"})
        assert meta is not None and meta.version >= 1
        assert r.last().json == {"data": {"k": "v"}}
        with pytest.raises(sdk.ConflictError):
            kv.write("app/db", {"k": "v"}, cas=1)
        assert r.last().json == {"data": {"k": "v"}, "options": {"cas": 1}}
        patched = kv.patch("app/db", {"k": None}, cas=2)
        assert patched.version >= 1
        seen = r.last("PATCH")
        assert seen.headers["content-type"] == "application/merge-patch+json"
        assert seen.json == {"data": {"k": None}, "options": {"cas": 2}}
        assert kv.version == 2 and kv.mount == "secret"


def test_kv_v2_not_found_and_deleted() -> None:
    r = Router().on("GET", V2, "kvV2.read.not-found", "kvV2.read.deleted", ok({"data": None}))
    with client(r) as c:
        for _ in range(3):
            with pytest.raises(sdk.NotFoundError):
                c.kv_v2().read("app/db")


def test_kv_v2_versions_and_metadata() -> None:
    r = Router()
    r.on("DELETE", V2, "kvV2.delete.ok")
    r.on("POST", "secret/delete/app/db", "kvV2.deleteVersions.ok")
    r.on("POST", "secret/undelete/app/db", "kvV2.undelete.ok")
    r.on("PUT", "secret/destroy/app/db", "kvV2.destroy.ok")
    r.on("GET", "secret/metadata/app/db", "kvV2.readMetadata.ok")
    r.on("POST", "secret/metadata/app/db", "kvV2.writeMetadata.ok")
    r.on("DELETE", "secret/metadata/app/db", "kvV2.deleteMetadata.ok")
    with client(r) as c:
        kv = c.kv_v2("/secret/")
        kv.delete("app/db")
        kv.delete_versions("app/db", [1, 2])
        assert r.last().json == {"versions": [1, 2]}
        kv.undelete("app/db", [3])
        kv.destroy("app/db", [1])
        assert r.last().method == "PUT"
        meta = kv.read_metadata("app/db")
        assert meta.current_version == 3 and meta.max_versions >= 0
        assert meta.custom_metadata["owner"] == "sdk"
        assert meta.delete_version_after_s >= 0
        assert set(meta.versions) >= {"1"}
        assert meta.versions["1"].version == 1
        kv.write_metadata(
            "app/db",
            max_versions=5,
            cas_required=True,
            delete_version_after_s=dt.timedelta(hours=720),
            custom_metadata={"a": "b"},
        )
        assert r.last().json == {
            "max_versions": 5,
            "cas_required": True,
            "delete_version_after": "2592000s",
            "custom_metadata": {"a": "b"},
        }
        kv.write_metadata("app/db")
        assert r.last().json == {}
        kv.delete_metadata("app/db")
        for bad in ([], [0], [True], "1", [1.5]):
            with pytest.raises(sdk.ValidationError):
                kv.destroy("app/db", bad)  # type: ignore[arg-type]
        with pytest.raises(sdk.ValidationError):
            kv.read("  ")


def test_kv_v2_list_pagination_and_empty() -> None:
    r = Router()
    r.on("GET", "secret/metadata/app/", "kvV2.list.paginated-limit")
    r.on("GET", "secret/metadata/none/", "kvV2.list.not-found")
    with client(r) as c:
        keys = c.kv_v2().list("app", after="a", limit=1)
        assert keys
        assert r.last().query == {"after": "a", "limit": "1", "list": "true"}
        assert c.kv_v2().list("none") == []


def test_kv_v2_metadata_odd_values() -> None:
    body = {
        "versions": {"x": {"destroyed": True}, "2": "nope"},
        "delete_version_after": "bogus",
        "created_time": "",
    }
    r = Router().on("GET", "secret/metadata/a", ok(body))
    with client(r) as c:
        meta = c.kv_v2().read_metadata("a")
    assert meta.versions == {
        "x": sdk.KvVersionMetadata(0, None, None, True, {}),
    }
    assert meta.delete_version_after_s == 0 and meta.created_time is None


def test_kv_v1_all_operations() -> None:
    r = Router()
    r.on("GET", "kv1/app/with%20space", "kvV1.read.encoded-path")
    r.on("POST", "kv1/app/with%20space", "kvV1.write.encoded-path")
    r.on("DELETE", "kv1/app/with%20space", "kvV1.delete.ok")
    r.on("GET", "kv1/app/", "kvV1.list.ok")
    with client(r) as c:
        kv = c.kv_v1("kv1")
        assert kv.version == 1
        secret = kv.read("app/with space")
        assert secret.metadata is None and secret.data
        assert kv.write("app/with space", {"n": 1}) is None
        assert r.last().json == {"n": 1}
        kv.delete("app/with space")
        assert kv.list("app")
        assert c.kv_v1("kv1").list("missing") == []
        unsupported = [
            lambda: kv.read("a", version=1),
            lambda: kv.write("a", {}, cas=0),
            lambda: kv.patch("a", {}),
            lambda: kv.delete_versions("a", [1]),
            lambda: kv.undelete("a", [1]),
            lambda: kv.destroy("a", [1]),
            lambda: kv.read_metadata("a"),
            lambda: kv.write_metadata("a", max_versions=1),
            lambda: kv.delete_metadata("a"),
        ]
        for call in unsupported:
            with pytest.raises(sdk.UnsupportedError, match="KV version 1"):
                call()


def test_kv_v1_patch_on_server_is_unsupported() -> None:
    """A real 405 (unsupported operation) maps to UnsupportedError too."""
    r = Router().on("PATCH", "secret/data/a", "kvV1.patch.unsupported")
    with client(r) as c, pytest.raises(sdk.UnsupportedError):
        c.kv_v2().patch("a", {"x": 1})


def test_kv_mount_detection_v1_and_v2() -> None:
    r = Router()
    r.on("GET", "sys/internal/ui/mounts/kv1/app/a", "mountDetect.kv1")
    r.on("GET", "sys/internal/ui/mounts/secret/app/a", "mountDetect.kv2")
    r.on("GET", "kv1/app/a", "kvV1.read.ok")
    r.on("GET", "secret/data/app/a", "kvV2.read.ok")
    r.on("POST", "secret/data/app/a", "kvV2.write.no-options")
    r.on("PATCH", "secret/data/app/a", "kvV2.patch.ok")
    r.on("DELETE", "secret/data/app/a", NO_CONTENT)
    r.on("POST", "secret/delete/app/a", NO_CONTENT)
    r.on("POST", "secret/undelete/app/a", NO_CONTENT)
    r.on("PUT", "secret/destroy/app/a", NO_CONTENT)
    r.on("GET", "secret/metadata/app/a", "kvV2.readMetadata.ok")
    r.on("POST", "secret/metadata/app/a", NO_CONTENT)
    r.on("DELETE", "secret/metadata/app/a", NO_CONTENT)
    r.on("GET", "secret/metadata/app/a/", "kvV2.list.ok")
    with client(r) as c:
        v1 = c.kv("kv1")
        assert v1.read("app/a").metadata is None
        assert v1.version() == 1
        with pytest.raises(sdk.UnsupportedError):
            v1.patch("app/a", {})
        v2 = c.kv("secret")
        assert v2 is c.kv()
        assert v2.version("app/a") == 2
        assert v2.read("app/a", version=1).metadata is not None
        assert v2.write("app/a", {"x": "1"}, cas=0) is not None
        assert v2.patch("app/a", {"x": "2"}).version >= 1
        v2.delete("app/a")
        v2.delete_versions("app/a", [1])
        v2.undelete("app/a", [1])
        v2.destroy("app/a", [1])
        assert v2.read_metadata("app/a").current_version == 3
        v2.write_metadata("app/a", max_versions=2)
        v2.delete_metadata("app/a")
        assert v2.list("app/a")
    detections = [p for p in r.paths() if "internal/ui" in p]
    assert len(detections) == 2  # cached per mount


def test_kv_detection_errors_and_override() -> None:
    r = Router()
    r.on("GET", "sys/internal/ui/mounts/secret/a", "mountDetect.no-access", ok({"type": "kv"}))
    r.on("GET", "sys/internal/ui/mounts/transit/a", ok({"type": "transit"}))
    r.on("GET", "sys/internal/ui/mounts/weird/a", ok({"type": "kv", "options": {"version": "9"}}))
    r.on("GET", "kv1/a", "kvV1.read.ok")
    with client(r) as c:
        with pytest.raises(sdk.PermissionDeniedError):
            c.kv().read("a")
        assert c.kv().version("a") == 1  # options missing → v1; the failed probe was not cached
        with pytest.raises(sdk.ValidationError, match="not a KV mount"):
            c.kv("transit").read("a")
        with pytest.raises(sdk.UnavailableError, match="unknown KV version"):
            c.kv("weird").read("a")
    with client(r, kv_version=1, kv_mount="kv1") as c:
        assert c.kv().read("a").data
        assert not [p for p in r.paths()[-1:] if "internal/ui" in p]


def test_cas_required_and_permission_errors() -> None:
    r = Router()
    r.on("POST", V2, "kvV2.write.cas-required")
    r.on(
        "GET",
        V2,
        "kvV2.read.permission-denied",
        "kvV2.read.missing-token",
        err(403, "permission denied"),
    )
    with client(r) as c:
        with pytest.raises(sdk.ValidationError):
            c.kv_v2().write("app/db", {})
        with pytest.raises(sdk.PermissionDeniedError):
            c.kv_v2().read("app/db")  # policy denial (wrapped multierror)
        with pytest.raises(sdk.AuthenticationError):
            c.kv_v2().read("app/db")  # missing token: plain "permission denied"
        with pytest.raises(sdk.AuthenticationError):
            c.kv_v2().read("app/db")
    r = Router().on("GET", V2, err(403))
    with client(r) as c, pytest.raises(sdk.AuthenticationError):
        c.kv_v2().read("app/db")  # no error text
    r = Router().on("GET", V2, err(403, "invalid token"))
    with client(r) as c, pytest.raises(sdk.AuthenticationError):
        c.kv_v2().read("app/db")


async def test_async_kv() -> None:
    r = Router()
    r.on("GET", "sys/internal/ui/mounts/secret/a", "mountDetect.kv2")
    r.on("GET", "secret/data/a", "kvV2.read.ok")
    r.on("GET", "kv1/a", "kvV1.read.ok")
    r.on("GET", "secret/metadata/a", "kvV2.readMetadata.ok")
    async with aclient(r) as c:
        assert (await c.kv().read("a")).data == {"a": "1", "b": "2"}
        assert await c.kv().version() == 2
        assert c.kv() is c.kv("secret")
        assert (await c.kv_v1("kv1").read("a")).metadata is None
        assert (await c.kv_v2().read_metadata("a")).current_version == 3
        with pytest.raises(sdk.UnsupportedError):
            await c.kv_v1().delete_metadata("a")
