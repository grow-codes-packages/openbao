"""KV v1 + v2 against the real server (every KV function with a round trip)."""

from __future__ import annotations

import pytest

import grow_openbao as sdk


def test_kv_v2_full_cycle(client: sdk.OpenBaoClient, run_id: str) -> None:
    kv = client.kv_v2("secret")
    path = f"py/{run_id}/app"
    v1 = kv.write(path, {"user": "a", "password": "p1"})
    assert v1 is not None and v1.version == 1
    v2 = kv.write(path, {"user": "a", "password": "p2"}, cas=1)
    assert v2 is not None and v2.version == 2
    with pytest.raises(sdk.ConflictError):
        kv.write(path, {"x": "y"}, cas=1)
    patched = kv.patch(path, {"password": None, "extra": "e"})
    assert patched.version == 3
    latest = kv.read(path)
    assert latest.data == {"user": "a", "extra": "e"}
    assert latest.metadata is not None and latest.metadata.version == 3
    assert kv.read(path, version=1).data["password"] == "p1"
    assert kv.list(f"py/{run_id}") == ["app"]
    kv.write_metadata(
        path,
        max_versions=5,
        cas_required=False,
        delete_version_after_s=3600,
        custom_metadata={"team": "sdk"},
    )
    meta = kv.read_metadata(path)
    assert meta.current_version == 3
    assert meta.max_versions == 5
    assert meta.delete_version_after_s == 3600
    assert meta.custom_metadata == {"team": "sdk"}
    assert set(meta.versions) == {"1", "2", "3"}
    kv.delete(path)
    with pytest.raises(sdk.NotFoundError):
        kv.read(path)
    kv.undelete(path, [3])
    assert kv.read(path).data["extra"] == "e"
    kv.delete_versions(path, [2])
    with pytest.raises(sdk.NotFoundError):
        kv.read(path, version=2)
    kv.destroy(path, [1])
    assert kv.read_metadata(path).versions["1"].destroyed
    kv.delete_metadata(path)
    assert kv.list(f"py/{run_id}") == []
    with pytest.raises(sdk.NotFoundError):
        kv.read_metadata(path)


def test_kv_v1_cycle_and_unsupported(client: sdk.OpenBaoClient, run_id: str) -> None:
    kv = client.kv_v1("kv1")
    path = f"py/{run_id}/with space"
    assert kv.write(path, {"n": 1, "s": "x"}) is None
    assert kv.read(path).data == {"n": 1, "s": "x"}
    assert kv.list(f"py/{run_id}") == ["with space"]
    for call in (
        lambda: kv.patch(path, {"a": 1}),
        lambda: kv.read(path, version=1),
        lambda: kv.write(path, {}, cas=0),
        lambda: kv.delete_versions(path, [1]),
        lambda: kv.undelete(path, [1]),
        lambda: kv.destroy(path, [1]),
        lambda: kv.read_metadata(path),
        lambda: kv.write_metadata(path, max_versions=1),
        lambda: kv.delete_metadata(path),
    ):
        with pytest.raises(sdk.UnsupportedError):
            call()
    kv.delete(path)
    with pytest.raises(sdk.NotFoundError):
        kv.read(path)
    assert kv.list(f"py/{run_id}") == []


def test_kv_mount_auto_detection(client: sdk.OpenBaoClient, run_id: str) -> None:
    assert client.kv("kv1").version() == 1
    assert client.kv("secret").version() == 2
    assert client.kv() is client.kv("secret")
    m = client.kv("kv1")
    m.write(f"py/{run_id}/a", {"v": "1"})
    assert m.read(f"py/{run_id}/a").data == {"v": "1"}
    with pytest.raises(sdk.UnsupportedError):
        m.patch(f"py/{run_id}/a", {"v": "2"})
    m.delete(f"py/{run_id}/a")
    v2 = client.kv("secret")
    meta = v2.write(f"py/{run_id}/b", {"v": "1"})
    assert meta is not None and meta.version == 1
    v2.patch(f"py/{run_id}/b", {"w": "2"})
    assert v2.read(f"py/{run_id}/b").data == {"v": "1", "w": "2"}
    v2.write_metadata(f"py/{run_id}/b", custom_metadata={"a": "b"})
    assert v2.read_metadata(f"py/{run_id}/b").custom_metadata == {"a": "b"}
    v2.delete_versions(f"py/{run_id}/b", [2])
    v2.undelete(f"py/{run_id}/b", [2])
    v2.destroy(f"py/{run_id}/b", [1])
    assert v2.list(f"py/{run_id}") == ["b"]
    v2.delete(f"py/{run_id}/b")
    v2.delete_metadata(f"py/{run_id}/b")


def test_restricted_token_detects_mount(env: dict[str, str]) -> None:
    values = {k: v for k, v in env.items() if k != "GROW_OPENBAO_TOKEN"}
    with sdk.OpenBaoClient.from_env(values) as c:
        c.auth.login(
            sdk.AppRoleAuth(
                env["GROW_OPENBAO_TEST_APPROLE_ROLE_ID"], env["GROW_OPENBAO_TEST_APPROLE_SECRET_ID"]
            )
        )
        assert c.kv("kv1").read("sdk/allowed/hello").data == {"value": "world"}
        with pytest.raises(sdk.PermissionDeniedError):
            c.kv("kv1").read("sdk/denied/hello")


def test_namespace(env: dict[str, str]) -> None:
    ns = env.get("GROW_OPENBAO_TEST_NAMESPACE")
    if not ns:
        pytest.skip("namespaces not available in this fixture")
    with sdk.OpenBaoClient.from_env(env, namespace=ns) as c:
        assert c.kv_v2("secret").read("sdk/in-namespace").data == {"value": "ns-only"}
    with sdk.OpenBaoClient.from_env(env) as c, pytest.raises(sdk.NotFoundError):
        c.kv_v2("secret").read("sdk/in-namespace")
