"""System backend: health, seal status, leader, policies, mounts, auth methods, AppRole admin."""

from __future__ import annotations

import time

import pytest

import grow_openbao as sdk


def test_health_seal_leader_version(client: sdk.OpenBaoClient, env: dict[str, str]) -> None:
    h = client.sys.health()
    assert h.state == "active" and h.initialized and not h.sealed
    assert h.version == env["GROW_OPENBAO_TEST_SERVER_VERSION"]
    status = client.sys.seal_status()
    assert status.type == "static" and not status.sealed and status.storage_type == "raft"
    leader = client.sys.leader()
    assert leader.ha_enabled and leader.is_self
    assert (
        client.sys.version() == client.server_version() == env["GROW_OPENBAO_TEST_SERVER_VERSION"]
    )
    health = client.health()
    assert health.healthy and health.status == "active"


def test_policies(client: sdk.OpenBaoClient, run_id: str) -> None:
    name = f"py-{run_id}"
    hcl = 'path "secret/data/py/*" { capabilities = ["read"] }'
    client.sys.write_policy(name, hcl)
    assert client.sys.read_policy(name) == sdk.Policy(name, hcl)
    assert name in client.sys.list_policies()
    client.sys.delete_policy(name)
    with pytest.raises(sdk.NotFoundError):
        client.sys.read_policy(name)
    with pytest.raises(sdk.ValidationError):
        client.sys.write_policy(name, "path {{{ not hcl")


def test_secrets_engines(client: sdk.OpenBaoClient, run_id: str) -> None:
    path = f"py-kv-{run_id}"
    client.sys.enable_secrets_engine(
        path, "kv", options={"version": "2"}, description="py test", max_lease_ttl_s=3600
    )
    mounts = client.sys.list_mounts()
    assert mounts[f"{path}/"].type == "kv"
    assert mounts[f"{path}/"].options.get("version") == "2"
    with pytest.raises(sdk.ValidationError):
        client.sys.enable_secrets_engine(path, "kv")
    # A new KV v2 mount answers 400 "upgrading" for a moment after enable.
    for _ in range(30):
        try:
            client.kv(path).write("x", {"a": "b"})
            break
        except sdk.ValidationError:
            time.sleep(0.5)
    assert client.kv(path).read("x").data == {"a": "b"}
    client.sys.disable_secrets_engine(path)
    assert f"{path}/" not in client.sys.list_mounts()


def test_auth_methods_and_approle_admin(
    client: sdk.OpenBaoClient, env: dict[str, str], run_id: str
) -> None:
    mount = f"py-ar-{run_id}"
    client.sys.enable_auth_method(mount, "approle", description="py test", default_lease_ttl_s=600)
    assert client.sys.list_auth_methods()[f"{mount}/"].type == "approle"
    client.sys.create_app_role(
        "role1", mount=mount, token_policies=["sdk-app"], token_ttl_s=600, secret_id_num_uses=1
    )
    assert client.sys.list_app_roles(mount=mount) == ["role1"]
    role_id = client.sys.read_role_id("role1", mount=mount)
    secret = client.sys.generate_secret_id("role1", mount=mount, metadata={"who": "py"})
    assert secret.secret_id_num_uses == 1
    with sdk.OpenBaoClient(client.config) as c:
        info = c.auth.login(sdk.AppRoleAuth(role_id, secret.secret_id, mount=mount))
        assert "sdk-app" in info.policies and info.metadata.get("who") == "py"
        with pytest.raises(sdk.AuthenticationError):  # single-use secret id
            c.auth.login(sdk.AppRoleAuth(role_id, secret.secret_id, mount=mount))
    client.sys.delete_app_role("role1", mount=mount)
    with pytest.raises(sdk.NotFoundError):
        client.sys.read_role_id("role1", mount=mount)
    client.sys.disable_auth_method(mount)
    assert f"{mount}/" not in client.sys.list_auth_methods()


def test_raw_request(client: sdk.OpenBaoClient) -> None:
    res = client.request("GET", "sys/mounts")
    assert res.status == 200 and res.data is not None and "secret/" in res.data
    keys = client.request("GET", "sys/policies/acl", list=True)
    assert keys.data is not None and "default" in keys.data["keys"]
