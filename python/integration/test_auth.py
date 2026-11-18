"""Auth methods, token self-service and token renewal against the real server."""

from __future__ import annotations

import threading
import time

import pytest

import grow_openbao as sdk


def _scoped(env: dict[str, str]) -> sdk.OpenBaoClient:
    """A client without a token (logins set it)."""
    values = {k: v for k, v in env.items() if k != "GROW_OPENBAO_TOKEN"}
    return sdk.OpenBaoClient.from_env(values)


def test_approle_login_reads_allowed_and_denied(env: dict[str, str]) -> None:
    with _scoped(env) as c:
        assert c.token is None
        info = c.auth.login(
            sdk.AppRoleAuth(
                env["GROW_OPENBAO_TEST_APPROLE_ROLE_ID"], env["GROW_OPENBAO_TEST_APPROLE_SECRET_ID"]
            )
        )
        assert info.metadata.get("role_name") == "sdk-app"
        assert "sdk-app" in info.policies
        assert c.token == info.client_token
        assert env["GROW_OPENBAO_TEST_APPROLE_SECRET_ID"] not in repr(info)
        assert c.kv().read("sdk/allowed/hello").data == {"value": "world"}
        with pytest.raises(sdk.PermissionDeniedError):
            c.kv().read("sdk/denied/hello")


def test_approle_bad_secret_is_authentication_error(env: dict[str, str]) -> None:
    with _scoped(env) as c, pytest.raises(sdk.AuthenticationError) as info:
        c.auth.login(sdk.AppRoleAuth(env["GROW_OPENBAO_TEST_APPROLE_ROLE_ID"], "wrong-secret-id"))
    assert "wrong-secret-id" not in str(info.value)


def test_userpass_login(env: dict[str, str]) -> None:
    with _scoped(env) as c:
        info = c.auth.login(
            sdk.UserpassAuth(
                env["GROW_OPENBAO_TEST_USERPASS_USER"], env["GROW_OPENBAO_TEST_USERPASS_PASSWORD"]
            )
        )
        assert info.metadata.get("username") == "sdk-user"
        assert c.auth.lookup_self().display_name.endswith("sdk-user")
        with pytest.raises(sdk.AuthenticationError):
            c.auth.login(sdk.UserpassAuth("sdk-user", "wrong-password"))


def test_jwt_login_and_expired(env: dict[str, str]) -> None:
    with _scoped(env) as c:
        info = c.auth.login(
            sdk.JwtAuth(env["GROW_OPENBAO_TEST_JWT_ROLE"], env["GROW_OPENBAO_TEST_JWT"])
        )
        assert info.metadata.get("role") == "sdk-jwt"
        assert c.kv().read("sdk/allowed/hello").data["value"] == "world"
        with pytest.raises(sdk.AuthenticationError):
            c.auth.login(
                sdk.JwtAuth(env["GROW_OPENBAO_TEST_JWT_ROLE"], env["GROW_OPENBAO_TEST_JWT_EXPIRED"])
            )


def test_kubernetes_login_request_shape(env: dict[str, str], tmp_path: object) -> None:
    """No Kubernetes API in the fixture: the TokenReview fails → AuthenticationError (403)."""
    import pathlib

    jwt_file = pathlib.Path(str(tmp_path)) / "token"
    jwt_file.write_text(env["GROW_OPENBAO_TEST_K8S_JWT"] + "\n", encoding="utf-8")
    with _scoped(env) as c, pytest.raises(sdk.AuthenticationError) as info:
        c.auth.login(sdk.KubernetesAuth(env["GROW_OPENBAO_TEST_K8S_ROLE"], str(jwt_file)))
    assert info.value.http_status == 403


def test_token_auth_lookup_renew_create_revoke(client: sdk.OpenBaoClient) -> None:
    child = client.auth.create_token(
        policies=["default"], ttl_s=600, renewable=True, display_name="py-child", meta={"k": "v"}
    )
    assert child.lease_duration_s == 600
    assert child.renewable
    orphan = client.auth.create_token(policies=["default"], ttl_s=60, no_parent=True)
    assert orphan.orphan
    with sdk.OpenBaoClient(client.config) as c:
        info = c.auth.login(sdk.TokenAuth(child.client_token))
        assert info.client_token == child.client_token
        me = c.auth.lookup_self()
        assert me.display_name == "token-py-child"
        assert me.meta == {"k": "v"}
        renewed = c.auth.renew_self(1200)
        assert 0 < renewed.lease_duration_s <= 1200
        c.auth.revoke_self()
        assert c.token is None
        with pytest.raises(sdk.AuthenticationError):
            c.auth.login(sdk.TokenAuth(child.client_token))


def test_non_renewable_token_renew_is_validation_error(client: sdk.OpenBaoClient) -> None:
    child = client.auth.create_token(policies=["default"], ttl_s=60, renewable=False)
    with sdk.OpenBaoClient(client.config) as c:
        c.set_token(child.client_token)
        with pytest.raises(sdk.ValidationError):
            c.auth.renew_self(30)


def test_token_renewer_renews_and_auto_renew_login(
    env: dict[str, str], client: sdk.OpenBaoClient
) -> None:
    child = client.auth.create_token(policies=["default"], ttl_s=3, renewable=True)
    renewed = threading.Event()
    with sdk.OpenBaoClient(client.config) as c:
        c.set_token(child.client_token)
        renewer = c.auth.start_renewer(increment_s=3, on_renew=lambda r: renewed.set())
        assert renewer.running
        assert renewed.wait(10), "token was not renewed"
        assert c.auth.lookup_self().ttl_s > 0
        renewer.stop()
        assert not renewer.running
    with _scoped(env) as c:
        c.auth.login(
            sdk.AppRoleAuth(
                env["GROW_OPENBAO_TEST_APPROLE_ROLE_ID"], env["GROW_OPENBAO_TEST_APPROLE_SECRET_ID"]
            ),
            auto_renew=True,
        )
        assert c.auth.active_renewers == 1
    assert c.auth.active_renewers == 0  # close() stopped it


def test_async_auth(env: dict[str, str]) -> None:
    import asyncio

    async def run() -> None:
        values = {k: v for k, v in env.items() if k != "GROW_OPENBAO_TOKEN"}
        async with sdk.AsyncOpenBaoClient.from_env(values) as c:
            await c.auth.login(
                sdk.UserpassAuth(
                    env["GROW_OPENBAO_TEST_USERPASS_USER"],
                    env["GROW_OPENBAO_TEST_USERPASS_PASSWORD"],
                )
            )
            me = await c.auth.lookup_self()
            assert "sdk-app" in me.policies
            renewed = await c.auth.renew_self(600)
            assert renewed.lease_duration_s > 0
            renewer = await c.auth.start_renewer()
            assert renewer.running
            await c.auth.revoke_self()
            assert c.token is None

    asyncio.run(run())
    time.sleep(0)
