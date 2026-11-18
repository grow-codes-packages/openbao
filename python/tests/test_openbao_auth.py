"""Auth methods, token self-service and token renewal (fixtures + fake clock)."""

from __future__ import annotations

import asyncio
import threading
from pathlib import Path
from typing import Any

import pytest

import grow_openbao as sdk
from obao import TOKEN, Reply, Router, aclient, client, err, ok


def auth_reply(token: str = "s.new-token", ttl: int = 3600, renewable: bool = True) -> Reply:
    return ok(
        None,
        auth={
            "client_token": token,
            "accessor": "acc-123",
            "policies": ["default", "sdk-app"],
            "token_policies": ["default", "sdk-app"],
            "metadata": {"role_name": "sdk-app"},
            "lease_duration": ttl,
            "renewable": renewable,
            "entity_id": "e1",
            "token_type": "service",
            "orphan": False,
            "num_uses": 0,
        },
    )


class FakeClock:
    def __init__(self) -> None:
        self.now = 1000.0
        self.waits: list[float] = []

    def __call__(self) -> float:
        return self.now

    def wait(self, delay: float) -> bool:
        self.waits.append(round(delay, 3))
        self.now += delay
        return False


def test_login_methods_and_token_switch(tmp_path: Path) -> None:
    r = Router()
    r.on("POST", "auth/approle/login", "appRoleLogin.ok")
    r.on("POST", "auth/custom/login", "appRoleLogin.custom-mount")
    r.on("POST", "auth/userpass/login/sdk-user", "userpassLogin.ok")
    r.on("POST", "auth/jwt/login", "jwtLogin.ok")
    r.on("POST", "auth/kubernetes/login", auth_reply("s.k8s"))
    r.on("POST", "auth/k8s2/login", auth_reply("s.k8s2"))
    r.on("GET", "auth/token/lookup-self", "lookupSelf.ok")
    with client(r, token=None) as c:
        info = c.auth.login(sdk.AppRoleAuth("role-id", "secret-id-value"))
        assert "x-vault-token" not in r.last().headers
        assert r.last().json == {"role_id": "role-id", "secret_id": "secret-id-value"}
        assert c.token == info.client_token
        assert info.metadata.get("role_name") and info.lease_duration_s > 0
        assert "secret-id-value" not in repr(sdk.AppRoleAuth("r", "secret-id-value"))
        c.auth.login(sdk.AppRoleAuth("role-id", mount="custom"), set_token=False)
        assert r.last().json == {"role_id": "role-id"}
        c.auth.login(sdk.UserpassAuth("sdk-user", "pw-123456"))
        assert r.last().json == {"password": "pw-123456"}
        assert "pw-123456" not in repr(sdk.UserpassAuth("sdk-user", "pw-123456"))
        c.auth.login(sdk.JwtAuth("sdk-jwt", "eyJ.jwt.value"))
        assert r.last().json == {"role": "sdk-jwt", "jwt": "eyJ.jwt.value"}
        assert "eyJ" not in repr(sdk.JwtAuth("sdk-jwt", "eyJ.jwt.value"))
        jwt_file = tmp_path / "token"
        jwt_file.write_text("k8s.jwt.value\n", encoding="utf-8")
        k8s = c.auth.login(sdk.KubernetesAuth("sdk-k8s", str(jwt_file)))
        assert k8s.client_token.reveal() == "s.k8s"
        assert r.last().json == {"role": "sdk-k8s", "jwt": "k8s.jwt.value"}
        c.auth.login(sdk.KubernetesAuth("sdk-k8s", jwt="inline.jwt", mount="k8s2"))
        assert r.last().path == "/v1/auth/k8s2/login"
        assert repr(sdk.KubernetesAuth("sdk-k8s")) == "KubernetesAuth(kubernetes, role=sdk-k8s)"
        token_info = c.auth.login(sdk.TokenAuth("s.existing"))
        assert r.last().headers["x-vault-token"] == "s.existing"
        assert token_info.client_token.reveal() == "s.existing"
        assert repr(sdk.TokenAuth("s.existing")) == "TokenAuth([REDACTED])"
        assert c.token is not None and c.token.reveal() == "s.existing"


def test_login_failures_are_authentication_errors(tmp_path: Path) -> None:
    r = Router()
    r.on("POST", "auth/approle/login", "appRoleLogin.invalid-secret")
    r.on("POST", "auth/userpass/login/u", "userpassLogin.invalid-password")
    r.on("POST", "auth/jwt/login", "jwtLogin.expired")
    r.on("POST", "auth/kubernetes/login", "kubernetesLogin.no-kubernetes-api")
    r.on("GET", "auth/token/lookup-self", "lookupSelf.revoked")
    with client(r, token=None) as c:
        for method in (
            sdk.AppRoleAuth("r", "the-bad-secret"),
            sdk.UserpassAuth("u", "the-bad-password"),
            sdk.JwtAuth("j", "the.bad.jwt"),
            sdk.KubernetesAuth("k", jwt="the.k8s.jwt"),
            sdk.TokenAuth("s.revoked-token"),
        ):
            with pytest.raises(sdk.AuthenticationError) as info:
                c.auth.login(method)
            for secret in method.secrets():
                assert secret not in str(info.value)
        with pytest.raises(sdk.ConfigError, match="cannot read"):
            c.auth.login(sdk.KubernetesAuth("k", str(tmp_path / "missing")))
        empty = tmp_path / "empty"
        empty.write_text("  ", encoding="utf-8")
        with pytest.raises(sdk.ConfigError, match="is empty"):
            c.auth.login(sdk.KubernetesAuth("k", str(empty)))
    for bad in (
        lambda: sdk.TokenAuth(""),
        lambda: sdk.JwtAuth("r", ""),
        lambda: sdk.UserpassAuth("u", ""),
    ):
        with pytest.raises(sdk.ConfigError):
            bad()
    with pytest.raises(sdk.ValidationError):
        sdk.AppRoleAuth(" ")
    r = Router().on("POST", "auth/approle/login", ok({}))
    with client(r) as c, pytest.raises(sdk.UnavailableError, match="no auth block"):
        c.auth.login(sdk.AppRoleAuth("r", "s"))


def test_custom_auth_method() -> None:
    class Custom(sdk.AuthMethod):
        method = "custom"

        def login_operation(self) -> Any:
            from grow_openbao.auth import login_post

            return login_post("auth/custom/login", {"x": "y"}, "auth.custom.login")

    r = Router().on("POST", "auth/custom/login", auth_reply("s.custom"))
    with client(r) as c:
        assert c.auth.login(Custom()).client_token.reveal() == "s.custom"
        assert Custom().secrets() == []


def test_self_service_and_create_token() -> None:
    r = Router()
    r.on("GET", "auth/token/lookup-self", "lookupSelf.ok")
    r.on("POST", "auth/token/renew-self", "renewSelf.ok", "renewSelf.not-renewable")
    r.on("POST", "auth/token/revoke-self", "revokeSelf.ok")
    r.on("POST", "auth/token/create", "createToken.ok", "createToken.permission-denied")
    r.on("POST", "auth/token/create/myrole", "createToken.orphan")
    with client(r) as c:
        me = c.auth.lookup_self()
        assert me.policies and me.ttl_s >= 0 and me.path
        assert me.creation_time is not None
        renewed = c.auth.renew_self(1800)
        assert r.last().json == {"increment": "1800s"}
        assert renewed.lease_duration_s > 0
        with pytest.raises(sdk.ValidationError):
            c.auth.renew_self()
        assert r.last().json == {}
        created = c.auth.create_token(
            policies=["default"],
            ttl_s=600,
            explicit_max_ttl_s=1200,
            renewable=True,
            display_name="py",
            meta={"a": "b"},
            num_uses=0,
            no_parent=False,
            no_default_policy=False,
            period_s=None,
        )
        assert created.client_token
        assert r.last().json == {
            "policies": ["default"],
            "ttl": "600s",
            "explicit_max_ttl": "1200s",
            "renewable": True,
            "display_name": "py",
            "meta": {"a": "b"},
            "num_uses": 0,
            "no_parent": False,
            "no_default_policy": False,
        }
        with pytest.raises(sdk.PermissionDeniedError):
            c.auth.create_token()
        assert c.auth.create_token(role="myrole").orphan
        with pytest.raises(sdk.ValidationError):
            c.auth.create_token(num_uses=-1)
        c.auth.revoke_self()
        assert c.token is None


def test_token_renewer_renews_until_capped_then_expires() -> None:
    clock = FakeClock()
    r = Router()
    r.on(
        "POST",
        "auth/token/renew-self",
        auth_reply(ttl=30),
        err(500, "flaky"),  # retryable: retried halfway to expiry
        auth_reply(ttl=10),  # capped (less than requested): final
    )
    renewals: list[sdk.TokenRenewal] = []
    errors: list[BaseException] = []
    expired: list[int] = []
    with client(r, retry=sdk.RetryPolicy(max_retries=0)) as c:
        renewer = sdk.TokenRenewer(
            c.auth,
            increment_s=30,
            on_renew=renewals.append,
            on_error=errors.append,
            on_expire=lambda: expired.append(1),
            clock=clock,
            wait=clock.wait,
        )
        renewer.start(sdk.LeaseState(30, True), background=False)
        assert [x.ttl_s for x in renewals] == [30, 10]
        assert len(errors) == 1 and isinstance(errors[0], sdk.UnavailableError)
        assert expired == [1] and renewer.expired and not renewer.running
        assert clock.waits == [20.0, 20.0, 5.0, 10.0]
        renewer.start()  # second start is a no-op
        renewer.stop()


def test_token_renewer_reauth_and_non_retryable_errors() -> None:
    clock = FakeClock()
    r = Router()
    r.on("POST", "auth/approle/login", err(500, "down"), auth_reply("s.relogin", ttl=0))
    r.on("POST", "auth/token/renew-self", err(400, "lease is not renewable"))
    seen: list[sdk.TokenRenewal] = []
    with client(r, retry=sdk.RetryPolicy(max_retries=0)) as c:
        renewer = sdk.TokenRenewer(
            c.auth,
            reauth=sdk.AppRoleAuth("r", "s"),
            on_renew=seen.append,
            clock=clock,
            wait=clock.wait,
            min_delay_s=0.5,
            renew_fraction=5,  # invalid → default 2/3
        )
        renewer.start(sdk.LeaseState(30, True), background=False)
        # renew fails (non-retryable) → reacquire; first login fails, retried; second login
        # returns a token without TTL → idle.
        assert [s.reauthenticated for s in seen] == [True]
        assert c.token is not None and c.token.reveal() == "s.relogin"
        assert renewer.expires_at is None and not renewer.expired


def test_token_renewer_reacquire_gives_up_at_expiry() -> None:
    clock = FakeClock()
    r = Router().on("POST", "auth/approle/login", err(500, "down"))
    expired: list[int] = []
    with client(r, retry=sdk.RetryPolicy(max_retries=0)) as c:
        renewer = sdk.TokenRenewer(
            c.auth,
            reauth=sdk.AppRoleAuth("r", "s"),
            on_expire=lambda: expired.append(1),
            on_error=lambda e: (_ for _ in ()).throw(RuntimeError("callbacks may fail")),
            clock=clock,
            wait=clock.wait,
        )
        renewer.start(sdk.LeaseState(3, False), background=False)
    assert expired == [1]


def test_token_renewer_stop_and_background() -> None:
    r = Router()
    r.on("GET", "auth/token/lookup-self", "lookupSelf.ok")
    r.on("POST", "auth/token/renew-self", auth_reply(ttl=3600))
    renewed = threading.Event()
    with client(r) as c:
        renewer = c.auth.start_renewer(on_renew=lambda _: renewed.set())
        assert renewer.running and c.auth.active_renewers == 1
        assert renewer.expires_at is not None
        renewer.stop()
        renewer.stop()
        assert not renewer.running and c.auth.active_renewers == 0
    r = Router()
    r.on("POST", "auth/approle/login", auth_reply(ttl=1))
    r.on("POST", "auth/token/renew-self", auth_reply(ttl=1))
    with client(r) as c:
        c.auth.login(
            sdk.AppRoleAuth("r", "s"),
            auto_renew={"min_delay_s": 0.05, "on_renew": lambda _: renewed.set()},
        )
        assert renewed.wait(5)
        assert c.auth.active_renewers == 1
    assert c.auth.active_renewers == 0
    r = Router().on("GET", "auth/token/lookup-self", "lookupSelf.revoked")
    with client(r) as c, pytest.raises(sdk.PermissionDeniedError):
        c.auth.start_renewer()
    assert c.auth.active_renewers == 0


def test_stop_during_renew_discards_result() -> None:
    clock = FakeClock()
    r = Router()
    with client(r) as c:
        holder: dict[str, sdk.TokenRenewer] = {}

        def renew(_: Any) -> Any:
            holder["r"].stop()
            return auth_reply(ttl=30)

        r.on("POST", "auth/token/renew-self", auth_reply(ttl=30))
        renewer = sdk.TokenRenewer(c.auth, clock=clock, wait=clock.wait, on_renew=renew)
        holder["r"] = renewer
        renewer.start(sdk.LeaseState(30, True), background=False)
        assert not renewer.running


# --------------------------------------------------------------------------- async


async def test_async_auth_flow() -> None:
    r = Router()
    r.on("POST", "auth/userpass/login/u", "userpassLogin.ok")
    r.on("GET", "auth/token/lookup-self", "lookupSelf.ok")
    r.on("POST", "auth/token/renew-self", auth_reply(ttl=3600))
    r.on("POST", "auth/token/revoke-self", "revokeSelf.ok")
    r.on("POST", "auth/token/create", "createToken.ok")
    async with aclient(r, token=None) as c:
        await c.auth.login(sdk.UserpassAuth("u", "pw-123456"))
        assert c.token is not None
        assert (await c.auth.lookup_self()).policies
        assert (await c.auth.renew_self(60)).lease_duration_s == 3600
        assert (await c.auth.create_token(ttl_s=60)).client_token
        renewer = await c.auth.start_renewer()
        assert renewer.running and c.auth.active_renewers == 1
        await asyncio.sleep(0.01)
        assert renewer.expires_at is not None
        await renewer.start()
        await c.auth.revoke_self()
        assert c.token is None and not renewer.running and c.auth.active_renewers == 0
        await c.auth.login(sdk.UserpassAuth("u", "pw-123456"), auto_renew=True)
        assert c.auth.active_renewers == 1
    assert c.auth.active_renewers == 0


async def test_async_token_renewer_fake_sleep() -> None:
    clock = FakeClock()

    async def sleep(delay: float) -> None:
        clock.now += delay
        clock.waits.append(delay)

    r = Router()
    r.on("POST", "auth/token/renew-self", auth_reply(ttl=30), err(400, "nope"))
    r.on("POST", "auth/approle/login", auth_reply(ttl=0))
    expired = asyncio.Event()
    async with aclient(r, retry=sdk.RetryPolicy(max_retries=0)) as c:
        renewer = sdk.AsyncTokenRenewer(
            c.auth, clock=clock, sleep=sleep, on_expire=expired.set, increment_s=30
        )
        await renewer.start(sdk.LeaseState(30, True))
        await asyncio.wait_for(expired.wait(), 5)
        assert renewer.expired and not renewer.running
        relog = sdk.AsyncTokenRenewer(
            c.auth, clock=clock, sleep=sleep, reauth=sdk.AppRoleAuth("r", "s")
        )
        await relog.start(sdk.LeaseState(3, False))
        await asyncio.sleep(0.05)
        assert c.token is not None and c.token.reveal() != TOKEN
    r = Router().on("GET", "auth/token/lookup-self", "lookupSelf.revoked")
    async with aclient(r) as c:
        with pytest.raises(sdk.PermissionDeniedError):
            await c.auth.start_renewer()
        assert c.auth.active_renewers == 0
