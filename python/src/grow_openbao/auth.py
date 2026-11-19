"""Auth methods, token self-service and automatic token renewal (API.md §3)."""

from __future__ import annotations

import abc
import dataclasses
import datetime as _dt
import threading
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any

from ._api import (
    AsyncModule,
    Call,
    Duration,
    Op,
    SyncModule,
    compact,
    data,
    encode_path,
    envelope,
    integer,
    opt_duration,
    opt_secret,
    parse_time,
    require_text,
    reveal,
    seconds,
    string_map,
    strings,
    text,
    trim_slashes,
    unexpected,
)
from ._core import ConfigError, Secret, ValidationError, to_seconds
from ._renewal import AsyncRenewalLoop, LeaseState, RenewalLoop, RenewalOptions, Result

__all__ = [
    "AuthInfo",
    "TokenInfo",
    "TokenRenewal",
    "AuthMethod",
    "TokenAuth",
    "AppRoleAuth",
    "KubernetesAuth",
    "JwtAuth",
    "UserpassAuth",
    "Auth",
    "AsyncAuth",
    "TokenRenewer",
    "AsyncTokenRenewer",
    "LeaseState",
]


@dataclasses.dataclass(frozen=True)
class AuthInfo:
    """Result of a login or token creation. The token and accessor are :class:`Secret`."""

    client_token: Secret
    accessor: Secret | None
    #: All policies of the token.
    policies: list[str]
    #: Policies attached to the token itself.
    token_policies: list[str]
    #: Auth metadata (e.g. ``role_name``, ``username``).
    metadata: dict[str, str]
    #: Token TTL in seconds (``0`` = no expiry).
    lease_duration_s: float
    renewable: bool
    entity_id: str
    #: ``service`` or ``batch``.
    token_type: str
    orphan: bool
    #: Remaining uses (``0`` = unlimited).
    num_uses: int


@dataclasses.dataclass(frozen=True)
class TokenInfo:
    """Token properties from :meth:`Auth.lookup_self`."""

    id: Secret
    accessor: Secret | None
    policies: list[str]
    #: Remaining TTL in seconds (``0`` = no expiry).
    ttl_s: float
    creation_ttl_s: float
    creation_time: _dt.datetime | None
    expire_time: _dt.datetime | None
    issue_time: _dt.datetime | None
    renewable: bool
    display_name: str
    meta: dict[str, str]
    num_uses: int
    orphan: bool
    #: Creation path, e.g. ``auth/token/create``.
    path: str
    #: ``service`` or ``batch``.
    type: str
    explicit_max_ttl_s: float
    entity_id: str


@dataclasses.dataclass(frozen=True)
class TokenRenewal:
    """One renewal or re-login seen by a :class:`TokenRenewer` ``on_renew`` callback."""

    ttl_s: float
    renewable: bool
    #: ``True`` when the token was replaced by a new login.
    reauthenticated: bool


def auth_info(env: Mapping[str, Any], operation: str) -> AuthInfo:
    """The ``auth`` block of an envelope; raises when it is missing."""
    auth = env.get("auth")
    if not isinstance(auth, Mapping) or not isinstance(auth.get("client_token"), str):
        raise unexpected(operation, "response has no auth block")
    return AuthInfo(
        client_token=Secret(auth["client_token"]),
        accessor=opt_secret(auth.get("accessor")),
        policies=strings(auth.get("policies")),
        token_policies=strings(auth.get("token_policies")),
        metadata=string_map(auth.get("metadata")),
        lease_duration_s=seconds(auth.get("lease_duration")),
        renewable=auth.get("renewable") is True,
        entity_id=text(auth.get("entity_id")),
        token_type=text(auth.get("token_type")),
        orphan=auth.get("orphan") is True,
        num_uses=integer(auth.get("num_uses")),
    )


def _token_info(d: Mapping[str, Any]) -> TokenInfo:
    return TokenInfo(
        id=Secret(text(d.get("id"))),
        accessor=opt_secret(d.get("accessor")),
        policies=strings(d.get("policies")),
        ttl_s=seconds(d.get("ttl")),
        creation_ttl_s=seconds(d.get("creation_ttl")),
        creation_time=parse_time(d.get("creation_time")),
        expire_time=parse_time(d.get("expire_time")),
        issue_time=parse_time(d.get("issue_time")),
        renewable=d.get("renewable") is True,
        display_name=text(d.get("display_name")),
        meta=string_map(d.get("meta")),
        num_uses=integer(d.get("num_uses")),
        orphan=d.get("orphan") is True,
        path=text(d.get("path")),
        type=text(d.get("type")),
        explicit_max_ttl_s=seconds(d.get("explicit_max_ttl")),
        entity_id=text(d.get("entity_id")),
    )


def lookup_op(token: str | None = None, *, login: bool = False) -> Op[TokenInfo]:
    """``GET auth/token/lookup-self`` with the client token (or ``token``)."""
    call = Call("GET", "auth/token/lookup-self", "auth.lookupSelf", login=login)
    if token is not None:
        call = dataclasses.replace(call, token=token)
    found = yield from data(call)
    return _token_info(found)


def login_post(path: str, body: Mapping[str, Any], operation: str) -> Op[AuthInfo]:
    """``POST <path>`` without a token; returns the ``auth`` block (failures → authentication)."""
    env = yield from envelope(
        Call("POST", path, operation, json=dict(body), token=None, login=True)
    )
    return auth_info(env, operation)


# --------------------------------------------------------------------------- auth methods


class AuthMethod(abc.ABC):
    """An auth method usable with ``client.auth.login(method)``.

    Implement :meth:`login_operation` to add a method (use :func:`login_post`).
    """

    #: Short method name, e.g. ``approle``.
    method: str = ""

    @abc.abstractmethod
    def login_operation(self) -> Op[AuthInfo]:
        """The login as an SDK operation (a generator of requests)."""

    def secrets(self) -> list[str]:
        """Credential values to redact from error messages."""
        return []


class TokenAuth(AuthMethod):
    """Uses an existing token; ``login`` checks it with ``lookup-self``."""

    method = "token"

    def __init__(self, token: str | Secret) -> None:
        if not reveal(token):
            raise ConfigError("TokenAuth: token must not be empty")
        self._token = Secret(token)

    def login_operation(self) -> Op[AuthInfo]:
        info = yield from lookup_op(self._token.reveal(), login=True)
        return AuthInfo(
            client_token=self._token,
            accessor=info.accessor,
            policies=info.policies,
            token_policies=info.policies,
            metadata=info.meta,
            lease_duration_s=info.ttl_s,
            renewable=info.renewable,
            entity_id=info.entity_id,
            token_type=info.type,
            orphan=info.orphan,
            num_uses=info.num_uses,
        )

    def secrets(self) -> list[str]:
        return [self._token.reveal()]

    def __repr__(self) -> str:
        return "TokenAuth([REDACTED])"


class AppRoleAuth(AuthMethod):
    """AppRole login: ``POST auth/<mount>/login {role_id, secret_id}``.

    ``secret_id`` may be omitted for roles with ``bind_secret_id=false``.
    """

    method = "approle"

    def __init__(
        self, role_id: str, secret_id: str | Secret | None = None, *, mount: str = "approle"
    ) -> None:
        self.role_id = require_text(role_id, "role_id", "AppRoleAuth")
        self._secret_id = Secret(secret_id) if secret_id else None
        self.mount = trim_slashes(mount)

    def login_operation(self) -> Op[AuthInfo]:
        body = compact(
            {
                "role_id": self.role_id,
                "secret_id": self._secret_id.reveal() if self._secret_id else None,
            }
        )
        return login_post(
            encode_path("auth", self.mount, "login"), body, f"auth.approle.login {self.mount}"
        )

    def secrets(self) -> list[str]:
        return [self._secret_id.reveal()] if self._secret_id else []

    def __repr__(self) -> str:
        return f"AppRoleAuth({self.mount}, role_id={self.role_id}, secret_id=[REDACTED])"


class KubernetesAuth(AuthMethod):
    """Kubernetes login: ``POST auth/<mount>/login {role, jwt}`` with the service account token.

    The token is read from ``jwt_path`` at login time unless ``jwt`` is given.
    """

    method = "kubernetes"
    #: Default service account token path inside a pod.
    DEFAULT_JWT_PATH = "/var/run/secrets/kubernetes.io/serviceaccount/token"

    def __init__(
        self,
        role: str,
        jwt_path: str | None = None,
        *,
        jwt: str | Secret | None = None,
        mount: str = "kubernetes",
    ) -> None:
        self.role = require_text(role, "role", "KubernetesAuth")
        self.jwt_path = jwt_path or self.DEFAULT_JWT_PATH
        self._jwt = Secret(jwt) if jwt else None
        self.mount = trim_slashes(mount)

    def _read_jwt(self) -> str:
        if self._jwt is not None:
            return self._jwt.reveal()
        try:
            value = Path(self.jwt_path).read_text(encoding="utf-8").strip()
        except OSError:
            raise ConfigError(
                f"auth.kubernetes.login: cannot read the service account token at {self.jwt_path}"
            ) from None
        if not value:
            raise ConfigError(f"auth.kubernetes.login: {self.jwt_path} is empty")
        return value

    def login_operation(self) -> Op[AuthInfo]:
        body = {"role": self.role, "jwt": self._read_jwt()}
        return login_post(
            encode_path("auth", self.mount, "login"), body, f"auth.kubernetes.login {self.mount}"
        )

    def secrets(self) -> list[str]:
        return [self._jwt.reveal()] if self._jwt else []

    def __repr__(self) -> str:
        return f"KubernetesAuth({self.mount}, role={self.role})"


class JwtAuth(AuthMethod):
    """JWT/OIDC login with a JWT: ``POST auth/<mount>/login {role, jwt}``."""

    method = "jwt"

    def __init__(self, role: str, jwt: str | Secret, *, mount: str = "jwt") -> None:
        self.role = require_text(role, "role", "JwtAuth")
        if not reveal(jwt):
            raise ConfigError("JwtAuth: jwt must not be empty")
        self._jwt = Secret(jwt)
        self.mount = trim_slashes(mount)

    def login_operation(self) -> Op[AuthInfo]:
        body = {"role": self.role, "jwt": self._jwt.reveal()}
        return login_post(
            encode_path("auth", self.mount, "login"), body, f"auth.jwt.login {self.mount}"
        )

    def secrets(self) -> list[str]:
        return [self._jwt.reveal()]

    def __repr__(self) -> str:
        return f"JwtAuth({self.mount}, role={self.role}, jwt=[REDACTED])"


class UserpassAuth(AuthMethod):
    """Username/password login: ``POST auth/<mount>/login/<username> {password}``."""

    method = "userpass"

    def __init__(self, username: str, password: str | Secret, *, mount: str = "userpass") -> None:
        self.username = require_text(username, "username", "UserpassAuth")
        if not reveal(password):
            raise ConfigError("UserpassAuth: password must not be empty")
        self._password = Secret(password)
        self.mount = trim_slashes(mount)

    def login_operation(self) -> Op[AuthInfo]:
        return login_post(
            encode_path("auth", self.mount, "login", self.username),
            {"password": self._password.reveal()},
            f"auth.userpass.login {self.mount}",
        )

    def secrets(self) -> list[str]:
        return [self._password.reveal()]

    def __repr__(self) -> str:
        return f"UserpassAuth({self.mount}, username={self.username}, password=[REDACTED])"


# --------------------------------------------------------------------------- operations


def _renew_self_op(increment_s: Duration | None) -> Op[AuthInfo]:
    env = yield from envelope(
        Call(
            "POST",
            "auth/token/renew-self",
            "auth.renewSelf",
            json=compact({"increment": opt_duration(increment_s)}),
        )
    )
    return auth_info(env, "auth.renewSelf")


def _revoke_self_op() -> Op[None]:
    yield Call("POST", "auth/token/revoke-self", "auth.revokeSelf")


def _create_token_op(
    *,
    policies: Sequence[str] | None,
    ttl_s: Duration | None,
    explicit_max_ttl_s: Duration | None,
    renewable: bool | None,
    display_name: str | None,
    meta: Mapping[str, str] | None,
    num_uses: int | None,
    no_parent: bool | None,
    no_default_policy: bool | None,
    period_s: Duration | None,
    role: str | None,
) -> Op[AuthInfo]:
    if num_uses is not None and num_uses < 0:
        raise ValidationError("auth.createToken: num_uses must be >= 0")
    path = "auth/token/create" if role is None else encode_path("auth/token/create", role)
    body = compact(
        {
            "policies": list(policies) if policies is not None else None,
            "ttl": opt_duration(ttl_s),
            "explicit_max_ttl": opt_duration(explicit_max_ttl_s),
            "renewable": renewable,
            "display_name": display_name,
            "meta": dict(meta) if meta is not None else None,
            "num_uses": num_uses,
            "no_parent": no_parent,
            "no_default_policy": no_default_policy,
            "period": opt_duration(period_s),
        }
    )
    env = yield from envelope(Call("POST", path, "auth.createToken", json=body))
    return auth_info(env, "auth.createToken")


def _renewal_options(
    increment_s: Duration | None,
    renew_fraction: float,
    min_delay_s: float,
    on_renew: Callable[[TokenRenewal], None] | None,
    on_error: Callable[[BaseException], None] | None,
    on_expire: Callable[[], None] | None,
    clock: Callable[[], float] | None,
) -> RenewalOptions:
    opts = RenewalOptions(
        increment_s=None if increment_s is None else to_seconds(increment_s),
        renew_fraction=renew_fraction,
        min_delay_s=min_delay_s,
        on_renew=on_renew,
        on_error=on_error,
        on_expire=on_expire,
    )
    if clock is not None:
        opts.clock = clock
    return opts


def _renewal(info: AuthInfo, reauthenticated: bool) -> Result:
    return (
        LeaseState(info.lease_duration_s, info.renewable),
        TokenRenewal(info.lease_duration_s, info.renewable, reauthenticated),
    )


# --------------------------------------------------------------------------- sync


class TokenRenewer:
    """Renews the client token at 2/3 of its TTL (``renew-self``).

    When the token cannot be renewed any more it logs in again with ``reauth`` or calls
    ``on_expire`` once at expiry. Stopped by :meth:`stop` or ``client.close()``.
    Create it with :meth:`Auth.start_renewer` (or ``login(..., auto_renew=True)``).
    """

    def __init__(
        self,
        auth: Auth,
        *,
        reauth: AuthMethod | None = None,
        increment_s: Duration | None = None,
        renew_fraction: float = 2 / 3,
        min_delay_s: float = 0.5,
        on_renew: Callable[[TokenRenewal], None] | None = None,
        on_error: Callable[[BaseException], None] | None = None,
        on_expire: Callable[[], None] | None = None,
        clock: Callable[[], float] | None = None,
        wait: Callable[[float], bool] | None = None,
    ) -> None:
        self._auth = auth
        opts = _renewal_options(
            increment_s, renew_fraction, min_delay_s, on_renew, on_error, on_expire, clock
        )

        def renew(increment: float | None) -> Result:
            return _renewal(auth.renew_self(increment), False)

        def reacquire() -> Result:
            assert reauth is not None
            return _renewal(auth.login(reauth), True)

        self._loop = RenewalLoop(opts, renew, reacquire if reauth else None, wait=wait)
        self._started = False

    def start(self, initial: LeaseState | None = None, *, background: bool = True) -> None:
        """Start renewing; without ``initial`` the TTL is read with ``lookup_self()``.

        A token without TTL (e.g. root) needs no renewal; the renewer then stays idle.
        """
        if self._started:
            return
        self._started = True
        if initial is None:
            info = self._auth.lookup_self()
            initial = LeaseState(info.ttl_s, info.renewable)
        self._loop.start(initial, background=background)

    def stop(self) -> None:
        """Stop renewing (idempotent)."""
        self._loop.stop()
        self._auth._forget(self)

    @property
    def running(self) -> bool:
        """Whether the renewer is active."""
        return self._started and self._loop.running

    @property
    def expired(self) -> bool:
        """Whether ``on_expire`` fired."""
        return self._loop.status.expired

    @property
    def expires_at(self) -> _dt.datetime | None:
        """Expiry of the current token, ``None`` when it never expires or is unknown."""
        return self._loop.status.expires_at


class Auth(SyncModule):
    """Logins, token self-service and token renewal: ``client.auth``."""

    __slots__ = ("_lock", "_renewers")

    def __init__(self, runner: Any) -> None:
        super().__init__(runner)
        self._renewers: set[TokenRenewer] = set()
        self._lock = threading.Lock()

    def login(
        self,
        method: AuthMethod,
        *,
        set_token: bool = True,
        auto_renew: bool | Mapping[str, Any] = False,
    ) -> AuthInfo:
        """Log in with an auth method and (by default) use the new token for this client.

        Failed logins raise :class:`AuthenticationError`. ``auto_renew=True`` (or a mapping of
        :meth:`start_renewer` keyword arguments) starts a :class:`TokenRenewer` that logs in
        again with the same method when the token can no longer be renewed.
        """
        session = self._runner.session
        session.remember(*method.secrets())
        info = self._run(method.login_operation())
        session.remember(info.client_token)
        if set_token:
            session.token = info.client_token
        if auto_renew:
            kwargs = dict(auto_renew) if isinstance(auto_renew, Mapping) else {}
            kwargs["reauth"] = method
            renewer = self._track(TokenRenewer(self, **kwargs))
            renewer.start(LeaseState(info.lease_duration_s, info.renewable))
        return info

    def lookup_self(self) -> TokenInfo:
        """Properties of the client token: ``GET auth/token/lookup-self``."""
        return self._run(lookup_op())

    def renew_self(self, increment_s: Duration | None = None) -> AuthInfo:
        """Renew the client token (``POST auth/token/renew-self``).

        ``increment_s`` requests a TTL; the granted TTL is ``lease_duration_s`` (capped by the
        maximum TTL). Non-renewable tokens raise :class:`ValidationError`.
        """
        return self._run(_renew_self_op(increment_s))

    def revoke_self(self) -> None:
        """Revoke the client token (``POST auth/token/revoke-self``) and forget it."""
        self._run(_revoke_self_op())
        self.stop_renewers()
        self._runner.session.token = None

    def create_token(
        self,
        *,
        policies: Sequence[str] | None = None,
        ttl_s: Duration | None = None,
        explicit_max_ttl_s: Duration | None = None,
        renewable: bool | None = None,
        display_name: str | None = None,
        meta: Mapping[str, str] | None = None,
        num_uses: int | None = None,
        no_parent: bool | None = None,
        no_default_policy: bool | None = None,
        period_s: Duration | None = None,
        role: str | None = None,
    ) -> AuthInfo:
        """Create a child (or orphan, ``no_parent=True``) token: ``POST auth/token/create``."""
        info = self._run(
            _create_token_op(
                policies=policies,
                ttl_s=ttl_s,
                explicit_max_ttl_s=explicit_max_ttl_s,
                renewable=renewable,
                display_name=display_name,
                meta=meta,
                num_uses=num_uses,
                no_parent=no_parent,
                no_default_policy=no_default_policy,
                period_s=period_s,
                role=role,
            )
        )
        self._runner.session.remember(info.client_token)
        return info

    def start_renewer(self, **options: Any) -> TokenRenewer:
        """Start a :class:`TokenRenewer` for the current token (TTL from ``lookup_self()``).

        Keyword arguments: ``reauth``, ``increment_s``, ``renew_fraction``, ``min_delay_s``,
        ``on_renew``, ``on_error``, ``on_expire``. Stopped by ``client.close()``.
        """
        renewer = self._track(TokenRenewer(self, **options))
        try:
            renewer.start()
        except BaseException:
            renewer.stop()
            raise
        return renewer

    def _track(self, renewer: TokenRenewer) -> TokenRenewer:
        with self._lock:
            self._renewers.add(renewer)
        return renewer

    def _forget(self, renewer: TokenRenewer) -> None:
        with self._lock:
            self._renewers.discard(renewer)

    @property
    def active_renewers(self) -> int:
        """Number of active renewers."""
        return len(self._renewers)

    def stop_renewers(self) -> None:
        """Stop every renewer started through this API (idempotent)."""
        with self._lock:
            renewers = list(self._renewers)
        for renewer in renewers:
            renewer.stop()


# --------------------------------------------------------------------------- async


class AsyncTokenRenewer:
    """Async :class:`TokenRenewer` (an asyncio task); see :meth:`AsyncAuth.start_renewer`."""

    def __init__(
        self,
        auth: AsyncAuth,
        *,
        reauth: AuthMethod | None = None,
        increment_s: Duration | None = None,
        renew_fraction: float = 2 / 3,
        min_delay_s: float = 0.5,
        on_renew: Callable[[TokenRenewal], None] | None = None,
        on_error: Callable[[BaseException], None] | None = None,
        on_expire: Callable[[], None] | None = None,
        clock: Callable[[], float] | None = None,
        sleep: Callable[[float], Any] | None = None,
    ) -> None:
        self._auth = auth
        opts = _renewal_options(
            increment_s, renew_fraction, min_delay_s, on_renew, on_error, on_expire, clock
        )

        async def renew(increment: float | None) -> Result:
            return _renewal(await auth.renew_self(increment), False)

        async def reacquire() -> Result:
            assert reauth is not None
            return _renewal(await auth.login(reauth), True)

        extra: dict[str, Any] = {} if sleep is None else {"sleep": sleep}
        self._loop = AsyncRenewalLoop(opts, renew, reacquire if reauth else None, **extra)
        self._started = False

    async def start(self, initial: LeaseState | None = None) -> None:
        """Start renewing (TTL from ``lookup_self()`` when ``initial`` is not given)."""
        if self._started:
            return
        self._started = True
        if initial is None:
            info = await self._auth.lookup_self()
            initial = LeaseState(info.ttl_s, info.renewable)
        self._loop.start(initial)

    def stop(self) -> None:
        """Stop renewing (idempotent)."""
        self._loop.stop()
        self._auth._forget(self)

    @property
    def running(self) -> bool:
        """Whether the renewer is active."""
        return self._started and self._loop.running

    @property
    def expired(self) -> bool:
        """Whether ``on_expire`` fired."""
        return self._loop.status.expired

    @property
    def expires_at(self) -> _dt.datetime | None:
        """Expiry of the current token, ``None`` when it never expires or is unknown."""
        return self._loop.status.expires_at


class AsyncAuth(AsyncModule):
    """Async :class:`Auth`: ``async_client.auth``."""

    __slots__ = ("_renewers",)

    def __init__(self, runner: Any) -> None:
        super().__init__(runner)
        self._renewers: set[AsyncTokenRenewer] = set()

    async def login(
        self,
        method: AuthMethod,
        *,
        set_token: bool = True,
        auto_renew: bool | Mapping[str, Any] = False,
    ) -> AuthInfo:
        """See :meth:`Auth.login`."""
        session = self._runner.session
        session.remember(*method.secrets())
        info = await self._run(method.login_operation())
        session.remember(info.client_token)
        if set_token:
            session.token = info.client_token
        if auto_renew:
            kwargs = dict(auto_renew) if isinstance(auto_renew, Mapping) else {}
            kwargs["reauth"] = method
            renewer = AsyncTokenRenewer(self, **kwargs)
            self._renewers.add(renewer)
            await renewer.start(LeaseState(info.lease_duration_s, info.renewable))
        return info

    async def lookup_self(self) -> TokenInfo:
        """See :meth:`Auth.lookup_self`."""
        return await self._run(lookup_op())

    async def renew_self(self, increment_s: Duration | None = None) -> AuthInfo:
        """See :meth:`Auth.renew_self`."""
        return await self._run(_renew_self_op(increment_s))

    async def revoke_self(self) -> None:
        """See :meth:`Auth.revoke_self`."""
        await self._run(_revoke_self_op())
        self.stop_renewers()
        self._runner.session.token = None

    async def create_token(
        self,
        *,
        policies: Sequence[str] | None = None,
        ttl_s: Duration | None = None,
        explicit_max_ttl_s: Duration | None = None,
        renewable: bool | None = None,
        display_name: str | None = None,
        meta: Mapping[str, str] | None = None,
        num_uses: int | None = None,
        no_parent: bool | None = None,
        no_default_policy: bool | None = None,
        period_s: Duration | None = None,
        role: str | None = None,
    ) -> AuthInfo:
        """See :meth:`Auth.create_token`."""
        info = await self._run(
            _create_token_op(
                policies=policies,
                ttl_s=ttl_s,
                explicit_max_ttl_s=explicit_max_ttl_s,
                renewable=renewable,
                display_name=display_name,
                meta=meta,
                num_uses=num_uses,
                no_parent=no_parent,
                no_default_policy=no_default_policy,
                period_s=period_s,
                role=role,
            )
        )
        self._runner.session.remember(info.client_token)
        return info

    async def start_renewer(self, **options: Any) -> AsyncTokenRenewer:
        """See :meth:`Auth.start_renewer` (call from a running event loop)."""
        renewer = AsyncTokenRenewer(self, **options)
        self._renewers.add(renewer)
        try:
            await renewer.start()
        except BaseException:
            renewer.stop()
            raise
        return renewer

    def _forget(self, renewer: AsyncTokenRenewer) -> None:
        self._renewers.discard(renewer)

    @property
    def active_renewers(self) -> int:
        """Number of active renewers."""
        return len(self._renewers)

    def stop_renewers(self) -> None:
        """Stop every renewer started through this API (idempotent)."""
        for renewer in list(self._renewers):
            renewer.stop()
