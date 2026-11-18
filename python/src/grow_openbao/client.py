"""OpenBao clients (sync and async), service-owned.

>>> client = OpenBaoClient.from_env()                    # doctest: +SKIP
>>> client.kv().write("app/db", {"password": "s3cret"})  # doctest: +SKIP
>>> client.kv().read("app/db").data                      # doctest: +SKIP
"""

from __future__ import annotations

import contextlib
import dataclasses
import datetime as _dt
import threading
import time
from collections.abc import Iterator, Mapping
from types import TracebackType
from typing import Any, Literal

import httpx

from ._api import (
    AsyncRunner,
    Call,
    Op,
    Session,
    SyncRunner,
    cancel_scope,
    decode_envelope,
    encode_path,
    map_vault_error,
    seconds,
    strings,
    text,
    trim_slashes,
    unexpected,
)
from ._core import (
    AsyncHttpTransport,
    CancelledError,
    CancelToken,
    ConfigError,
    HealthStatus,
    HttpTransport,
    ResourceRegistry,
    Secret,
    ServiceError,
    TimeoutError,
    UnavailableError,
    error_from_status,
    to_seconds,
)
from .auth import AsyncAuth, Auth
from .config import OpenBaoConfig
from .database import AsyncDatabase, Database
from .kv import AsyncKvMount, AsyncKvV1, AsyncKvV2, KvMount, KvV1, KvV2
from .leases import AsyncLeaseManager, LeaseManager
from .pki import AsyncPki, Pki
from .provider import AsyncOpenBaoSecretsProvider, OpenBaoSecretsProvider
from .system import HEALTH_QUERY, AsyncSys, HealthResponse, Sys, to_health, version_op
from .transit import AsyncTransit, Transit
from .wrapping import AsyncWrapping, WrapInfo, Wrapping, wrap_info

__all__ = ["OpenBaoClient", "AsyncOpenBaoClient", "RawResponse"]

Method = Literal["GET", "POST", "PUT", "PATCH", "DELETE"]


@dataclasses.dataclass(frozen=True)
class RawResponse:
    """Result of :meth:`OpenBaoClient.request`: the decoded OpenBao envelope."""

    #: HTTP status (204 = no content).
    status: int
    data: dict[str, Any] | None = dataclasses.field(repr=False)
    lease_id: str
    lease_duration_s: float
    renewable: bool
    warnings: list[str]
    #: Set when the response was wrapped (``wrap_ttl_s``).
    wrap_info: WrapInfo | None = None


def _health_status(h: HealthResponse) -> HealthStatus:
    details = {
        "version": h.version,
        "initialized": str(h.initialized).lower(),
        "sealed": str(h.sealed).lower(),
        "standby": str(h.standby).lower(),
    }
    if h.cluster_name:
        details["clusterName"] = h.cluster_name
    return HealthStatus(healthy=h.state == "active", status=h.state, details=details)


def _health_error(err: ServiceError) -> HealthStatus:
    if isinstance(err, (CancelledError, ConfigError)):
        raise err
    word = "unreachable" if isinstance(err, (UnavailableError, TimeoutError)) else "unhealthy"
    details = {"error": err.message}
    if err.http_status is not None:
        details["httpStatus"] = str(err.http_status)
    return HealthStatus(healthy=False, status=word, details=details)


def _health_op() -> Op[HealthResponse]:
    # Every node state answers 200 thanks to HEALTH_QUERY; a proxy or server that ignores the
    # query still sends the health body with 429/473/501/503, which is parsed the same way.
    resp = yield Call(
        "GET",
        "sys/health",
        "health",
        params=HEALTH_QUERY,
        token=None,
        max_retries=0,
        raise_for_status=False,
    )
    try:
        body = decode_envelope(resp, "health")
    except ServiceError:
        body = {}
    if resp.ok or "initialized" in body:
        if not body:
            raise unexpected("health", "empty response body")
        return to_health(body)
    raise map_vault_error(
        error_from_status(resp.status, "health", content=resp.content, headers=resp.headers)
    )


def _ping_op() -> Op[None]:
    # lookup-self is allowed for every valid token: 400/401/403 mean bad credentials.
    yield Call("GET", "auth/token/lookup-self", "ping", login=True)


def _raw_op(
    method: Method,
    path: str,
    params: Mapping[str, Any] | None,
    json: Any,
    headers: Mapping[str, str] | None,
    list_: bool,
    wrap_ttl_s: float | _dt.timedelta | None,
    idempotent: bool | None,
) -> Op[RawResponse]:
    call = Call(
        method,
        encode_path(path),
        f"{method} {trim_slashes(path)}",
        params=params,
        json=json,
        headers=headers,
        list=list_,
        wrap_ttl=None if wrap_ttl_s is None else to_seconds(wrap_ttl_s),
        idempotent=idempotent,
    )
    resp = yield call
    env = decode_envelope(resp, call.operation)
    found = env.get("data")
    return RawResponse(
        status=resp.status,
        data=found if isinstance(found, dict) else None,
        lease_id=text(env.get("lease_id")),
        lease_duration_s=seconds(env.get("lease_duration")),
        renewable=env.get("renewable") is True,
        warnings=strings(env.get("warnings")),
        wrap_info=wrap_info(env.get("wrap_info")),
    )


class _ClientBase:
    config: OpenBaoConfig
    _session: Session

    def _setup(self, config: OpenBaoConfig | None) -> None:
        if config is None:
            config = OpenBaoConfig.from_env()
        self.config = config.validate()
        self._session = Session(config.token, config.namespace)
        self._resources = ResourceRegistry()
        self._closed = False

    def _known_secrets(self) -> list[str]:
        return self._session.known_secrets(self.config.known_secrets())

    @property
    def token(self) -> Secret | None:
        """The current client token (from the config, a login or :meth:`set_token`)."""
        return self._session.token

    def set_token(self, token: str | Secret | None) -> None:
        """Replace the client token (``None`` removes it)."""
        self._session.token = Secret(token) if token else None
        if token:
            self._session.remember(token)

    @property
    def closed(self) -> bool:
        """Whether :meth:`close` was called."""
        return self._closed

    @property
    def resources(self) -> ResourceRegistry:
        """Background resources (watchers) stopped by :meth:`close`."""
        return self._resources

    def _mount(self, mount: str | None) -> str:
        return trim_slashes(mount if mount is not None else self.config.kv_mount)


class OpenBaoClient(_ClientBase):
    """Synchronous OpenBao client. Thread-safe; use as a context manager or call
    :meth:`close`.

    Service modules: :attr:`auth`, :attr:`sys`, :attr:`wrapping`, :attr:`leases`,
    :meth:`kv`, :meth:`kv_v1`, :meth:`kv_v2`, :meth:`transit`, :meth:`database`, :meth:`pki`
    and :meth:`secrets` (the ``SecretsProvider``). Cancel calls from another thread with
    ``with client.cancellable(token): ...`` or the ``cancel=`` argument of the core methods.
    """

    def __init__(
        self,
        config: OpenBaoConfig | None = None,
        *,
        http_transport: httpx.BaseTransport | None = None,
    ) -> None:
        self._setup(config)
        self._transport = HttpTransport(
            self.config, known_secrets=self._known_secrets, http_transport=http_transport
        )
        self._runner = SyncRunner(self._transport, self._session)
        self._kv_mounts: dict[str, KvMount] = {}
        self._lock = threading.Lock()
        self.auth = Auth(self._runner)
        """Logins, token self-service and token renewal."""
        self.sys = Sys(self._runner)
        """System backend (health, seal status, policies, mounts, auth methods, AppRole)."""
        self.wrapping = Wrapping(self._runner)
        """Response wrapping."""
        self.leases = LeaseManager(self._runner)
        """Lease renew/revoke/lookup and automatic lease renewal."""

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None, **overrides: Any) -> OpenBaoClient:
        """Build a client from ``GROW_OPENBAO_*`` and ``BAO_*``/``VAULT_*`` variables."""
        return cls(OpenBaoConfig.from_env(env, **overrides))

    @contextlib.contextmanager
    def cancellable(self, token: CancelToken) -> Iterator[CancelToken]:
        """Apply ``token`` to every call made by this thread inside the ``with`` block."""
        with cancel_scope(token) as t:
            yield t

    def kv(self, mount: str | None = None) -> KvMount:
        """KV mount with auto-detected version (default ``config.kv_mount``); cached per mount."""
        key = self._mount(mount)
        with self._lock:
            found = self._kv_mounts.get(key)
            if found is None:
                found = KvMount(self._runner, key, self.config.kv_version)
                self._kv_mounts[key] = found
        return found

    def kv_v1(self, mount: str | None = None) -> KvV1:
        """KV version 1 mount (no detection)."""
        return KvV1(self._runner, self._mount(mount))

    def kv_v2(self, mount: str | None = None) -> KvV2:
        """KV version 2 mount (no detection)."""
        return KvV2(self._runner, self._mount(mount))

    def transit(self, mount: str = "transit") -> Transit:
        """Transit engine (default mount ``transit``)."""
        return Transit(self._runner, mount)

    def database(self, mount: str = "database") -> Database:
        """Database engine (default mount ``database``)."""
        return Database(self._runner, mount)

    def pki(self, mount: str = "pki") -> Pki:
        """PKI engine (default mount ``pki``)."""
        return Pki(self._runner, mount)

    def secrets(
        self, mount: str | None = None, *, path: str = "", value_field: str = "value"
    ) -> OpenBaoSecretsProvider:
        """:class:`SecretsProvider` over a KV mount; ``close()`` stops its watchers."""
        return OpenBaoSecretsProvider(
            self.kv(mount), path=path, value_field=value_field, owner=self._resources
        )

    def request(
        self,
        method: Method,
        path: str,
        *,
        params: Mapping[str, Any] | None = None,
        json: Any = None,
        headers: Mapping[str, str] | None = None,
        list: bool = False,  # noqa: A002 - mirrors the LIST operation
        wrap_ttl_s: float | _dt.timedelta | None = None,
        idempotent: bool | None = None,
    ) -> RawResponse:
        """Call any OpenBao API path (``/v1/<path>``) with the client token, namespace,
        retries and error mapping (for endpoints this SDK has no method for)."""
        return self._runner.run(
            _raw_op(method, path, params, json, headers, list, wrap_ttl_s, idempotent)
        )

    def health(self, *, cancel: CancelToken | None = None) -> HealthStatus:
        """Unauthenticated health (``GET /v1/sys/health``); never raises for an unhealthy or
        unreachable server.

        ``healthy`` is true only for an active, unsealed node; ``status`` is ``active``,
        ``standby``, ``perfstandby``, ``sealed`` or ``uninitialized`` (``unreachable`` /
        ``unhealthy`` on errors). Raises only :class:`CancelledError` and :class:`ConfigError`.
        """
        try:
            with self._maybe_cancel(cancel):
                return _health_status(self._runner.run(_health_op()))
        except ServiceError as err:
            return _health_error(err)

    def ping(self, *, cancel: CancelToken | None = None) -> float:
        """Authenticated round trip (``GET auth/token/lookup-self``); latency in ms.

        A missing, invalid or revoked token raises :class:`AuthenticationError`.
        """
        started = time.monotonic()
        with self._maybe_cancel(cancel):
            self._runner.run(_ping_op())
        return (time.monotonic() - started) * 1000.0

    def server_version(self, *, cancel: CancelToken | None = None) -> str:
        """Server version from ``sys/health`` (e.g. ``2.7.2``)."""
        with self._maybe_cancel(cancel):
            return self._runner.run(version_op())

    @contextlib.contextmanager
    def _maybe_cancel(self, cancel: CancelToken | None) -> Iterator[None]:
        if cancel is None:
            yield
            return
        with cancel_scope(cancel):
            yield

    def close(self) -> None:
        """Stop token renewers, managed leases and secret watchers, then release connections
        (idempotent)."""
        if self._closed:
            return
        self._closed = True
        self.auth.stop_renewers()
        self.leases.stop_all()
        self._resources.stop_all()
        self._transport.close()

    def __enter__(self) -> OpenBaoClient:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()

    def __repr__(self) -> str:
        return f"OpenBaoClient(config={self.config!r})"


class AsyncOpenBaoClient(_ClientBase):
    """Asynchronous OpenBao client (same modules and methods, awaitable); use ``async with``
    or call :meth:`aclose`.

    Cancel a call by cancelling its task: the SDK raises :class:`CancelledError`, which is also
    an :class:`asyncio.CancelledError`.
    """

    def __init__(
        self,
        config: OpenBaoConfig | None = None,
        *,
        http_transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._setup(config)
        self._transport = AsyncHttpTransport(
            self.config, known_secrets=self._known_secrets, http_transport=http_transport
        )
        self._runner = AsyncRunner(self._transport, self._session)
        self._kv_mounts: dict[str, AsyncKvMount] = {}
        self.auth = AsyncAuth(self._runner)
        """Logins, token self-service and token renewal."""
        self.sys = AsyncSys(self._runner)
        """System backend."""
        self.wrapping = AsyncWrapping(self._runner)
        """Response wrapping."""
        self.leases = AsyncLeaseManager(self._runner)
        """Lease operations and automatic renewal."""

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None, **overrides: Any) -> AsyncOpenBaoClient:
        """Build a client from ``GROW_OPENBAO_*`` and ``BAO_*``/``VAULT_*`` variables."""
        return cls(OpenBaoConfig.from_env(env, **overrides))

    def kv(self, mount: str | None = None) -> AsyncKvMount:
        """See :meth:`OpenBaoClient.kv`."""
        key = self._mount(mount)
        found = self._kv_mounts.get(key)
        if found is None:
            found = AsyncKvMount(self._runner, key, self.config.kv_version)
            self._kv_mounts[key] = found
        return found

    def kv_v1(self, mount: str | None = None) -> AsyncKvV1:
        """KV version 1 mount (no detection)."""
        return AsyncKvV1(self._runner, self._mount(mount))

    def kv_v2(self, mount: str | None = None) -> AsyncKvV2:
        """KV version 2 mount (no detection)."""
        return AsyncKvV2(self._runner, self._mount(mount))

    def transit(self, mount: str = "transit") -> AsyncTransit:
        """Transit engine (default mount ``transit``)."""
        return AsyncTransit(self._runner, mount)

    def database(self, mount: str = "database") -> AsyncDatabase:
        """Database engine (default mount ``database``)."""
        return AsyncDatabase(self._runner, mount)

    def pki(self, mount: str = "pki") -> AsyncPki:
        """PKI engine (default mount ``pki``)."""
        return AsyncPki(self._runner, mount)

    def secrets(
        self, mount: str | None = None, *, path: str = "", value_field: str = "value"
    ) -> AsyncOpenBaoSecretsProvider:
        """See :meth:`OpenBaoClient.secrets`."""
        return AsyncOpenBaoSecretsProvider(
            self.kv(mount), path=path, value_field=value_field, owner=self._resources
        )

    async def request(
        self,
        method: Method,
        path: str,
        *,
        params: Mapping[str, Any] | None = None,
        json: Any = None,
        headers: Mapping[str, str] | None = None,
        list: bool = False,  # noqa: A002 - mirrors the LIST operation
        wrap_ttl_s: float | _dt.timedelta | None = None,
        idempotent: bool | None = None,
    ) -> RawResponse:
        """See :meth:`OpenBaoClient.request`."""
        return await self._runner.run(
            _raw_op(method, path, params, json, headers, list, wrap_ttl_s, idempotent)
        )

    async def health(self) -> HealthStatus:
        """See :meth:`OpenBaoClient.health`."""
        try:
            return _health_status(await self._runner.run(_health_op()))
        except ServiceError as err:
            return _health_error(err)

    async def ping(self) -> float:
        """See :meth:`OpenBaoClient.ping`."""
        started = time.monotonic()
        await self._runner.run(_ping_op())
        return (time.monotonic() - started) * 1000.0

    async def server_version(self) -> str:
        """See :meth:`OpenBaoClient.server_version`."""
        return await self._runner.run(version_op())

    async def aclose(self) -> None:
        """Stop renewers, managed leases and watchers, then close connections (idempotent)."""
        if self._closed:
            return
        self._closed = True
        self.auth.stop_renewers()
        await self.leases.stop_all()
        self._resources.stop_all()
        await self._transport.aclose()

    close = aclose

    async def __aenter__(self) -> AsyncOpenBaoClient:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        await self.aclose()

    def __repr__(self) -> str:
        return f"AsyncOpenBaoClient(config={self.config!r})"
