"""Leases of dynamic secrets: renew, revoke, lookup and automatic renewal with ``on_expire``
(API.md §6)."""

from __future__ import annotations

import dataclasses
import datetime as _dt
import threading
from collections.abc import Callable, Mapping
from typing import Any, Generic, TypeVar

from ._api import (
    AsyncModule,
    Call,
    Duration,
    Op,
    SyncModule,
    async_op,
    encode_path,
    envelope,
    opt_duration,
    parse_time,
    require_text,
    seconds,
    strings,
    sync_op,
    text,
)
from ._api import data as get_data
from ._core import ValidationError, to_seconds
from ._renewal import AsyncRenewalLoop, LeaseState, RenewalLoop, RenewalOptions, Result

__all__ = [
    "Lease",
    "LeaseRenewal",
    "LeaseInfo",
    "ManagedLease",
    "AsyncManagedLease",
    "LeaseManager",
    "AsyncLeaseManager",
]

T = TypeVar("T")


@dataclasses.dataclass(frozen=True)
class Lease(Generic[T]):
    """A lease on a dynamic secret (e.g. database credentials)."""

    #: Lease id, e.g. ``database/creds/readonly/abc``.
    lease_id: str
    #: TTL in seconds.
    lease_duration_s: float
    renewable: bool
    #: The secret data.
    data: T
    #: Server warnings (e.g. TTL capped by ``max_ttl``).
    warnings: list[str]


@dataclasses.dataclass(frozen=True)
class LeaseRenewal:
    """Result of :meth:`LeaseManager.renew`."""

    lease_id: str
    #: Granted TTL in seconds (may be capped by the maximum TTL; see ``warnings``).
    lease_duration_s: float
    renewable: bool
    warnings: list[str]


@dataclasses.dataclass(frozen=True)
class LeaseInfo:
    """Result of :meth:`LeaseManager.lookup`."""

    id: str
    path: str
    issue_time: _dt.datetime | None
    expire_time: _dt.datetime | None
    last_renewal: _dt.datetime | None
    renewable: bool
    #: Remaining TTL in seconds.
    ttl_s: float


def lease_from_envelope(env: Mapping[str, Any], data: T) -> Lease[T]:
    """Build a :class:`Lease` from an envelope with a lease."""
    return Lease(
        lease_id=text(env.get("lease_id")),
        lease_duration_s=seconds(env.get("lease_duration")),
        renewable=env.get("renewable") is True,
        data=data,
        warnings=strings(env.get("warnings")),
    )


def _renew(m: Any, /, lease_id: str, increment_s: Duration | None = None) -> Op[LeaseRenewal]:
    """Renew a lease (``PUT sys/leases/renew``).

    A TTL beyond the maximum is capped (see ``warnings``); unknown or revoked leases raise
    :class:`ValidationError`.
    """
    body: dict[str, Any] = {"lease_id": require_text(lease_id, "lease_id", "leases.renew")}
    if increment_s is not None:
        body["increment"] = opt_duration(increment_s)
    env = yield from envelope(Call("PUT", "sys/leases/renew", "leases.renew", json=body))
    return LeaseRenewal(
        lease_id=text(env.get("lease_id")) or lease_id,
        lease_duration_s=seconds(env.get("lease_duration")),
        renewable=env.get("renewable") is True,
        warnings=strings(env.get("warnings")),
    )


def _revoke(m: Any, /, lease_id: str) -> Op[None]:
    """Revoke a lease now (``PUT sys/leases/revoke``)."""
    yield Call(
        "PUT",
        "sys/leases/revoke",
        "leases.revoke",
        json={"lease_id": require_text(lease_id, "lease_id", "leases.revoke")},
    )


def _revoke_prefix(m: Any, /, prefix: str) -> Op[None]:
    """Revoke every lease under a prefix (``PUT sys/leases/revoke-prefix/<prefix>``)."""
    yield Call(
        "PUT",
        encode_path(
            "sys/leases/revoke-prefix", require_text(prefix, "prefix", "leases.revokePrefix")
        ),
        "leases.revokePrefix",
    )


def _lookup(m: Any, /, lease_id: str) -> Op[LeaseInfo]:
    """Lease details (``PUT sys/leases/lookup``); unknown leases raise :class:`ValidationError`."""
    d = yield from get_data(
        Call(
            "PUT",
            "sys/leases/lookup",
            "leases.lookup",
            json={"lease_id": require_text(lease_id, "lease_id", "leases.lookup")},
        )
    )
    return LeaseInfo(
        id=text(d.get("id")) or lease_id,
        path=text(d.get("path")),
        issue_time=parse_time(d.get("issue_time")),
        expire_time=parse_time(d.get("expire_time")),
        last_renewal=parse_time(d.get("last_renewal")),
        renewable=d.get("renewable") is True,
        ttl_s=seconds(d.get("ttl")),
    )


def _options(
    increment_s: Duration | None,
    renew_fraction: float,
    min_delay_s: float,
    on_renew: Callable[[LeaseRenewal], None] | None,
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


def _result(r: LeaseRenewal) -> Result:
    return LeaseState(r.lease_duration_s, r.renewable), r


def _check_lease(lease: Lease[Any]) -> None:
    if not lease.lease_id:
        raise ValidationError("leases.manage: the lease has no id")


class ManagedLease:
    """Handle of a lease kept alive by :meth:`LeaseManager.manage`."""

    def __init__(
        self, manager: LeaseManager, lease: Lease[Any], loop: RenewalLoop, revoke_on_stop: bool
    ) -> None:
        self.lease_id = lease.lease_id
        self.lease = lease
        self._manager = manager
        self._loop = loop
        self._revoke_on_stop = revoke_on_stop
        self._stopped = False

    @property
    def running(self) -> bool:
        """Whether renewal is still active."""
        return self._loop.running

    @property
    def expired(self) -> bool:
        """Whether ``on_expire`` fired."""
        return self._loop.status.expired

    @property
    def expires_at(self) -> _dt.datetime | None:
        """Expiry of the current lease."""
        return self._loop.status.expires_at

    def stop(self) -> None:
        """Stop renewing (and revoke when ``revoke_on_stop``). Idempotent."""
        if self._stopped:
            return
        self._stopped = True
        self._loop.stop()
        self._manager._forget(self)
        if self._revoke_on_stop and not self.expired:
            try:
                self._manager.revoke(self.lease_id)
            except Exception as err:  # noqa: BLE001 - reported, never raised from stop()
                on_error = self._loop.options.on_error
                if on_error is not None:
                    on_error(err)


class LeaseManager(SyncModule):
    """Lease operations and automatic renewal: ``client.leases``."""

    __slots__ = ("_lock", "_managed")

    def __init__(self, runner: Any) -> None:
        super().__init__(runner)
        self._managed: set[ManagedLease] = set()
        self._lock = threading.Lock()

    renew = sync_op(_renew)
    revoke = sync_op(_revoke)
    revoke_prefix = sync_op(_revoke_prefix)
    lookup = sync_op(_lookup)

    def manage(
        self,
        lease: Lease[Any],
        *,
        increment_s: Duration | None = None,
        renew_fraction: float = 2 / 3,
        min_delay_s: float = 0.5,
        on_renew: Callable[[LeaseRenewal], None] | None = None,
        on_error: Callable[[BaseException], None] | None = None,
        on_expire: Callable[[], None] | None = None,
        revoke_on_stop: bool = False,
        clock: Callable[[], float] | None = None,
        wait: Callable[[float], bool] | None = None,
        background: bool = True,
    ) -> ManagedLease:
        """Keep a lease alive in a background thread.

        Renews at 2/3 of its TTL until the maximum TTL is reached, then calls ``on_expire`` once
        when it expires. Stopped by the handle, :meth:`stop_all` or ``client.close()``.
        """
        _check_lease(lease)
        handle: ManagedLease | None = None

        def expired() -> None:
            if handle is not None:
                self._forget(handle)
            if on_expire is not None:
                on_expire()

        opts = _options(
            increment_s, renew_fraction, min_delay_s, on_renew, on_error, expired, clock
        )
        lease_id = lease.lease_id
        loop = RenewalLoop(opts, lambda inc: _result(self.renew(lease_id, inc)), wait=wait)
        handle = ManagedLease(self, lease, loop, revoke_on_stop)
        with self._lock:
            self._managed.add(handle)
        loop.start(LeaseState(lease.lease_duration_s, lease.renewable), background=background)
        return handle

    def _forget(self, handle: ManagedLease) -> None:
        with self._lock:
            self._managed.discard(handle)

    @property
    def active_leases(self) -> int:
        """Number of managed leases."""
        return len(self._managed)

    def stop_all(self) -> None:
        """Stop every managed lease (revoking those with ``revoke_on_stop``). Idempotent."""
        with self._lock:
            handles = list(self._managed)
        for handle in handles:
            handle.stop()


class AsyncManagedLease:
    """Handle of a lease kept alive by :meth:`AsyncLeaseManager.manage`."""

    def __init__(
        self,
        manager: AsyncLeaseManager,
        lease: Lease[Any],
        loop: AsyncRenewalLoop,
        revoke_on_stop: bool,
    ) -> None:
        self.lease_id = lease.lease_id
        self.lease = lease
        self._manager = manager
        self._loop = loop
        self._revoke_on_stop = revoke_on_stop
        self._stopped = False

    @property
    def running(self) -> bool:
        """Whether renewal is still active."""
        return self._loop.running

    @property
    def expired(self) -> bool:
        """Whether ``on_expire`` fired."""
        return self._loop.status.expired

    @property
    def expires_at(self) -> _dt.datetime | None:
        """Expiry of the current lease."""
        return self._loop.status.expires_at

    async def stop(self) -> None:
        """Stop renewing (and revoke when ``revoke_on_stop``). Idempotent."""
        if self._stopped:
            return
        self._stopped = True
        self._loop.stop()
        self._manager._forget(self)
        if self._revoke_on_stop and not self.expired:
            try:
                await self._manager.revoke(self.lease_id)
            except Exception as err:  # noqa: BLE001 - reported, never raised from stop()
                on_error = self._loop.options.on_error
                if on_error is not None:
                    on_error(err)


class AsyncLeaseManager(AsyncModule):
    """Async :class:`LeaseManager`: ``async_client.leases``."""

    __slots__ = ("_managed",)

    def __init__(self, runner: Any) -> None:
        super().__init__(runner)
        self._managed: set[AsyncManagedLease] = set()

    renew = async_op(_renew)
    revoke = async_op(_revoke)
    revoke_prefix = async_op(_revoke_prefix)
    lookup = async_op(_lookup)

    def manage(
        self,
        lease: Lease[Any],
        *,
        increment_s: Duration | None = None,
        renew_fraction: float = 2 / 3,
        min_delay_s: float = 0.5,
        on_renew: Callable[[LeaseRenewal], None] | None = None,
        on_error: Callable[[BaseException], None] | None = None,
        on_expire: Callable[[], None] | None = None,
        revoke_on_stop: bool = False,
        clock: Callable[[], float] | None = None,
        sleep: Callable[[float], Any] | None = None,
    ) -> AsyncManagedLease:
        """See :meth:`LeaseManager.manage` (an asyncio task; call from a running loop)."""
        _check_lease(lease)
        handle: AsyncManagedLease | None = None

        def expired() -> None:
            if handle is not None:
                self._forget(handle)
            if on_expire is not None:
                on_expire()

        opts = _options(
            increment_s, renew_fraction, min_delay_s, on_renew, on_error, expired, clock
        )
        lease_id = lease.lease_id

        async def renew(inc: float | None) -> Result:
            return _result(await self.renew(lease_id, inc))

        extra: dict[str, Any] = {} if sleep is None else {"sleep": sleep}
        loop = AsyncRenewalLoop(opts, renew, **extra)
        handle = AsyncManagedLease(self, lease, loop, revoke_on_stop)
        self._managed.add(handle)
        loop.start(LeaseState(lease.lease_duration_s, lease.renewable))
        return handle

    def _forget(self, handle: AsyncManagedLease) -> None:
        self._managed.discard(handle)

    @property
    def active_leases(self) -> int:
        """Number of managed leases."""
        return len(self._managed)

    async def stop_all(self) -> None:
        """Stop every managed lease (revoking those with ``revoke_on_stop``). Idempotent."""
        for handle in list(self._managed):
            await handle.stop()
