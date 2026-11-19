"""Response wrapping: wrap, unwrap and look up single-use wrapping tokens (API.md §9)."""

from __future__ import annotations

import dataclasses
import datetime as _dt
from collections.abc import Mapping
from typing import Any

from ._api import (
    AsyncModule,
    Call,
    Duration,
    Op,
    SyncModule,
    async_op,
    envelope,
    opt_secret,
    parse_time,
    require_text,
    reveal,
    seconds,
    strings,
    sync_op,
    text,
    unexpected,
)
from ._api import data as get_data
from ._core import Secret, to_seconds
from .auth import AuthInfo, auth_info

__all__ = ["WrapInfo", "WrappingLookup", "UnwrapResult", "Wrapping", "AsyncWrapping"]


@dataclasses.dataclass(frozen=True)
class WrapInfo:
    """A wrapping token (a :class:`Secret`) and its properties."""

    token: Secret
    accessor: Secret | None
    #: TTL in seconds.
    ttl_s: float
    creation_time: _dt.datetime | None
    creation_path: str


@dataclasses.dataclass(frozen=True)
class WrappingLookup:
    """Result of :meth:`Wrapping.lookup_wrapping`."""

    creation_path: str
    creation_time: _dt.datetime | None
    #: TTL at creation in seconds.
    creation_ttl_s: float


@dataclasses.dataclass(frozen=True)
class UnwrapResult:
    """Result of :meth:`Wrapping.unwrap`: the original response (``repr`` hides ``data``)."""

    #: The wrapped data (``None`` for wrapped responses without data, e.g. logins).
    data: dict[str, Any] | None = dataclasses.field(repr=False)
    #: The ``auth`` block when a login response was wrapped.
    auth: AuthInfo | None
    lease_id: str
    lease_duration_s: float
    renewable: bool
    warnings: list[str]


def wrap_info(raw: Any) -> WrapInfo | None:
    """Convert a ``wrap_info`` block (``None`` when absent)."""
    if not isinstance(raw, Mapping) or not isinstance(raw.get("token"), str):
        return None
    return WrapInfo(
        token=Secret(raw["token"]),
        accessor=opt_secret(raw.get("accessor")),
        ttl_s=seconds(raw.get("ttl")),
        creation_time=parse_time(raw.get("creation_time")),
        creation_path=text(raw.get("creation_path")),
    )


def _wrap(m: Any, /, data: Mapping[str, Any], ttl_s: Duration) -> Op[WrapInfo]:
    """Wrap ``data`` in a single-use token valid for ``ttl_s`` (``POST sys/wrapping/wrap``)."""
    env = yield from envelope(
        Call(
            "POST",
            "sys/wrapping/wrap",
            "wrapping.wrap",
            json=dict(data),
            wrap_ttl=to_seconds(ttl_s),
        )
    )
    info = wrap_info(env.get("wrap_info"))
    if info is None:
        raise unexpected("wrapping.wrap", "no wrap_info")
    return info


def _unwrap(m: Any, /, token: str | Secret) -> Op[UnwrapResult]:
    """Unwrap a token (``POST sys/wrapping/unwrap`` authenticated with the token itself).

    A used or invalid token raises :class:`ValidationError`; never retried.
    """
    value = require_text(reveal(token), "token", "wrapping.unwrap")
    env = yield from envelope(
        Call("POST", "sys/wrapping/unwrap", "wrapping.unwrap", token=value, max_retries=0)
    )
    found = env.get("data")
    return UnwrapResult(
        data=found if isinstance(found, dict) else None,
        auth=auth_info(env, "wrapping.unwrap") if isinstance(env.get("auth"), Mapping) else None,
        lease_id=text(env.get("lease_id")),
        lease_duration_s=seconds(env.get("lease_duration")),
        renewable=env.get("renewable") is True,
        warnings=strings(env.get("warnings")),
    )


def _lookup_wrapping(m: Any, /, token: str | Secret) -> Op[WrappingLookup]:
    """Properties of a wrapping token without using it (``POST sys/wrapping/lookup``)."""
    value = require_text(reveal(token), "token", "wrapping.lookupWrapping")
    d = yield from get_data(
        Call(
            "POST",
            "sys/wrapping/lookup",
            "wrapping.lookupWrapping",
            json={"token": value},
            token=None,
            idempotent=True,
        )
    )
    return WrappingLookup(
        creation_path=text(d.get("creation_path")),
        creation_time=parse_time(d.get("creation_time")),
        creation_ttl_s=seconds(d.get("creation_ttl")),
    )


class Wrapping(SyncModule):
    """Response wrapping: ``client.wrapping``."""

    __slots__ = ()

    wrap = sync_op(_wrap)
    unwrap = sync_op(_unwrap)
    lookup_wrapping = sync_op(_lookup_wrapping)


class AsyncWrapping(AsyncModule):
    """Async :class:`Wrapping`."""

    __slots__ = ()

    wrap = async_op(_wrap)
    unwrap = async_op(_unwrap)
    lookup_wrapping = async_op(_lookup_wrapping)
