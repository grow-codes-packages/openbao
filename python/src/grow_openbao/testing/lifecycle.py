"""Server lifecycle helpers for tests and bootstrap scripts: init, unseal, seal and waiting for
an active node (API.md §2). Service-owned; import from ``grow_openbao.testing.lifecycle``.

Every helper has a sync form (taking an :class:`~grow_openbao.OpenBaoClient`) and an async
form prefixed with ``a`` (taking an :class:`~grow_openbao.AsyncOpenBaoClient`).
"""

from __future__ import annotations

import dataclasses
import time
from typing import Any

from .._api import Call, Op, Sleep, reveal, unexpected
from .._core import Secret, ServiceError, TimeoutError, ValidationError, to_seconds
from ..client import AsyncOpenBaoClient, OpenBaoClient
from ..system import HealthResponse, SealStatus, health_op, raw_body, to_seal_status

__all__ = [
    "InitResult",
    "init_status",
    "init",
    "unseal",
    "seal",
    "wait_for_active",
    "ainit_status",
    "ainit",
    "aunseal",
    "aseal",
    "await_for_active",
]


@dataclasses.dataclass(frozen=True)
class InitResult:
    """Result of :func:`init`. Every key and the root token are :class:`Secret` values."""

    #: Unseal keys (hex); empty with an auto-unseal seal.
    keys: list[Secret]
    keys_base64: list[Secret]
    #: Recovery keys (auto-unseal / static seals only).
    recovery_keys: list[Secret]
    recovery_keys_base64: list[Secret]
    #: Initial root token.
    root_token: Secret


def _secrets(value: Any) -> list[Secret]:
    if not isinstance(value, list):
        return []
    return [Secret(v) for v in value if isinstance(v, str) and v]


def _init_status_op() -> Op[bool]:
    body = yield from raw_body(Call("GET", "sys/init", "testing.initStatus", token=None))
    return body.get("initialized") is True


def _init_op(
    secret_shares: int,
    secret_threshold: int,
    recovery_shares: int | None,
    recovery_threshold: int | None,
) -> Op[InitResult]:
    if recovery_shares is not None or recovery_threshold is not None:
        body: dict[str, int] = {
            "recovery_shares": recovery_shares or 1,
            "recovery_threshold": recovery_threshold or 1,
        }
    else:
        body = {"secret_shares": secret_shares, "secret_threshold": secret_threshold}
    found = yield from raw_body(
        Call("PUT", "sys/init", "testing.init", json=body, token=None, idempotent=False)
    )
    root = found.get("root_token")
    if not isinstance(root, str):
        raise unexpected("testing.init", "no root_token")
    return InitResult(
        keys=_secrets(found.get("keys")),
        keys_base64=_secrets(found.get("keys_base64")),
        recovery_keys=_secrets(found.get("recovery_keys")),
        recovery_keys_base64=_secrets(found.get("recovery_keys_base64")),
        root_token=Secret(root),
    )


def _unseal_op(key: str | Secret | None, reset: bool) -> Op[SealStatus]:
    value = "" if key is None else reveal(key)
    if not reset and not value.strip():
        raise ValidationError("testing.unseal: key must not be empty")
    body = yield from raw_body(
        Call(
            "PUT",
            "sys/unseal",
            "testing.unseal",
            json={"reset": True} if reset else {"key": value},
            token=None,
            idempotent=False,
        )
    )
    return to_seal_status(body)


def _seal_op() -> Op[None]:
    yield Call("PUT", "sys/seal", "testing.seal")


def _wait_op(timeout_s: float, interval_s: float) -> Op[HealthResponse]:
    deadline = time.monotonic() + timeout_s
    last: BaseException | None = None
    while True:
        try:
            health = yield from health_op("testing.waitUntilActive")
        except ServiceError as err:
            if not err.retryable:
                raise
            last = err
        else:
            if health.state == "active":
                return health
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError(
                f"testing.waitUntilActive: not active within {timeout_s:g}s", cause=last
            )
        yield Sleep(min(interval_s, remaining))


# --------------------------------------------------------------------------- sync


def init_status(client: OpenBaoClient) -> bool:
    """Whether the server is initialised (``GET sys/init``)."""
    return client._runner.run(_init_status_op())


def init(
    client: OpenBaoClient,
    *,
    secret_shares: int = 1,
    secret_threshold: int = 1,
    recovery_shares: int | None = None,
    recovery_threshold: int | None = None,
) -> InitResult:
    """Initialise a new server (``PUT sys/init``); never retried.

    Shamir seals use ``secret_shares``/``secret_threshold``; auto-unseal (static) seals use
    ``recovery_shares``/``recovery_threshold``. An initialised server raises
    :class:`ValidationError` ("already initialized").
    """
    return client._runner.run(
        _init_op(secret_shares, secret_threshold, recovery_shares, recovery_threshold)
    )


def unseal(
    client: OpenBaoClient, key: str | Secret | None = None, *, reset: bool = False
) -> SealStatus:
    """Enter one unseal key, hex or base64 (``PUT sys/unseal``); returns the seal status.

    ``reset=True`` discards the keys entered so far.
    """
    return client._runner.run(_unseal_op(key, reset))


def seal(client: OpenBaoClient) -> None:
    """Seal the server (``PUT sys/seal``, needs a root/sudo token)."""
    client._runner.run(_seal_op())


def wait_for_active(
    client: OpenBaoClient, *, timeout_s: float = 30.0, interval_s: float = 0.25
) -> HealthResponse:
    """Poll ``sys/health`` until the node is active (:class:`TimeoutError` otherwise)."""
    return client._runner.run(_wait_op(to_seconds(timeout_s), to_seconds(interval_s)))


# --------------------------------------------------------------------------- async


async def ainit_status(client: AsyncOpenBaoClient) -> bool:
    """Async :func:`init_status`."""
    return await client._runner.run(_init_status_op())


async def ainit(
    client: AsyncOpenBaoClient,
    *,
    secret_shares: int = 1,
    secret_threshold: int = 1,
    recovery_shares: int | None = None,
    recovery_threshold: int | None = None,
) -> InitResult:
    """Async :func:`init`."""
    return await client._runner.run(
        _init_op(secret_shares, secret_threshold, recovery_shares, recovery_threshold)
    )


async def aunseal(
    client: AsyncOpenBaoClient, key: str | Secret | None = None, *, reset: bool = False
) -> SealStatus:
    """Async :func:`unseal`."""
    return await client._runner.run(_unseal_op(key, reset))


async def aseal(client: AsyncOpenBaoClient) -> None:
    """Async :func:`seal`."""
    await client._runner.run(_seal_op())


async def await_for_active(
    client: AsyncOpenBaoClient, *, timeout_s: float = 30.0, interval_s: float = 0.25
) -> HealthResponse:
    """Async :func:`wait_for_active`."""
    return await client._runner.run(_wait_op(to_seconds(timeout_s), to_seconds(interval_s)))
