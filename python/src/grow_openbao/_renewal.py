"""Renewal scheduling shared by :class:`TokenRenewer` and :class:`LeaseManager` (service-owned).

The schedule is a generator of instructions (wait, renew, reacquire) so the same logic runs in
a background thread (sync clients) and in an asyncio task (async clients), and tests drive it
with a fake clock.
"""

from __future__ import annotations

import asyncio
import contextlib
import dataclasses
import datetime as _dt
import threading
import time
from collections.abc import Awaitable, Callable, Generator
from typing import Any

from ._core import ServiceError

__all__ = ["LeaseState"]

#: Slack when comparing a granted TTL with the requested one (seconds).
CAP_TOLERANCE_S = 1.0


@dataclasses.dataclass(frozen=True)
class LeaseState:
    """Remaining lifetime of a token or lease."""

    #: Time to live in seconds (``0`` = never expires).
    ttl_s: float
    #: Whether it can be renewed.
    renewable: bool


@dataclasses.dataclass(frozen=True)
class _Wait:
    seconds: float


@dataclasses.dataclass(frozen=True)
class _Renew:
    increment_s: float | None


@dataclasses.dataclass(frozen=True)
class _Reacquire:
    pass


Result = tuple[LeaseState, Any]
"""What a renew/reacquire function returns: the new state and the payload for ``on_renew``."""


def _safe(fn: Callable[..., Any] | None, *args: Any) -> None:
    if fn is None:
        return
    with contextlib.suppress(Exception):  # callbacks never break the renewal loop
        fn(*args)


def _retryable(err: BaseException) -> bool:
    return err.retryable if isinstance(err, ServiceError) else True


@dataclasses.dataclass
class RenewalOptions:
    """Options shared by the renewers (seconds)."""

    increment_s: float | None = None
    renew_fraction: float = 2 / 3
    min_delay_s: float = 0.5
    on_renew: Callable[[Any], None] | None = None
    on_error: Callable[[BaseException], None] | None = None
    on_expire: Callable[[], None] | None = None
    clock: Callable[[], float] = time.monotonic

    def __post_init__(self) -> None:
        if not 0 < self.renew_fraction < 1:
            self.renew_fraction = 2 / 3
        self.min_delay_s = max(0.0, self.min_delay_s)


class _Status:
    def __init__(self) -> None:
        self.running = False
        self.expired = False
        self.expires_at: _dt.datetime | None = None

    def set_ttl(self, ttl_s: float) -> None:
        self.expires_at = (
            None
            if ttl_s <= 0
            else _dt.datetime.now(_dt.timezone.utc) + _dt.timedelta(seconds=ttl_s)
        )


def steps(
    initial: LeaseState, o: RenewalOptions, has_reacquire: bool, status: _Status
) -> Generator[_Wait | _Renew | _Reacquire, Result | None, None]:
    """The renewal schedule (ported 1:1 to every language).

    Renew at ``renew_fraction`` of the TTL. When the lifetime cannot be extended any more (not
    renewable, maximum TTL reached, renewal refused) reacquire (when configured) or call
    ``on_expire`` once at expiry. Retryable failures are retried halfway to the expiry.
    """
    baseline = initial.ttl_s
    state, final = initial, False
    while True:
        if state.ttl_s <= 0:  # never expires (e.g. a root token): nothing to schedule
            status.set_ttl(0)
            return
        expires = o.clock() + state.ttl_s
        status.set_ttl(state.ttl_s)
        early = max(o.min_delay_s, state.ttl_s * o.renew_fraction)
        if not final and state.renewable:
            yield _Wait(early)
            while True:
                try:
                    result = yield _Renew(o.increment_s)
                except Exception as err:  # noqa: BLE001 - reported through on_error
                    _safe(o.on_error, err)
                    remaining = expires - o.clock()
                    if _retryable(err) and remaining > 2 * o.min_delay_s:
                        yield _Wait(remaining / 2)
                        continue
                    state, final = LeaseState(max(remaining, 0.001), False), True
                    break
                assert result is not None
                new, payload = result
                _safe(o.on_renew, payload)
                wanted = o.increment_s if o.increment_s is not None else baseline
                capped = new.ttl_s + CAP_TOLERANCE_S < wanted
                state, final = new, capped or not new.renewable
                break
            continue
        if has_reacquire:
            yield _Wait(min(early, state.ttl_s))
            while True:
                try:
                    result = yield _Reacquire()
                except Exception as err:  # noqa: BLE001 - reported through on_error
                    _safe(o.on_error, err)
                    remaining = expires - o.clock()
                    if remaining > 2 * o.min_delay_s:
                        yield _Wait(remaining / 2)
                        continue
                    yield _Wait(max(remaining, 0.0))
                    _expire(o, status)
                    return
                assert result is not None
                new, payload = result
                baseline = new.ttl_s
                _safe(o.on_renew, payload)
                state, final = new, False
                break
            continue
        yield _Wait(state.ttl_s)
        _expire(o, status)
        return


def _expire(o: RenewalOptions, status: _Status) -> None:
    if status.expired:
        return
    status.expired = True
    status.running = False
    _safe(o.on_expire)


class RenewalLoop:
    """Runs :func:`steps` in a daemon thread (sync clients)."""

    def __init__(
        self,
        options: RenewalOptions,
        renew: Callable[[float | None], Result],
        reacquire: Callable[[], Result] | None = None,
        *,
        wait: Callable[[float], bool] | None = None,
    ) -> None:
        self.options = options
        self._renew = renew
        self._reacquire = reacquire
        self._stop = threading.Event()
        self._wait = wait or self._stop.wait
        self.status = _Status()
        self._thread: threading.Thread | None = None

    @property
    def running(self) -> bool:
        return self.status.running and not self._stop.is_set()

    def start(self, initial: LeaseState, *, background: bool = True) -> None:
        """Start renewing from ``initial`` (``background=False`` runs inline, for tests)."""
        self.status.running = True
        if not background:
            self.run(initial)
            return
        self._thread = threading.Thread(
            target=self.run, args=(initial,), name="grow-openbao-renewer", daemon=True
        )
        self._thread.start()

    def stop(self) -> None:
        """Stop renewing (idempotent); ``on_expire`` is not called."""
        self._stop.set()
        self.status.running = False

    def run(self, initial: LeaseState) -> None:
        gen = steps(initial, self.options, self._reacquire is not None, self.status)
        value: Result | None = None
        exc: BaseException | None = None
        try:
            while True:
                instr = gen.throw(exc) if exc is not None else gen.send(value)
                value, exc = None, None
                if self._stop.is_set():
                    return
                if isinstance(instr, _Wait):
                    if self._wait(instr.seconds) or self._stop.is_set():
                        return
                    continue
                try:
                    if isinstance(instr, _Renew):
                        value = self._renew(instr.increment_s)
                    else:
                        assert self._reacquire is not None
                        value = self._reacquire()
                except Exception as err:  # noqa: BLE001 - handed to the schedule
                    exc = err
                if self._stop.is_set():
                    return
        except StopIteration:
            return
        finally:
            gen.close()


class AsyncRenewalLoop:
    """Runs :func:`steps` in an asyncio task (async clients)."""

    def __init__(
        self,
        options: RenewalOptions,
        renew: Callable[[float | None], Awaitable[Result]],
        reacquire: Callable[[], Awaitable[Result]] | None = None,
        *,
        sleep: Callable[[float], Awaitable[Any]] = asyncio.sleep,
    ) -> None:
        self.options = options
        self._renew = renew
        self._reacquire = reacquire
        self._sleep = sleep
        self._stopped = False
        self.status = _Status()
        self._task: asyncio.Task[None] | None = None

    @property
    def running(self) -> bool:
        return self.status.running and not self._stopped

    def start(self, initial: LeaseState) -> None:
        """Start renewing in a task of the running event loop."""
        self.status.running = True
        self._task = asyncio.get_running_loop().create_task(self.run(initial))

    def stop(self) -> None:
        """Stop renewing (idempotent); ``on_expire`` is not called."""
        self._stopped = True
        self.status.running = False
        if self._task is not None and not self._task.done():
            self._task.cancel()

    async def run(self, initial: LeaseState) -> None:
        gen = steps(initial, self.options, self._reacquire is not None, self.status)
        value: Result | None = None
        exc: BaseException | None = None
        try:
            while True:
                instr = gen.throw(exc) if exc is not None else gen.send(value)
                value, exc = None, None
                if isinstance(instr, _Wait):
                    await self._sleep(instr.seconds)
                    continue
                try:
                    if isinstance(instr, _Renew):
                        value = await self._renew(instr.increment_s)
                    else:
                        assert self._reacquire is not None
                        value = await self._reacquire()
                except asyncio.CancelledError:
                    raise
                except Exception as err:  # noqa: BLE001 - handed to the schedule
                    exc = err
                if self._stopped:
                    return
        except (StopIteration, asyncio.CancelledError):
            return
        finally:
            gen.close()
