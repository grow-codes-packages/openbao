"""Internal OpenBao request layer (service-owned).

Every service operation is written once as a *generator* that yields instructions
(:class:`Call`, :class:`Sleep`, :class:`Parallel`) and receives their results. The sync client
drives these generators with blocking I/O, the async client with ``await``; both share the
same request building, response parsing and error mapping (API.md §0, DECISIONS.md #4).
"""

from __future__ import annotations

import asyncio
import base64
import concurrent.futures
import contextlib
import contextvars
import dataclasses
import datetime as _dt
import functools
import inspect
import json
import math
import re
import time
from collections.abc import Callable, Coroutine, Generator, Iterator, Mapping, Sequence
from typing import Any, Concatenate, ParamSpec, TypeVar, cast
from urllib.parse import quote

from ._core import (
    AsyncHttpTransport,
    CancelToken,
    ErrorCode,
    HttpTransport,
    NotFoundError,
    Request,
    Response,
    Secret,
    ServiceError,
    UnavailableError,
    ValidationError,
    error_for_code,
    to_seconds,
)

__all__: list[str] = []

T = TypeVar("T")
P = ParamSpec("P")

Duration = float | int | _dt.timedelta
"""A duration in seconds (``float``/``int``) or a :class:`datetime.timedelta`."""


class _Unset:
    """Marker for "use the client token"."""

    def __repr__(self) -> str:
        return "UNSET"


UNSET: Any = _Unset()


@dataclasses.dataclass(frozen=True)
class Call:
    """One OpenBao API call (``/v1/<path>``)."""

    method: str
    #: Path below ``/v1/``, already percent-encoded (see :func:`encode_path`).
    path: str
    #: Operation name used in error messages, e.g. ``kv.read secret/app``.
    operation: str
    params: Mapping[str, Any] | None = None
    json: Any = None
    headers: Mapping[str, str] | None = None
    #: ``UNSET`` = client token, ``None`` = no token, a string = that token.
    token: Any = UNSET
    #: Sends ``GET ...?list=true`` (the LIST operation).
    list: bool = False
    #: Requests response wrapping (``X-Vault-Wrap-TTL``), seconds.
    wrap_ttl: float | None = None
    idempotent: bool | None = None
    #: Login endpoint: 400/401/403 become ``AuthenticationError``.
    login: bool = False
    raise_for_status: bool = True
    max_retries: int | None = None


@dataclasses.dataclass(frozen=True)
class Sleep:
    """Pause the operation (seconds)."""

    seconds: float


@dataclasses.dataclass(frozen=True)
class Parallel:
    """Run sub-operations with bounded concurrency; the result is the list of their values."""

    ops: Sequence[Generator[Any, Any, Any]]
    limit: int = 8


Instr = Call | Sleep | Parallel
Op = Generator[Instr, Any, T]

# --------------------------------------------------------------------------- error mapping

_AUTH_403 = re.compile(
    r"invalid token|token not found|missing client token|bad token", re.IGNORECASE
)
#: Missing/invalid/revoked tokens get the plain ``["permission denied"]`` body (or no error text);
#: a policy denial uses the wrapped ``"1 error occurred: * permission denied"`` form.
_PLAIN_DENIED = re.compile(r": (?:permission denied|forbidden) \(HTTP 403\)$")
_CAS_MISMATCH = re.compile(r"check-and-set parameter did not match", re.IGNORECASE)


def map_vault_error(err: ServiceError, login: bool = False) -> ServiceError:
    """Apply the OpenBao-specific status mapping on top of the SPEC defaults.

    * login endpoints: 400/401/403 → ``AUTHENTICATION``;
    * 403 with the plain "permission denied" body (missing, invalid or revoked token), no error
      text, or a message naming an invalid/missing token → ``AUTHENTICATION``; a policy denial
      ("1 error occurred: * permission denied") stays ``PERMISSION_DENIED``;
    * 400 "check-and-set parameter did not match" → ``CONFLICT``;
    * 405 (unsupported operation) → ``UNSUPPORTED``;
    * 501 (not initialised) → ``UNAVAILABLE``.
    """
    status = err.http_status
    if status is None:
        return err
    code: ErrorCode | None = None
    plain_denied = (
        status == 403
        and _PLAIN_DENIED.search(err.message) is not None
        and "error occurred" not in err.message
    )
    if (
        (login and status in (400, 401, 403))
        or (status == 403 and _AUTH_403.search(err.message))
        or plain_denied
    ):
        code = ErrorCode.AUTHENTICATION
    elif status == 400 and _CAS_MISMATCH.search(err.message):
        code = ErrorCode.CONFLICT
    elif status == 405:
        code = ErrorCode.UNSUPPORTED
    elif status == 501:
        code = ErrorCode.UNAVAILABLE
    if code is None or code == err.code:
        return err
    return error_for_code(code)(
        err.message,
        http_status=status,
        request_id=err.request_id,
        retry_after=err.retry_after,
        cause=err.__cause__,
    )


def unexpected(operation: str, reason: str) -> UnavailableError:
    """Error for a response that does not have the documented shape."""
    return UnavailableError(f"{operation}: unexpected response ({reason})", retryable=False)


# --------------------------------------------------------------------------- wire helpers


def trim_slashes(value: str) -> str:
    """Strip leading and trailing slashes."""
    return value.strip("/")


def encode_path(*parts: str) -> str:
    """Join parts with ``/`` and percent-encode each segment (separators kept, empties skipped).

    ``encode_path("kv1", "sdk/with space")`` → ``kv1/sdk/with%20space``.
    """
    segments = [s for p in parts for s in p.split("/") if s]
    return "/".join(quote(s, safe="") for s in segments)


def require_text(value: str, what: str, operation: str) -> str:
    """Reject empty names client side (:class:`ValidationError`)."""
    if not isinstance(value, str) or not value.strip():
        raise ValidationError(f"{operation}: {what} must not be empty")
    return value


def duration_string(value: Duration) -> str:
    """Seconds/timedelta → OpenBao duration string in whole seconds, rounded up (``"2s"``)."""
    seconds = to_seconds(value)
    if not math.isfinite(seconds) or seconds < 0:
        raise ValidationError("invalid duration: must be a non-negative number of seconds")
    return f"{math.ceil(seconds)}s"


def opt_duration(value: Duration | None) -> str | None:
    """:func:`duration_string` or ``None``."""
    return None if value is None else duration_string(value)


def seconds(value: Any) -> float:
    """Wire seconds → float seconds; non-numbers become 0."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return 0.0
    return float(value)


_GO_DURATION = re.compile(r"(\d+(?:\.\d+)?)(ns|us|µs|ms|s|m|h)")
_GO_UNITS = {"ns": 1e-9, "us": 1e-6, "µs": 1e-6, "ms": 1e-3, "s": 1.0, "m": 60.0, "h": 3600.0}


def parse_vault_duration(value: Any) -> float | None:
    """Seconds (number or digits) or a Go duration string (``"720h0m0s"``) → float seconds."""
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if not isinstance(value, str) or not value:
        return None
    if value.isdigit():
        return float(value)
    total = 0.0
    pos = 0
    for match in _GO_DURATION.finditer(value):
        if match.start() != pos:
            return None
        total += float(match.group(1)) * _GO_UNITS[match.group(2)]
        pos = match.end()
    return total if pos == len(value) else None


_RFC3339 = re.compile(
    r"(\d{4})-(\d{2})-(\d{2})[Tt ](\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?(Z|z|[+-]\d{2}:\d{2})?"
)


def parse_time(value: Any) -> _dt.datetime | None:
    """RFC 3339 string (nanoseconds allowed) or unix seconds → aware UTC datetime.

    Empty strings, ``0``, ``None`` and invalid values return ``None``.
    """
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        if value <= 0:
            return None
        return _dt.datetime.fromtimestamp(value, tz=_dt.timezone.utc)
    if not isinstance(value, str) or not value:
        return None
    match = _RFC3339.fullmatch(value.strip())
    if match is None:
        return None
    year, month, day, hour, minute, sec = (int(g) for g in match.groups()[:6])
    fraction = (match.group(7) or "0")[:6].ljust(6, "0")
    zone = match.group(8)
    tz = _dt.timezone.utc
    if zone and zone not in ("Z", "z"):
        sign = 1 if zone[0] == "+" else -1
        tz = _dt.timezone(sign * _dt.timedelta(hours=int(zone[1:3]), minutes=int(zone[4:6])))
    try:
        parsed = _dt.datetime(year, month, day, hour, minute, sec, int(fraction), tzinfo=tz)
    except ValueError:
        return None
    if parsed.year <= 1:
        return None  # Go zero time
    return parsed.astimezone(_dt.timezone.utc)


def to_b64(value: str | bytes) -> str:
    """UTF-8 text or bytes → standard base64."""
    data = value.encode("utf-8") if isinstance(value, str) else bytes(value)
    return base64.b64encode(data).decode("ascii")


def opt_b64(value: str | bytes | None) -> str | None:
    """:func:`to_b64` or ``None``."""
    return None if value is None else to_b64(value)


def from_b64(value: str) -> bytes:
    """Standard base64 → bytes (invalid input → :class:`ValidationError`)."""
    try:
        return base64.b64decode(value, validate=True)
    except (ValueError, TypeError):
        raise ValidationError("invalid base64 in response") from None


def strings(value: Any) -> list[str]:
    """String list from a wire value (``None`` → ``[]``)."""
    if not isinstance(value, list):
        return []
    return [v for v in value if isinstance(v, str)]


def string_map(value: Any) -> dict[str, str]:
    """String map from a wire value (``None`` → ``{}``), JSON-encoding non-string values."""
    if not isinstance(value, Mapping):
        return {}
    out: dict[str, str] = {}
    for key, item in value.items():
        if item is None:
            continue
        out[str(key)] = item if isinstance(item, str) else json.dumps(item, separators=(",", ":"))
    return out


def text(value: Any) -> str:
    """The value when it is a string, else ``""``."""
    return value if isinstance(value, str) else ""


def integer(value: Any) -> int:
    """The value when it is an int (not bool), else ``0``."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return 0
    return int(value)


def compact(body: Mapping[str, Any]) -> dict[str, Any]:
    """Copy without ``None`` values."""
    return {k: v for k, v in body.items() if v is not None}


def opt_secret(value: Any) -> Secret | None:
    """A :class:`Secret` for non-empty strings, else ``None``."""
    return Secret(value) if isinstance(value, str) and value else None


def reveal(value: str | Secret) -> str:
    """The plain value of a string or :class:`Secret`."""
    return value.reveal() if isinstance(value, Secret) else value


# --------------------------------------------------------------------------- sub-operations


def send(call: Call) -> Op[Response]:
    """Send ``call``; the raw response."""
    resp: Response = yield call
    return resp


def envelope(call: Call) -> Op[dict[str, Any]]:
    """Send ``call``; the decoded JSON envelope (``{}`` for 204 / empty bodies)."""
    resp: Response = yield call
    return decode_envelope(resp, call.operation)


def decode_envelope(resp: Response, operation: str) -> dict[str, Any]:
    """The JSON object of a response (``{}`` when the body is empty)."""
    if resp.status == 204 or not resp.content.strip():
        return {}
    body = resp.json()
    if not isinstance(body, dict):
        raise unexpected(operation, "body is not a JSON object")
    return body


def data(call: Call) -> Op[dict[str, Any]]:
    """Send ``call``; ``envelope["data"]`` (raises when missing)."""
    env = yield from envelope(call)
    value = env.get("data")
    if not isinstance(value, dict):
        raise unexpected(call.operation, "response has no data")
    return value


def list_keys(call: Call) -> Op[list[str]]:
    """Send a LIST ``call``; ``data.keys`` (``[]`` when the folder does not exist)."""
    try:
        found = yield from data(dataclasses.replace(call, list=True))
    except NotFoundError:
        return []
    return strings(found.get("keys"))


# --------------------------------------------------------------------------- runners

_CANCEL: contextvars.ContextVar[CancelToken | None] = contextvars.ContextVar(
    "grow_openbao_cancel", default=None
)


@contextlib.contextmanager
def cancel_scope(token: CancelToken) -> Iterator[CancelToken]:
    """Apply ``token`` to every sync call made in this context (thread / context var)."""
    reset = _CANCEL.set(token)
    try:
        yield token
    finally:
        _CANCEL.reset(reset)


class Session:
    """Client state shared by the sync/async runners: token, namespace, remembered secrets."""

    def __init__(self, token: Secret | None, namespace: str | None) -> None:
        self.token = token
        self.namespace = namespace
        self._secrets: set[str] = set()

    def remember(self, *values: str | Secret | None) -> None:
        """Remember credential values so error messages never contain them."""
        for value in values:
            plain = reveal(value) if value is not None else ""
            if len(plain) >= 4:
                self._secrets.add(plain)

    def known_secrets(self, base: Sequence[str]) -> list[str]:
        out = list(base)
        if self.token is not None and self.token:
            out.append(self.token.reveal())
        out.extend(self._secrets)
        return out

    def request(self, call: Call) -> Request:
        headers: dict[str, str] = {}
        if self.namespace:
            headers["X-Vault-Namespace"] = self.namespace
        token = (self.token.reveal() if self.token else None) if call.token is UNSET else call.token
        if token:
            headers["X-Vault-Token"] = token
        if call.wrap_ttl is not None:
            headers["X-Vault-Wrap-TTL"] = duration_string(call.wrap_ttl)
        if call.headers:
            headers.update(call.headers)
        params = dict(call.params or {})
        if call.list:
            params["list"] = "true"
        return Request(
            call.method,
            "/v1/" + call.path,
            operation=call.operation,
            params=params or None,
            json=call.json,
            headers=headers,
            idempotent=call.idempotent,
            raise_for_status=call.raise_for_status,
            max_retries=call.max_retries,
        )


def _step(op: Op[T], value: Any, exc: BaseException | None) -> Instr:
    if exc is not None:
        return op.throw(exc)
    return op.send(value)


class SyncRunner:
    """Drives operations with blocking I/O."""

    def __init__(self, transport: HttpTransport, session: Session) -> None:
        self.transport = transport
        self.session = session
        self.sleep: Callable[[float], None] = self._sleep

    def _sleep(self, delay: float) -> None:
        token = _CANCEL.get()
        if token is not None:
            if token.wait(delay):
                token.raise_if_cancelled("sleep")
            return
        time.sleep(delay)

    def execute(self, call: Call) -> Response:
        try:
            return self.transport.request(self.session.request(call), cancel=_CANCEL.get())
        except ServiceError as err:
            raise map_vault_error(err, call.login) from err.__cause__

    def run(self, op: Op[T]) -> T:
        value: Any = None
        exc: BaseException | None = None
        while True:
            try:
                instr = _step(op, value, exc)
            except StopIteration as stop:
                return cast("T", stop.value)
            value, exc = None, None
            try:
                value = self._dispatch(instr)
            except ServiceError as err:
                exc = err

    def _dispatch(self, instr: Instr) -> Any:
        if isinstance(instr, Call):
            return self.execute(instr)
        if isinstance(instr, Sleep):
            self.sleep(instr.seconds)
            return None
        if not instr.ops:
            return []
        workers = max(1, min(instr.limit, len(instr.ops)))
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
            futures = [
                pool.submit(contextvars.copy_context().run, self.run, sub) for sub in instr.ops
            ]
            return [f.result() for f in futures]


class AsyncRunner:
    """Drives operations with ``await``."""

    def __init__(self, transport: AsyncHttpTransport, session: Session) -> None:
        self.transport = transport
        self.session = session

    async def execute(self, call: Call) -> Response:
        try:
            return await self.transport.request(self.session.request(call))
        except ServiceError as err:
            if err.code == ErrorCode.CANCELLED:
                raise
            raise map_vault_error(err, call.login) from err.__cause__

    async def run(self, op: Op[T]) -> T:
        value: Any = None
        exc: BaseException | None = None
        while True:
            try:
                instr = _step(op, value, exc)
            except StopIteration as stop:
                return cast("T", stop.value)
            value, exc = None, None
            try:
                value = await self._dispatch(instr)
            except ServiceError as err:
                if err.code == ErrorCode.CANCELLED:
                    op.close()
                    raise
                exc = err

    async def _dispatch(self, instr: Instr) -> Any:
        if isinstance(instr, Call):
            return await self.execute(instr)
        if isinstance(instr, Sleep):
            await asyncio.sleep(instr.seconds)
            return None
        semaphore = asyncio.Semaphore(max(1, instr.limit))

        async def one(sub: Op[Any]) -> Any:
            async with semaphore:
                return await self.run(sub)

        return list(await asyncio.gather(*(one(sub) for sub in instr.ops)))


# --------------------------------------------------------------------------- facades


class SyncModule:
    """Base of the sync service modules (``client.kv()``, ``client.transit()`` …)."""

    __slots__ = ("_runner",)

    def __init__(self, runner: SyncRunner) -> None:
        self._runner = runner

    def _run(self, op: Op[T]) -> T:
        return self._runner.run(op)


class AsyncModule:
    """Base of the async service modules."""

    __slots__ = ("_runner",)

    def __init__(self, runner: AsyncRunner) -> None:
        self._runner = runner

    async def _run(self, op: Op[T]) -> T:
        return await self._runner.run(op)


def _method_signature(fn: Callable[..., Any]) -> inspect.Signature:
    """``fn``'s signature with its state parameter shown as ``self`` and ``Op[T]`` as ``T``."""
    sig = inspect.signature(fn)
    params = list(sig.parameters.values())
    self_param = inspect.Parameter("self", inspect.Parameter.POSITIONAL_OR_KEYWORD)
    ret = sig.return_annotation
    if isinstance(ret, str) and ret.startswith("Op[") and ret.endswith("]"):
        ret = ret[3:-1]
    return sig.replace(parameters=[self_param, *params[1:]], return_annotation=ret)


def sync_op(fn: Callable[Concatenate[Any, P], Op[T]]) -> Callable[Concatenate[Any, P], T]:
    """Turn an operation generator into a blocking method of a :class:`SyncModule`."""

    def method(self: SyncModule, /, *args: P.args, **kwargs: P.kwargs) -> T:
        return self._run(fn(self, *args, **kwargs))

    wrapped = functools.wraps(fn)(method)
    del wrapped.__wrapped__
    wrapped.__signature__ = _method_signature(fn)  # type: ignore[attr-defined]
    return cast("Callable[Concatenate[Any, P], T]", wrapped)


def async_op(
    fn: Callable[Concatenate[Any, P], Op[T]],
) -> Callable[Concatenate[Any, P], Coroutine[Any, Any, T]]:
    """Turn an operation generator into a coroutine method of an :class:`AsyncModule`."""

    async def method(self: AsyncModule, /, *args: P.args, **kwargs: P.kwargs) -> T:
        return await self._run(fn(self, *args, **kwargs))

    wrapped = functools.wraps(fn)(method)
    del wrapped.__wrapped__
    wrapped.__signature__ = _method_signature(fn)  # type: ignore[attr-defined]
    return cast("Callable[Concatenate[Any, P], Coroutine[Any, Any, T]]", wrapped)
