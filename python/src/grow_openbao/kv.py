"""KV secrets engine v1 + v2 with per-mount version auto-detection (API.md §4)."""

from __future__ import annotations

import dataclasses
import datetime as _dt
from collections.abc import Mapping, Sequence
from typing import Any, Literal

from ._api import (
    AsyncModule,
    AsyncRunner,
    Call,
    Duration,
    Op,
    SyncModule,
    SyncRunner,
    async_op,
    compact,
    encode_path,
    integer,
    list_keys,
    opt_duration,
    parse_time,
    parse_vault_duration,
    require_text,
    string_map,
    sync_op,
    trim_slashes,
    unexpected,
)
from ._api import (
    data as get_data,
)
from ._core import NotFoundError, UnsupportedError, ValidationError

__all__ = [
    "KvVersionMetadata",
    "KvSecret",
    "KvMetadata",
    "KvV1",
    "KvV2",
    "KvMount",
    "AsyncKvV1",
    "AsyncKvV2",
    "AsyncKvMount",
]

KvVersion = Literal[1, 2]


@dataclasses.dataclass(frozen=True)
class KvVersionMetadata:
    """Metadata of one KV v2 version."""

    version: int
    created_time: _dt.datetime | None
    #: Soft-delete time, ``None`` when not deleted.
    deletion_time: _dt.datetime | None
    destroyed: bool
    custom_metadata: dict[str, str]


@dataclasses.dataclass(frozen=True)
class KvSecret:
    """A KV secret: the key/value ``data`` and, on KV v2, the version ``metadata``.

    ``repr()`` hides the values.
    """

    data: dict[str, Any] = dataclasses.field(repr=False)
    metadata: KvVersionMetadata | None = None


@dataclasses.dataclass(frozen=True)
class KvMetadata:
    """Metadata of a KV v2 secret (all versions)."""

    cas_required: bool
    created_time: _dt.datetime | None
    updated_time: _dt.datetime | None
    current_version: int
    oldest_version: int
    max_versions: int
    #: Automatic deletion delay in seconds (``0`` = never).
    delete_version_after_s: float
    custom_metadata: dict[str, str]
    #: Per-version state by version number (string keys, as on the wire).
    versions: dict[str, KvVersionMetadata]


def _version_meta(raw: Any, version: int | None = None) -> KvVersionMetadata | None:
    if not isinstance(raw, Mapping):
        return None
    return KvVersionMetadata(
        version=integer(raw.get("version")) if version is None else version,
        created_time=parse_time(raw.get("created_time")),
        deletion_time=parse_time(raw.get("deletion_time")),
        destroyed=raw.get("destroyed") is True,
        custom_metadata=string_map(raw.get("custom_metadata")),
    )


def _check_versions(versions: Sequence[int], operation: str) -> list[int]:
    if (
        isinstance(versions, (str, bytes))
        or not versions
        or any(isinstance(v, bool) or not isinstance(v, int) or v <= 0 for v in versions)
    ):
        raise ValidationError(
            f"{operation}: versions must be a non-empty list of positive integers"
        )
    return list(versions)


def _unsupported(m: Any, op: str) -> UnsupportedError:
    return UnsupportedError(f"kv.{op} {m.mount}: not supported by KV version 1")


# --------------------------------------------------------------------------- KV v1 operations


def _v1_read(m: Any, /, path: str, *, version: int | None = None) -> Op[KvSecret]:
    """Read a secret; :class:`NotFoundError` when missing (``version`` is v2 only)."""
    op = f"kv.read {m.mount}/{path}"
    if version is not None:
        raise _unsupported(m, "read with version")
    found = yield from get_data(
        Call("GET", encode_path(m.mount, require_text(path, "path", op)), op)
    )
    return KvSecret(found)


def _v1_write(
    m: Any, /, path: str, data: Mapping[str, Any], *, cas: int | None = None
) -> Op[KvVersionMetadata | None]:
    """Write (replace) a secret; returns ``None`` on KV v1 (``cas`` is v2 only)."""
    op = f"kv.write {m.mount}/{path}"
    if cas is not None:
        raise _unsupported(m, "write with cas")
    yield Call("POST", encode_path(m.mount, require_text(path, "path", op)), op, json=dict(data))
    return None


def _v1_delete(m: Any, /, path: str) -> Op[None]:
    """Delete a secret (missing paths are not an error)."""
    op = f"kv.delete {m.mount}/{path}"
    yield Call("DELETE", encode_path(m.mount, require_text(path, "path", op)), op)


def _v1_list(
    m: Any, /, path: str = "", *, after: str | None = None, limit: int | None = None
) -> Op[list[str]]:
    """Keys directly under a folder (sub-folders end in ``/``); ``[]`` when there is none."""
    op = f"kv.list {m.mount}/{path}"
    return (yield from list_keys(Call("GET", encode_path(m.mount, path) + "/", op)))


def _v1_reject(name: str) -> Any:
    def reject(m: Any, /, *args: Any, **kwargs: Any) -> Op[Any]:
        raise _unsupported(m, name)
        yield  # type: ignore[unreachable]  # pragma: no cover - makes this a generator

    reject.__doc__ = f"Not supported by KV version 1 (:class:`UnsupportedError`): ``{name}``."
    return reject


# --------------------------------------------------------------------------- KV v2 operations


def _v2_path(m: Any, kind: str, path: str, op: str) -> str:
    return encode_path(m.mount, kind, require_text(path, "path", op))


def _v2_read(m: Any, /, path: str, *, version: int | None = None) -> Op[KvSecret]:
    """Read the latest (or a given) version; :class:`NotFoundError` when missing, deleted or
    destroyed."""
    op = f"kv.read {m.mount}/{path}"
    found = yield from get_data(
        Call("GET", _v2_path(m, "data", path, op), op, params={"version": version})
    )
    secret = found.get("data")
    if not isinstance(secret, dict):
        raise NotFoundError(f"{op}: version is deleted or destroyed")
    return KvSecret(secret, _version_meta(found.get("metadata")))


def _v2_written(found: Mapping[str, Any], op: str) -> KvVersionMetadata:
    meta = _version_meta(found)
    if meta is None:  # pragma: no cover - data() guarantees a mapping
        raise unexpected(op, "no version metadata")
    return meta


def _v2_write(
    m: Any, /, path: str, data: Mapping[str, Any], *, cas: int | None = None
) -> Op[KvVersionMetadata | None]:
    """Write a new version (``cas``: the current version must equal it, ``0`` = create only).

    A CAS mismatch raises :class:`ConflictError`.
    """
    op = f"kv.write {m.mount}/{path}"
    body: dict[str, Any] = {"data": dict(data)}
    if cas is not None:
        body["options"] = {"cas": cas}
    found = yield from get_data(Call("POST", _v2_path(m, "data", path, op), op, json=body))
    return _v2_written(found, op)


def _v2_patch(
    m: Any, /, path: str, data: Mapping[str, Any], *, cas: int | None = None
) -> Op[KvVersionMetadata]:
    """Merge keys into the latest version (RFC 7386: a ``None`` value removes the key)."""
    op = f"kv.patch {m.mount}/{path}"
    body: dict[str, Any] = {"data": dict(data)}
    if cas is not None:
        body["options"] = {"cas": cas}
    found = yield from get_data(
        Call(
            "PATCH",
            _v2_path(m, "data", path, op),
            op,
            json=body,
            headers={"Content-Type": "application/merge-patch+json"},
        )
    )
    return _v2_written(found, op)


def _v2_delete(m: Any, /, path: str) -> Op[None]:
    """Soft-delete the latest version (missing paths are not an error)."""
    op = f"kv.delete {m.mount}/{path}"
    yield Call("DELETE", _v2_path(m, "data", path, op), op)


def _v2_versions(m: Any, kind: str, path: str, versions: Sequence[int]) -> Op[None]:
    name = "deleteVersions" if kind == "delete" else kind
    op = f"kv.{name} {m.mount}/{path}"
    yield Call(
        "PUT" if kind == "destroy" else "POST",
        _v2_path(m, kind, path, op),
        op,
        json={"versions": _check_versions(versions, op)},
    )


def _v2_delete_versions(m: Any, /, path: str, versions: Sequence[int]) -> Op[None]:
    """Soft-delete the given versions."""
    return _v2_versions(m, "delete", path, versions)


def _v2_undelete(m: Any, /, path: str, versions: Sequence[int]) -> Op[None]:
    """Restore soft-deleted versions."""
    return _v2_versions(m, "undelete", path, versions)


def _v2_destroy(m: Any, /, path: str, versions: Sequence[int]) -> Op[None]:
    """Permanently destroy versions."""
    return _v2_versions(m, "destroy", path, versions)


def _v2_list(
    m: Any, /, path: str = "", *, after: str | None = None, limit: int | None = None
) -> Op[list[str]]:
    """Keys directly under a folder (sub-folders end in ``/``); ``[]`` when there is none.

    ``after``/``limit`` paginate.
    """
    op = f"kv.list {m.mount}/{path}"
    return (
        yield from list_keys(
            Call(
                "GET",
                encode_path(m.mount, "metadata", path) + "/",
                op,
                params={"after": after, "limit": limit},
            )
        )
    )


def _v2_read_metadata(m: Any, /, path: str) -> Op[KvMetadata]:
    """Metadata of all versions; :class:`NotFoundError` when missing."""
    op = f"kv.readMetadata {m.mount}/{path}"
    d = yield from get_data(Call("GET", _v2_path(m, "metadata", path, op), op))
    versions: dict[str, KvVersionMetadata] = {}
    raw_versions = d.get("versions")
    if isinstance(raw_versions, Mapping):
        for key, raw in raw_versions.items():
            parsed = _version_meta(raw, int(key) if str(key).isdigit() else 0)
            if parsed is not None:
                versions[str(key)] = parsed
    return KvMetadata(
        cas_required=d.get("cas_required") is True,
        created_time=parse_time(d.get("created_time")),
        updated_time=parse_time(d.get("updated_time")),
        current_version=integer(d.get("current_version")),
        oldest_version=integer(d.get("oldest_version")),
        max_versions=integer(d.get("max_versions")),
        delete_version_after_s=parse_vault_duration(d.get("delete_version_after")) or 0.0,
        custom_metadata=string_map(d.get("custom_metadata")),
        versions=versions,
    )


def _v2_write_metadata(
    m: Any,
    /,
    path: str,
    *,
    max_versions: int | None = None,
    cas_required: bool | None = None,
    delete_version_after_s: Duration | None = None,
    custom_metadata: Mapping[str, str] | None = None,
) -> Op[None]:
    """Update the metadata settings of a secret."""
    op = f"kv.writeMetadata {m.mount}/{path}"
    body = compact(
        {
            "max_versions": max_versions,
            "cas_required": cas_required,
            "delete_version_after": opt_duration(delete_version_after_s),
            "custom_metadata": dict(custom_metadata) if custom_metadata is not None else None,
        }
    )
    yield Call("POST", _v2_path(m, "metadata", path, op), op, json=body)


def _v2_delete_metadata(m: Any, /, path: str) -> Op[None]:
    """Delete the secret with all versions and metadata."""
    op = f"kv.deleteMetadata {m.mount}/{path}"
    yield Call("DELETE", _v2_path(m, "metadata", path, op), op)


# --------------------------------------------------------------------------- detection


def detect_kv_version(mount: str, path: str = "") -> Op[KvVersion]:
    """``GET sys/internal/ui/mounts/<mount>/<path>`` → the KV version of the mount.

    Restricted tokens need some capability on ``path``. A mount that is not KV raises
    :class:`ValidationError`.
    """
    op = f"kv.detectVersion {mount}"
    d = yield from get_data(Call("GET", encode_path("sys/internal/ui/mounts", mount, path), op))
    if d.get("type") != "kv":
        raise ValidationError(f"{op}: not a KV mount (type {d.get('type')})")
    options = d.get("options")
    version = options.get("version") if isinstance(options, Mapping) else None
    if version in ("2", 2):
        return 2
    if version in ("1", 1, None):
        return 1
    raise unexpected(op, f"unknown KV version {version}")


def _engine(m: Any, path: str) -> Op[KvVersion]:
    if m._version is None:
        m._version = yield from detect_kv_version(m.mount, path)
    version: KvVersion = m._version
    return version


def _dispatch(v1: Any, v2: Any, doc: str) -> Any:
    def op(m: Any, /, path: str = "", *args: Any, **kwargs: Any) -> Op[Any]:
        version = yield from _engine(m, path)
        fn = v2 if version == 2 else v1
        return (yield from fn(m, path, *args, **kwargs))

    op.__doc__ = doc
    return op


_m_read = _dispatch(_v1_read, _v2_read, _v2_read.__doc__ or "")
_m_write = _dispatch(_v1_write, _v2_write, _v2_write.__doc__ or "")
_m_patch = _dispatch(_v1_reject("patch"), _v2_patch, _v2_patch.__doc__ or "")
_m_delete = _dispatch(_v1_delete, _v2_delete, "Delete the secret (v2: soft-delete latest).")
_m_delete_versions = _dispatch(
    _v1_reject("deleteVersions"), _v2_delete_versions, "Soft-delete versions (KV v2 only)."
)
_m_undelete = _dispatch(_v1_reject("undelete"), _v2_undelete, "Restore versions (KV v2 only).")
_m_destroy = _dispatch(_v1_reject("destroy"), _v2_destroy, "Destroy versions (KV v2 only).")
_m_list = _dispatch(_v1_list, _v2_list, _v2_list.__doc__ or "")
_m_read_metadata = _dispatch(
    _v1_reject("readMetadata"), _v2_read_metadata, "Metadata of all versions (KV v2 only)."
)
_m_write_metadata = _dispatch(
    _v1_reject("writeMetadata"), _v2_write_metadata, "Update metadata settings (KV v2 only)."
)
_m_delete_metadata = _dispatch(
    _v1_reject("deleteMetadata"), _v2_delete_metadata, "Delete all versions (KV v2 only)."
)


def _typed_read(m: Any, /, path: str, *, version: int | None = None) -> Op[KvSecret]:
    return _m_read(m, path, version=version)  # type: ignore[no-any-return]


def _typed_write(
    m: Any, /, path: str, data: Mapping[str, Any], *, cas: int | None = None
) -> Op[KvVersionMetadata | None]:
    return _m_write(m, path, data, cas=cas)  # type: ignore[no-any-return]


def _typed_patch(
    m: Any, /, path: str, data: Mapping[str, Any], *, cas: int | None = None
) -> Op[KvVersionMetadata]:
    return _m_patch(m, path, data, cas=cas)  # type: ignore[no-any-return]


def _typed_delete(m: Any, /, path: str) -> Op[None]:
    return _m_delete(m, path)  # type: ignore[no-any-return]


def _typed_delete_versions(m: Any, /, path: str, versions: Sequence[int]) -> Op[None]:
    return _m_delete_versions(m, path, versions)  # type: ignore[no-any-return]


def _typed_undelete(m: Any, /, path: str, versions: Sequence[int]) -> Op[None]:
    return _m_undelete(m, path, versions)  # type: ignore[no-any-return]


def _typed_destroy(m: Any, /, path: str, versions: Sequence[int]) -> Op[None]:
    return _m_destroy(m, path, versions)  # type: ignore[no-any-return]


def _typed_list(
    m: Any, /, path: str = "", *, after: str | None = None, limit: int | None = None
) -> Op[list[str]]:
    return _m_list(m, path, after=after, limit=limit)  # type: ignore[no-any-return]


def _typed_read_metadata(m: Any, /, path: str) -> Op[KvMetadata]:
    return _m_read_metadata(m, path)  # type: ignore[no-any-return]


def _typed_write_metadata(
    m: Any,
    /,
    path: str,
    *,
    max_versions: int | None = None,
    cas_required: bool | None = None,
    delete_version_after_s: Duration | None = None,
    custom_metadata: Mapping[str, str] | None = None,
) -> Op[None]:
    return _m_write_metadata(  # type: ignore[no-any-return]
        m,
        path,
        max_versions=max_versions,
        cas_required=cas_required,
        delete_version_after_s=delete_version_after_s,
        custom_metadata=custom_metadata,
    )


def _typed_delete_metadata(m: Any, /, path: str) -> Op[None]:
    return _m_delete_metadata(m, path)  # type: ignore[no-any-return]


for _fn, _src in (
    (_typed_read, _m_read),
    (_typed_write, _m_write),
    (_typed_patch, _m_patch),
    (_typed_delete, _m_delete),
    (_typed_delete_versions, _m_delete_versions),
    (_typed_undelete, _m_undelete),
    (_typed_destroy, _m_destroy),
    (_typed_list, _m_list),
    (_typed_read_metadata, _m_read_metadata),
    (_typed_write_metadata, _m_write_metadata),
    (_typed_delete_metadata, _m_delete_metadata),
):
    _fn.__doc__ = _src.__doc__

_reject_patch = _v1_reject("patch")
_reject_delete_versions = _v1_reject("deleteVersions")
_reject_undelete = _v1_reject("undelete")
_reject_destroy = _v1_reject("destroy")
_reject_read_metadata = _v1_reject("readMetadata")
_reject_write_metadata = _v1_reject("writeMetadata")
_reject_delete_metadata = _v1_reject("deleteMetadata")


# --------------------------------------------------------------------------- classes


class _KvBase:
    mount: str
    _version: KvVersion | None

    def _init_kv(self, mount: str, version: KvVersion | None) -> None:
        self.mount = trim_slashes(mount)
        self._version = version


class KvV1(SyncModule, _KvBase):
    """KV version 1 (unversioned) mount; version-only operations raise
    :class:`UnsupportedError`."""

    #: Always ``1``.
    version: KvVersion = 1

    def __init__(self, runner: SyncRunner, mount: str) -> None:
        super().__init__(runner)
        self._init_kv(mount, 1)

    read = sync_op(_v1_read)
    write = sync_op(_v1_write)
    patch = sync_op(_reject_patch)
    delete = sync_op(_v1_delete)
    delete_versions = sync_op(_reject_delete_versions)
    undelete = sync_op(_reject_undelete)
    destroy = sync_op(_reject_destroy)
    list = sync_op(_v1_list)
    read_metadata = sync_op(_reject_read_metadata)
    write_metadata = sync_op(_reject_write_metadata)
    delete_metadata = sync_op(_reject_delete_metadata)


class KvV2(SyncModule, _KvBase):
    """KV version 2 (versioned) mount."""

    #: Always ``2``.
    version: KvVersion = 2

    def __init__(self, runner: SyncRunner, mount: str) -> None:
        super().__init__(runner)
        self._init_kv(mount, 2)

    read = sync_op(_v2_read)
    write = sync_op(_v2_write)
    patch = sync_op(_v2_patch)
    delete = sync_op(_v2_delete)
    delete_versions = sync_op(_v2_delete_versions)
    undelete = sync_op(_v2_undelete)
    destroy = sync_op(_v2_destroy)
    list = sync_op(_v2_list)
    read_metadata = sync_op(_v2_read_metadata)
    write_metadata = sync_op(_v2_write_metadata)
    delete_metadata = sync_op(_v2_delete_metadata)


class KvMount(SyncModule, _KvBase):
    """A KV mount whose version is detected on first use (or taken from
    ``config.kv_version``); then delegates to the v1 or v2 behaviour. Version-only operations
    raise :class:`UnsupportedError` on v1 mounts."""

    def __init__(self, runner: SyncRunner, mount: str, version: KvVersion | None = None) -> None:
        super().__init__(runner)
        self._init_kv(mount, version)

    def version(self, path: str = "") -> KvVersion:
        """The KV version of the mount (detected on first use)."""
        return self._run(_engine(self, path))

    read = sync_op(_typed_read)
    write = sync_op(_typed_write)
    patch = sync_op(_typed_patch)
    delete = sync_op(_typed_delete)
    delete_versions = sync_op(_typed_delete_versions)
    undelete = sync_op(_typed_undelete)
    destroy = sync_op(_typed_destroy)
    list = sync_op(_typed_list)
    read_metadata = sync_op(_typed_read_metadata)
    write_metadata = sync_op(_typed_write_metadata)
    delete_metadata = sync_op(_typed_delete_metadata)


class AsyncKvV1(AsyncModule, _KvBase):
    """Async :class:`KvV1`."""

    version: KvVersion = 1

    def __init__(self, runner: AsyncRunner, mount: str) -> None:
        super().__init__(runner)
        self._init_kv(mount, 1)

    read = async_op(_v1_read)
    write = async_op(_v1_write)
    patch = async_op(_reject_patch)
    delete = async_op(_v1_delete)
    delete_versions = async_op(_reject_delete_versions)
    undelete = async_op(_reject_undelete)
    destroy = async_op(_reject_destroy)
    list = async_op(_v1_list)
    read_metadata = async_op(_reject_read_metadata)
    write_metadata = async_op(_reject_write_metadata)
    delete_metadata = async_op(_reject_delete_metadata)


class AsyncKvV2(AsyncModule, _KvBase):
    """Async :class:`KvV2`."""

    version: KvVersion = 2

    def __init__(self, runner: AsyncRunner, mount: str) -> None:
        super().__init__(runner)
        self._init_kv(mount, 2)

    read = async_op(_v2_read)
    write = async_op(_v2_write)
    patch = async_op(_v2_patch)
    delete = async_op(_v2_delete)
    delete_versions = async_op(_v2_delete_versions)
    undelete = async_op(_v2_undelete)
    destroy = async_op(_v2_destroy)
    list = async_op(_v2_list)
    read_metadata = async_op(_v2_read_metadata)
    write_metadata = async_op(_v2_write_metadata)
    delete_metadata = async_op(_v2_delete_metadata)


class AsyncKvMount(AsyncModule, _KvBase):
    """Async :class:`KvMount`."""

    def __init__(self, runner: AsyncRunner, mount: str, version: KvVersion | None = None) -> None:
        super().__init__(runner)
        self._init_kv(mount, version)

    async def version(self, path: str = "") -> KvVersion:
        """The KV version of the mount (detected on first use)."""
        return await self._run(_engine(self, path))

    read = async_op(_typed_read)
    write = async_op(_typed_write)
    patch = async_op(_typed_patch)
    delete = async_op(_typed_delete)
    delete_versions = async_op(_typed_delete_versions)
    undelete = async_op(_typed_undelete)
    destroy = async_op(_typed_destroy)
    list = async_op(_typed_list)
    read_metadata = async_op(_typed_read_metadata)
    write_metadata = async_op(_typed_write_metadata)
    delete_metadata = async_op(_typed_delete_metadata)
