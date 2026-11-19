"""``SecretsProvider`` (SPEC §3) on top of a KV mount (DECISIONS.md #1, #2, #6).

One secret = one KV path whose data is ``{"value": "<string>"}``; bytes are stored as
``{"value": "<base64>", "encoding": "base64"}``; objects are JSON-encoded into ``value``.
Reading a path without the value field returns the whole data map JSON-encoded.
"""

from __future__ import annotations

import base64
import builtins
import json
from collections.abc import Mapping
from typing import Any

from ._api import Op, Parallel, trim_slashes
from ._core import NotFoundError, ResourceRegistry, UnsupportedError, ValidationError
from ._secrets import (
    AsyncBaseSecretsProvider,
    BaseSecretsProvider,
    DeleteOptions,
    GetOptions,
    SecretMetadata,
    SecretValue,
    SetOptions,
)
from .kv import (
    KvMetadata,
    _engine,
    _v1_delete,
    _v1_list,
    _v1_read,
    _v1_write,
    _v2_delete,
    _v2_delete_metadata,
    _v2_delete_versions,
    _v2_list,
    _v2_read,
    _v2_read_metadata,
    _v2_write,
    _v2_write_metadata,
)

__all__ = ["LIST_METADATA_CONCURRENCY", "OpenBaoSecretsProvider", "AsyncOpenBaoSecretsProvider"]

#: Concurrency of per-key metadata reads in ``list()`` (DECISIONS.md #2).
LIST_METADATA_CONCURRENCY = 8

_ENCODING_FIELD = "encoding"


def _or_none(op: Op[Any]) -> Op[Any]:
    try:
        return (yield from op)
    except NotFoundError:
        return None


def _current_gone(meta: KvMetadata) -> bool:
    current = meta.versions.get(str(meta.current_version))
    return current is None or current.deletion_time is not None or current.destroyed


class _Core:
    """Provider logic shared by the sync and async providers (operation generators)."""

    def __init__(self, kv: Any, path: str, value_field: str) -> None:
        self.kv = kv
        self.path = trim_slashes(path)
        self.value_field = value_field

    def full_path(self, name: str, path: str | None = None) -> str:
        base = trim_slashes(self.path if path is None else path)
        leaf = trim_slashes(name)
        if not base:
            return leaf
        return f"{base}/{leaf}" if leaf else base

    def decode(self, data: Mapping[str, Any], version: str | None) -> SecretValue:
        raw = data.get(self.value_field)
        if raw is None:
            return SecretValue(json.dumps(dict(data), separators=(",", ":")), version)
        if not isinstance(raw, str):
            return SecretValue(json.dumps(raw, separators=(",", ":")), version)
        if data.get(_ENCODING_FIELD) == "base64":
            try:
                return SecretValue(base64.b64decode(raw, validate=True), version)
            except ValueError:
                raise ValidationError("secrets.get: stored value is not valid base64") from None
        return SecretValue(raw, version)

    def payload(self, value: str | bytes) -> dict[str, Any]:
        if isinstance(value, bytes):
            return {
                self.value_field: base64.b64encode(value).decode("ascii"),
                _ENCODING_FIELD: "base64",
            }
        return {self.value_field: value}

    def text_or_bytes(self, data: bytes) -> str | bytes:
        try:
            return data.decode("utf-8")
        except UnicodeDecodeError:
            return data

    # ------------------------------------------------------------------ primitives
    def fetch(self, name: str, opts: GetOptions) -> Op[SecretValue | None]:
        path = self.full_path(name, opts.path)
        version = yield from _engine(self.kv, path)
        number: int | None = None
        if opts.version is not None:
            if version == 1:
                raise ValidationError(f"secrets.get {name}: versions need a KV version 2 mount")
            try:
                number = int(opts.version)
            except ValueError:
                number = 0
            if number <= 0:
                raise ValidationError(f"secrets.get {name}: version must be a positive integer")
        reader = _v2_read if version == 2 else _v1_read
        secret = yield from _or_none(reader(self.kv, path, version=number))
        if secret is None:
            return None
        meta = secret.metadata
        return self.decode(secret.data, None if meta is None else str(meta.version))

    def basic_meta(self, name: str, path: str | None = None) -> SecretMetadata:
        full = self.full_path(name, path)
        folder = full.rsplit("/", 1)[0] if "/" in full else None
        return SecretMetadata(name=name, path=folder)

    def meta_v2(self, name: str, path: str | None) -> Op[SecretMetadata | None]:
        meta: KvMetadata | None = yield from _or_none(
            _v2_read_metadata(self.kv, self.full_path(name, path))
        )
        if meta is None or _current_gone(meta):
            return None
        basic = self.basic_meta(name, path)
        return SecretMetadata(
            name=basic.name,
            path=basic.path,
            version=str(meta.current_version),
            created_at=meta.created_time,
            updated_at=meta.updated_time,
            tags=meta.custom_metadata,
            versions=len(meta.versions),
            extra={
                "maxVersions": str(meta.max_versions),
                "casRequired": str(meta.cas_required).lower(),
                "deleteVersionAfter": f"{int(meta.delete_version_after_s)}s",
                "oldestVersion": str(meta.oldest_version),
            },
        )

    def list(self, prefix: str | None) -> Op[builtins.list[SecretMetadata]]:
        rel = trim_slashes(prefix or "")
        folder = self.full_path(rel)
        version = yield from _engine(self.kv, folder)
        lister = _v2_list if version == 2 else _v1_list
        keys = yield from lister(self.kv, folder)
        names = [k if not rel else f"{rel}/{k}" for k in sorted(keys) if not k.endswith("/")]
        if version == 1:
            return [self.basic_meta(n) for n in names]
        metas = yield Parallel([self.meta_v2(n, None) for n in names], LIST_METADATA_CONCURRENCY)
        return [m for m in metas if m is not None]

    def write(self, name: str, data: dict[str, Any], opts: SetOptions) -> Op[str]:
        path = self.full_path(name, opts.path)
        version = yield from _engine(self.kv, path)
        if version == 1:
            if opts.cas is not None or opts.tags is not None:
                raise UnsupportedError(
                    f"secrets.set {name}: cas and tags need a KV version 2 mount"
                )
            yield from _v1_write(self.kv, path, data)
            return ""
        meta = yield from _v2_write(self.kv, path, data, cas=opts.cas)
        if opts.tags is not None:
            yield from _v2_write_metadata(self.kv, path, custom_metadata=opts.tags)
        return "" if meta is None else str(meta.version)

    def remove(self, name: str, opts: DeleteOptions) -> Op[None]:
        path = self.full_path(name, opts.path)
        version = yield from _engine(self.kv, path)
        missing = NotFoundError(f"secrets.delete {name}: not found")
        # KV DELETE answers 204 for missing paths, so check first (DECISIONS.md #6).
        if version == 1:
            if (yield from _or_none(_v1_read(self.kv, path))) is None:
                raise missing
            yield from _v1_delete(self.kv, path)
            return
        if opts.versions or opts.permanent:
            if (yield from _or_none(_v2_read_metadata(self.kv, path))) is None:
                raise missing
            if opts.permanent:
                yield from _v2_delete_metadata(self.kv, path)
            else:
                try:
                    numbers = [int(v) for v in opts.versions or ()]
                except ValueError:
                    raise ValidationError(
                        f"secrets.delete {name}: versions must be integers"
                    ) from None
                yield from _v2_delete_versions(self.kv, path, numbers)
            return
        if (yield from _or_none(_v2_read(self.kv, path))) is None:
            raise missing
        yield from _v2_delete(self.kv, path)

    def metadata(self, name: str, opts: GetOptions) -> Op[SecretMetadata | None]:
        path = self.full_path(name, opts.path)
        version = yield from _engine(self.kv, path)
        if version == 2:
            return (yield from self.meta_v2(name, opts.path))
        secret = yield from _or_none(_v1_read(self.kv, path))
        return None if secret is None else self.basic_meta(name, opts.path)

    def get_all(self, path: str | None) -> Op[dict[str, SecretValue]]:
        metas = yield from self.list(path)
        out: dict[str, SecretValue] = {}
        for meta in metas:
            value = yield from self.fetch(meta.name, GetOptions())
            if value is not None:
                out[meta.name] = value
        return out


class OpenBaoSecretsProvider(BaseSecretsProvider):
    """:class:`SecretsProvider` over an OpenBao KV mount (v1 or v2, auto-detected).

    Create it with ``client.secrets(mount=None, path="", value_field="value")``.

    * ``get(name)`` reads ``<path>/<name>``; KV v2 versions are the ``SecretValue.version``.
    * ``set`` returns the new KV v2 version (``""`` on KV v1); ``cas`` and ``tags`` (custom
      metadata) need KV v2. ``str`` is stored as is, ``bytes`` as base64 (with
      ``encoding: base64``), other values JSON-encoded.
    * ``delete`` soft-deletes the latest version (KV v2); ``versions`` deletes those versions,
      ``permanent=True`` removes all versions and metadata. Missing → :class:`NotFoundError`.
    * ``list(prefix)`` lists one folder level (sub-folders skipped); on KV v2 each entry carries
      its metadata and secrets whose current version is deleted are skipped.
    """

    #: Capabilities for the conformance runner.
    capabilities = frozenset({"write", "versions", "delete"})

    def __init__(
        self,
        kv: Any,
        *,
        path: str = "",
        value_field: str = "value",
        owner: ResourceRegistry | None = None,
    ) -> None:
        super().__init__(owner=owner)
        self.kv = kv
        self._core = _Core(kv, path, value_field)

    @property
    def path(self) -> str:
        """Base path inside the mount that names are relative to."""
        return self._core.path

    @property
    def value_field(self) -> str:
        """Data field that holds the value."""
        return self._core.value_field

    def full_path(self, name: str, path: str | None = None) -> str:
        """The KV path of a secret: ``<path or provider path>/<name>``."""
        return self._core.full_path(name, path)

    def _run(self, op: Op[Any]) -> Any:
        return self.kv._run(op)

    def _fetch_secret(self, name: str, opts: GetOptions) -> SecretValue | None:
        result: SecretValue | None = self._run(self._core.fetch(name, opts))
        return result

    def _list_secrets(self, path: str | None) -> builtins.list[SecretMetadata]:
        result: builtins.list[SecretMetadata] = self._run(self._core.list(path))
        return result

    def _put_secret(self, name: str, data: bytes, opts: SetOptions) -> str:
        payload = self._core.payload(self._core.text_or_bytes(data))
        result: str = self._run(self._core.write(name, payload, opts))
        return result

    def _remove_secret(self, name: str, opts: DeleteOptions) -> None:
        self._run(self._core.remove(name, opts))

    def _fetch_metadata(self, name: str, opts: GetOptions) -> SecretMetadata | None:
        result: SecretMetadata | None = self._run(self._core.metadata(name, opts))
        return result

    def set(
        self,
        name: str,
        value: Any,
        *,
        path: str | None = None,
        cas: int | None = None,
        tags: Mapping[str, str] | None = None,
        description: str | None = None,
    ) -> str:
        """Store ``value`` (``str``, ``bytes`` → base64, other → JSON); returns the version."""
        if isinstance(value, (bytes, bytearray, memoryview)):
            opts = SetOptions(path=path, cas=cas, tags=tags, description=description)
            result: str = self._run(self._core.write(name, self._core.payload(bytes(value)), opts))
            return result
        return super().set(name, value, path=path, cas=cas, tags=tags, description=description)

    def get_all(self, path: str | None = None) -> dict[str, SecretValue]:
        """Every secret directly under ``path`` (non-recursive), keyed by name."""
        result: dict[str, SecretValue] = self._run(self._core.get_all(path))
        return result


class AsyncOpenBaoSecretsProvider(AsyncBaseSecretsProvider):
    """Async :class:`OpenBaoSecretsProvider`: ``async_client.secrets()``."""

    capabilities = frozenset({"write", "versions", "delete"})

    def __init__(
        self,
        kv: Any,
        *,
        path: str = "",
        value_field: str = "value",
        owner: ResourceRegistry | None = None,
    ) -> None:
        super().__init__(owner=owner)
        self.kv = kv
        self._core = _Core(kv, path, value_field)

    @property
    def path(self) -> str:
        """Base path inside the mount that names are relative to."""
        return self._core.path

    @property
    def value_field(self) -> str:
        """Data field that holds the value."""
        return self._core.value_field

    def full_path(self, name: str, path: str | None = None) -> str:
        """The KV path of a secret: ``<path or provider path>/<name>``."""
        return self._core.full_path(name, path)

    async def _run(self, op: Op[Any]) -> Any:
        return await self.kv._run(op)

    async def _fetch_secret(self, name: str, opts: GetOptions) -> SecretValue | None:
        result: SecretValue | None = await self._run(self._core.fetch(name, opts))
        return result

    async def _list_secrets(self, path: str | None) -> builtins.list[SecretMetadata]:
        result: builtins.list[SecretMetadata] = await self._run(self._core.list(path))
        return result

    async def _put_secret(self, name: str, data: bytes, opts: SetOptions) -> str:
        payload = self._core.payload(self._core.text_or_bytes(data))
        result: str = await self._run(self._core.write(name, payload, opts))
        return result

    async def _remove_secret(self, name: str, opts: DeleteOptions) -> None:
        await self._run(self._core.remove(name, opts))

    async def _fetch_metadata(self, name: str, opts: GetOptions) -> SecretMetadata | None:
        result: SecretMetadata | None = await self._run(self._core.metadata(name, opts))
        return result

    async def set(
        self,
        name: str,
        value: Any,
        *,
        path: str | None = None,
        cas: int | None = None,
        tags: Mapping[str, str] | None = None,
        description: str | None = None,
    ) -> str:
        """See :meth:`OpenBaoSecretsProvider.set`."""
        if isinstance(value, (bytes, bytearray, memoryview)):
            opts = SetOptions(path=path, cas=cas, tags=tags, description=description)
            result: str = await self._run(
                self._core.write(name, self._core.payload(bytes(value)), opts)
            )
            return result
        return await super().set(
            name, value, path=path, cas=cas, tags=tags, description=description
        )

    async def get_all(self, path: str | None = None) -> dict[str, SecretValue]:
        """Every secret directly under ``path`` (non-recursive), keyed by name."""
        result: dict[str, SecretValue] = await self._run(self._core.get_all(path))
        return result
