"""Transit secrets engine: encryption as a service (API.md §5).

Plaintext/input values are ``str`` (UTF-8) or ``bytes`` and are sent base64-encoded; ciphertexts,
signatures and HMACs are ``vault:v<key version>:<base64>`` strings.
"""

from __future__ import annotations

import dataclasses
import json
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
    envelope,
    from_b64,
    integer,
    list_keys,
    opt_b64,
    opt_duration,
    parse_vault_duration,
    require_text,
    sync_op,
    text,
    to_b64,
    trim_slashes,
    unexpected,
)
from ._api import data as get_data
from ._core import ValidationError

__all__ = [
    "TransitKey",
    "Ciphertext",
    "DataKey",
    "Signature",
    "EncryptBatchItem",
    "DecryptBatchItem",
    "EncryptBatchResult",
    "DecryptBatchResult",
    "Transit",
    "AsyncTransit",
]

TransitInput = str | bytes


@dataclasses.dataclass(frozen=True)
class TransitKey:
    """A transit key."""

    name: str
    type: str
    #: Key versions → creation time (unix seconds as text) or, for asymmetric keys, JSON text.
    keys: dict[str, str]
    latest_version: int
    min_decryption_version: int
    min_encryption_version: int
    min_available_version: int
    deletion_allowed: bool
    exportable: bool
    derived: bool
    supports_encryption: bool
    supports_decryption: bool
    supports_signing: bool
    supports_derivation: bool
    #: Automatic rotation period in seconds (``0`` = off).
    auto_rotate_period_s: float


@dataclasses.dataclass(frozen=True)
class Ciphertext:
    """Ciphertext ``vault:v<n>:<base64>`` and the key version that produced it."""

    ciphertext: str
    key_version: int


@dataclasses.dataclass(frozen=True)
class DataKey:
    """A data key: ``ciphertext`` decrypts (with the transit key) to ``plaintext``."""

    ciphertext: str
    key_version: int
    #: Present unless ``plaintext=False`` was requested; hidden from ``repr()``.
    plaintext: bytes | None = dataclasses.field(default=None, repr=False)


@dataclasses.dataclass(frozen=True)
class Signature:
    """A signature ``vault:v<n>:<base64>``."""

    signature: str
    key_version: int


@dataclasses.dataclass(frozen=True)
class EncryptBatchItem:
    """One item of :meth:`Transit.encrypt_batch`."""

    plaintext: TransitInput = dataclasses.field(repr=False)
    context: TransitInput | None = None
    #: Echoed back in the result.
    reference: str | None = None


@dataclasses.dataclass(frozen=True)
class DecryptBatchItem:
    """One item of :meth:`Transit.decrypt_batch`."""

    ciphertext: str
    context: TransitInput | None = None
    reference: str | None = None


@dataclasses.dataclass(frozen=True)
class EncryptBatchResult:
    """Result of one batch item; ``error`` is set when this item failed."""

    ciphertext: str | None = None
    key_version: int | None = None
    reference: str | None = None
    error: str | None = None


@dataclasses.dataclass(frozen=True)
class DecryptBatchResult:
    """Result of one batch item; ``error`` is set when this item failed."""

    plaintext: bytes | None = dataclasses.field(default=None, repr=False)
    reference: str | None = None
    error: str | None = None


def _key(d: Mapping[str, Any]) -> TransitKey:
    keys: dict[str, str] = {}
    raw = d.get("keys")
    if isinstance(raw, Mapping):
        for version, value in raw.items():
            keys[str(version)] = (
                json.dumps(value, separators=(",", ":"))
                if isinstance(value, (dict, list))
                else str(value)
            )
    return TransitKey(
        name=text(d.get("name")),
        type=text(d.get("type")),
        keys=keys,
        latest_version=integer(d.get("latest_version")),
        min_decryption_version=integer(d.get("min_decryption_version")),
        min_encryption_version=integer(d.get("min_encryption_version")),
        min_available_version=integer(d.get("min_available_version")),
        deletion_allowed=d.get("deletion_allowed") is True,
        exportable=d.get("exportable") is True,
        derived=d.get("derived") is True,
        supports_encryption=d.get("supports_encryption") is True,
        supports_decryption=d.get("supports_decryption") is True,
        supports_signing=d.get("supports_signing") is True,
        supports_derivation=d.get("supports_derivation") is True,
        auto_rotate_period_s=parse_vault_duration(d.get("auto_rotate_period")) or 0.0,
    )


def _ciphertext(d: Mapping[str, Any], op: str) -> Ciphertext:
    if not isinstance(d.get("ciphertext"), str):
        raise unexpected(op, "no ciphertext")
    return Ciphertext(d["ciphertext"], integer(d.get("key_version")))


def _p(m: Any, *parts: str) -> str:
    return encode_path(m.mount, *parts)


def _name(name: str, op: str) -> str:
    return require_text(name, "key name", f"transit.{op}")


def _post(
    m: Any, path: str, op: str, body: Mapping[str, Any], *, idempotent: bool = False
) -> Op[dict[str, Any]]:
    return get_data(Call("POST", path, f"transit.{op}", json=compact(body), idempotent=idempotent))


def _create_key(
    m: Any,
    /,
    name: str,
    type: str = "aes256-gcm96",  # noqa: A002 - wire name
    *,
    exportable: bool | None = None,
    derived: bool | None = None,
    auto_rotate_period_s: Duration | None = None,
    allow_plaintext_backup: bool | None = None,
    key_size: int | None = None,
) -> Op[TransitKey]:
    """Create a key (idempotent: an existing key is returned unchanged).

    Types: ``aes128-gcm96``, ``aes256-gcm96`` (default), ``chacha20-poly1305``, ``ed25519``,
    ``ecdsa-p256``/``-p384``/``-p521``, ``rsa-2048``/``-3072``/``-4096``, ``hmac`` …
    """
    env = yield from envelope(
        Call(
            "POST",
            _p(m, "keys", _name(name, "createKey")),
            f"transit.createKey {name}",
            json=compact(
                {
                    "type": type,
                    "exportable": exportable,
                    "derived": derived,
                    "auto_rotate_period": opt_duration(auto_rotate_period_s),
                    "allow_plaintext_backup": allow_plaintext_backup,
                    "key_size": key_size,
                }
            ),
        )
    )
    found = env.get("data")
    if isinstance(found, Mapping):
        return _key(found)
    return (yield from _read_key(m, name))


def _read_key(m: Any, /, name: str) -> Op[TransitKey]:
    """Read a key; :class:`NotFoundError` when missing."""
    d = yield from get_data(
        Call("GET", _p(m, "keys", _name(name, "readKey")), f"transit.readKey {name}")
    )
    return _key(d)


def _list_keys(m: Any, /, *, after: str | None = None, limit: int | None = None) -> Op[list[str]]:
    """Key names (sorted); ``[]`` when there is none."""
    return (
        yield from list_keys(
            Call(
                "GET",
                _p(m, "keys") + "/",
                "transit.listKeys",
                params={"after": after, "limit": limit},
            )
        )
    )


def _rotate_key(m: Any, /, name: str) -> Op[TransitKey]:
    """Add a new key version; returns the updated key."""
    d = yield from _post(
        m, _p(m, "keys", _name(name, "rotateKey"), "rotate"), f"rotateKey {name}", {}
    )
    return _key(d)


def _update_key_config(
    m: Any,
    /,
    name: str,
    *,
    deletion_allowed: bool | None = None,
    min_decryption_version: int | None = None,
    min_encryption_version: int | None = None,
    exportable: bool | None = None,
    allow_plaintext_backup: bool | None = None,
    auto_rotate_period_s: Duration | None = None,
) -> Op[TransitKey]:
    """Update key settings; returns the updated key."""
    d = yield from _post(
        m,
        _p(m, "keys", _name(name, "updateKeyConfig"), "config"),
        f"updateKeyConfig {name}",
        {
            "deletion_allowed": deletion_allowed,
            "min_decryption_version": min_decryption_version,
            "min_encryption_version": min_encryption_version,
            "exportable": exportable,
            "allow_plaintext_backup": allow_plaintext_backup,
            "auto_rotate_period": opt_duration(auto_rotate_period_s),
        },
        idempotent=True,
    )
    return _key(d)


def _delete_key(m: Any, /, name: str) -> Op[None]:
    """Delete a key (needs ``deletion_allowed=True``, else :class:`ValidationError`)."""
    yield Call("DELETE", _p(m, "keys", _name(name, "deleteKey")), f"transit.deleteKey {name}")


def _encrypt(
    m: Any,
    /,
    name: str,
    plaintext: TransitInput,
    *,
    context: TransitInput | None = None,
    key_version: int | None = None,
    associated_data: TransitInput | None = None,
) -> Op[Ciphertext]:
    """Encrypt ``plaintext`` (text is UTF-8 encoded)."""
    op = f"encrypt {name}"
    d = yield from _post(
        m,
        _p(m, "encrypt", _name(name, "encrypt")),
        op,
        {
            "plaintext": to_b64(plaintext),
            "context": opt_b64(context),
            "key_version": key_version,
            "associated_data": opt_b64(associated_data),
        },
    )
    return _ciphertext(d, f"transit.{op}")


def _decrypt(
    m: Any,
    /,
    name: str,
    ciphertext: str,
    *,
    context: TransitInput | None = None,
    associated_data: TransitInput | None = None,
) -> Op[bytes]:
    """Decrypt a ``vault:v<n>:`` ciphertext; returns the plaintext bytes."""
    d = yield from _post(
        m,
        _p(m, "decrypt", _name(name, "decrypt")),
        f"decrypt {name}",
        {
            "ciphertext": require_text(ciphertext, "ciphertext", "transit.decrypt"),
            "context": opt_b64(context),
            "associated_data": opt_b64(associated_data),
        },
        idempotent=True,
    )
    return from_b64(text(d.get("plaintext")))


def _rewrap(
    m: Any,
    /,
    name: str,
    ciphertext: str,
    *,
    context: TransitInput | None = None,
    key_version: int | None = None,
) -> Op[Ciphertext]:
    """Re-encrypt a ciphertext with the latest (or given) key version without revealing it."""
    op = f"rewrap {name}"
    d = yield from _post(
        m,
        _p(m, "rewrap", _name(name, "rewrap")),
        op,
        {
            "ciphertext": require_text(ciphertext, "ciphertext", "transit.rewrap"),
            "context": opt_b64(context),
            "key_version": key_version,
        },
    )
    return _ciphertext(d, f"transit.{op}")


def _batch(m: Any, kind: str, name: str, items: list[dict[str, Any]]) -> Op[list[dict[str, Any]]]:
    op = f"{kind}Batch {name}"
    if not items:
        return []
    # 207 instead of 400 when some items fail, so per-item results are always readable.
    d = yield from _post(
        m,
        _p(m, kind, _name(name, f"{kind}Batch")),
        op,
        {"batch_input": items, "partial_failure_response_code": 207},
        idempotent=kind == "decrypt",
    )
    results = d.get("batch_results")
    if not isinstance(results, list):
        raise unexpected(f"transit.{op}", "no batch_results")
    return [r if isinstance(r, dict) else {} for r in results]


def _opt_text(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None


def _encrypt_batch(
    m: Any, /, name: str, items: Sequence[EncryptBatchItem]
) -> Op[list[EncryptBatchResult]]:
    """Encrypt many items in one request.

    Results are in input order; a failed item has ``error`` set (the call itself fails only
    when the whole request fails).
    """
    results = yield from _batch(
        m,
        "encrypt",
        name,
        [
            compact(
                {
                    "plaintext": to_b64(i.plaintext),
                    "context": opt_b64(i.context),
                    "reference": i.reference,
                }
            )
            for i in items
        ],
    )
    return [
        EncryptBatchResult(
            ciphertext=_opt_text(r.get("ciphertext")),
            key_version=r["key_version"] if isinstance(r.get("key_version"), int) else None,
            reference=_opt_text(r.get("reference")),
            error=_opt_text(r.get("error")),
        )
        for r in results
    ]


def _decrypt_batch(
    m: Any, /, name: str, items: Sequence[DecryptBatchItem]
) -> Op[list[DecryptBatchResult]]:
    """Decrypt many items in one request; see :meth:`Transit.encrypt_batch` for errors."""
    results = yield from _batch(
        m,
        "decrypt",
        name,
        [
            compact(
                {
                    "ciphertext": i.ciphertext,
                    "context": opt_b64(i.context),
                    "reference": i.reference,
                }
            )
            for i in items
        ],
    )
    out = []
    for r in results:
        error = _opt_text(r.get("error"))
        plaintext = r.get("plaintext")
        out.append(
            DecryptBatchResult(
                plaintext=from_b64(plaintext)
                if error is None and isinstance(plaintext, str)
                else None,
                reference=_opt_text(r.get("reference")),
                error=error,
            )
        )
    return out


def _generate_data_key(
    m: Any,
    /,
    name: str,
    *,
    plaintext: bool = True,
    bits: Literal[128, 256, 512] = 256,
    context: TransitInput | None = None,
) -> Op[DataKey]:
    """Generate a data key encrypted with the transit key (plus its plaintext by default)."""
    kind = "plaintext" if plaintext else "wrapped"
    op = f"generateDataKey {name}"
    d = yield from _post(
        m,
        _p(m, "datakey", kind, _name(name, "generateDataKey")),
        op,
        {"bits": bits, "context": opt_b64(context)},
    )
    ct = _ciphertext(d, f"transit.{op}")
    raw = d.get("plaintext")
    return DataKey(
        ct.ciphertext, ct.key_version, from_b64(raw) if isinstance(raw, str) and raw else None
    )


def _hmac(
    m: Any,
    /,
    name: str,
    input: TransitInput,  # noqa: A002 - wire name
    *,
    algorithm: str | None = None,
    key_version: int | None = None,
) -> Op[str]:
    """HMAC of ``input`` (``vault:v<n>:<base64>``)."""
    d = yield from _post(
        m,
        _p(m, "hmac", _name(name, "hmac"), algorithm or ""),
        f"hmac {name}",
        {"input": to_b64(input), "key_version": key_version},
        idempotent=True,
    )
    if not isinstance(d.get("hmac"), str):
        raise unexpected(f"transit.hmac {name}", "no hmac")
    return str(d["hmac"])


def _sign(
    m: Any,
    /,
    name: str,
    input: TransitInput,  # noqa: A002 - wire name
    *,
    hash_algorithm: str | None = None,
    signature_algorithm: Literal["pss", "pkcs1v15"] | None = None,
    prehashed: bool | None = None,
    key_version: int | None = None,
    context: TransitInput | None = None,
) -> Op[Signature]:
    """Sign ``input`` with an asymmetric key (symmetric keys raise :class:`ValidationError`)."""
    d = yield from _post(
        m,
        _p(m, "sign", _name(name, "sign"), hash_algorithm or ""),
        f"sign {name}",
        {
            "input": to_b64(input),
            "signature_algorithm": signature_algorithm,
            "prehashed": prehashed,
            "key_version": key_version,
            "context": opt_b64(context),
        },
    )
    if not isinstance(d.get("signature"), str):
        raise unexpected(f"transit.sign {name}", "no signature")
    return Signature(d["signature"], integer(d.get("key_version")))


def _verify(
    m: Any,
    /,
    name: str,
    input: TransitInput,  # noqa: A002 - wire name
    *,
    signature: str | None = None,
    hmac: str | None = None,
    hash_algorithm: str | None = None,
    signature_algorithm: Literal["pss", "pkcs1v15"] | None = None,
    prehashed: bool | None = None,
    context: TransitInput | None = None,
) -> Op[bool]:
    """Verify a ``signature`` or an ``hmac`` (exactly one); ``False`` when invalid."""
    if (signature is None) == (hmac is None):
        raise ValidationError("transit.verify: pass exactly one of signature or hmac")
    d = yield from _post(
        m,
        _p(m, "verify", _name(name, "verify"), hash_algorithm or ""),
        f"verify {name}",
        {
            "input": to_b64(input),
            "signature": signature,
            "hmac": hmac,
            "signature_algorithm": signature_algorithm,
            "prehashed": prehashed,
            "context": opt_b64(context),
        },
        idempotent=True,
    )
    return d.get("valid") is True


def _hash(
    m: Any,
    /,
    input: TransitInput,  # noqa: A002 - wire name
    *,
    algorithm: str | None = None,
    format: Literal["hex", "base64"] | None = None,  # noqa: A002 - wire name
) -> Op[str]:
    """Hash of ``input`` (default ``sha2-256``, hex)."""
    d = yield from _post(
        m,
        _p(m, "hash", algorithm or ""),
        "hash",
        {"input": to_b64(input), "format": format},
        idempotent=True,
    )
    if not isinstance(d.get("sum"), str):
        raise unexpected("transit.hash", "no sum")
    return str(d["sum"])


def _random_bytes(
    m: Any,
    /,
    bytes: int,  # noqa: A002 - wire name
    *,
    format: Literal["hex", "base64"] = "base64",  # noqa: A002 - wire name
) -> Op[str]:
    """``bytes`` random bytes from the server, encoded as ``base64`` (default) or ``hex``."""
    if isinstance(bytes, bool) or not isinstance(bytes, int) or bytes <= 0:
        raise ValidationError("transit.randomBytes: bytes must be a positive integer")
    d = yield from _post(
        m, _p(m, "random"), "randomBytes", {"bytes": bytes, "format": format}, idempotent=True
    )
    if not isinstance(d.get("random_bytes"), str):
        raise unexpected("transit.randomBytes", "no random_bytes")
    return str(d["random_bytes"])


class Transit(SyncModule):
    """Transit engine on one mount: ``client.transit(mount="transit")``."""

    __slots__ = ("mount",)

    def __init__(self, runner: SyncRunner, mount: str = "transit") -> None:
        super().__init__(runner)
        self.mount = trim_slashes(mount)

    create_key = sync_op(_create_key)
    read_key = sync_op(_read_key)
    list_keys = sync_op(_list_keys)
    rotate_key = sync_op(_rotate_key)
    update_key_config = sync_op(_update_key_config)
    delete_key = sync_op(_delete_key)
    encrypt = sync_op(_encrypt)
    decrypt = sync_op(_decrypt)
    rewrap = sync_op(_rewrap)
    encrypt_batch = sync_op(_encrypt_batch)
    decrypt_batch = sync_op(_decrypt_batch)
    generate_data_key = sync_op(_generate_data_key)
    hmac = sync_op(_hmac)
    sign = sync_op(_sign)
    verify = sync_op(_verify)
    hash = sync_op(_hash)
    random_bytes = sync_op(_random_bytes)


class AsyncTransit(AsyncModule):
    """Async :class:`Transit`: ``async_client.transit()``."""

    __slots__ = ("mount",)

    def __init__(self, runner: AsyncRunner, mount: str = "transit") -> None:
        super().__init__(runner)
        self.mount = trim_slashes(mount)

    create_key = async_op(_create_key)
    read_key = async_op(_read_key)
    list_keys = async_op(_list_keys)
    rotate_key = async_op(_rotate_key)
    update_key_config = async_op(_update_key_config)
    delete_key = async_op(_delete_key)
    encrypt = async_op(_encrypt)
    decrypt = async_op(_decrypt)
    rewrap = async_op(_rewrap)
    encrypt_batch = async_op(_encrypt_batch)
    decrypt_batch = async_op(_decrypt_batch)
    generate_data_key = async_op(_generate_data_key)
    hmac = async_op(_hmac)
    sign = async_op(_sign)
    verify = async_op(_verify)
    hash = async_op(_hash)
    random_bytes = async_op(_random_bytes)
