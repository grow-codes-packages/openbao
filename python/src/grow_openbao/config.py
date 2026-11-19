"""Configuration for the OpenBao client (service-owned)."""

from __future__ import annotations

import dataclasses
from collections.abc import Mapping
from typing import Any, ClassVar, Literal, TypeVar

from ._core import BaseConfig, ConfigError, EnvReader, Secret

__all__ = ["DEFAULT_KV_MOUNT", "DEFAULT_URL", "DEFAULT_VALUE_FIELD", "OpenBaoConfig", "VENDOR_ENV"]

#: Default endpoint when neither the config nor the environment sets one.
DEFAULT_URL = "http://127.0.0.1:8200"

#: Default KV mount used by ``client.kv()`` and ``client.secrets()``.
DEFAULT_KV_MOUNT = "secret"

#: Default KV data field that holds a ``client.secrets()`` value.
DEFAULT_VALUE_FIELD = "value"

#: Vendor variables read after ``GROW_OPENBAO_*``, in order: the OpenBao (``BAO_*``) name first,
#: then the HashiCorp Vault compatible (``VAULT_*``) name (DECISIONS.md #3).
VENDOR_ENV: Mapping[str, tuple[str, ...]] = {
    "URL": ("BAO_ADDR", "VAULT_ADDR"),
    "TOKEN": ("BAO_TOKEN", "VAULT_TOKEN"),
    "NAMESPACE": ("BAO_NAMESPACE", "VAULT_NAMESPACE"),
    "CA_CERT": ("BAO_CACERT", "VAULT_CACERT"),
    "CLIENT_CERT": ("BAO_CLIENT_CERT", "VAULT_CLIENT_CERT"),
    "CLIENT_KEY": ("BAO_CLIENT_KEY", "VAULT_CLIENT_KEY"),
    "INSECURE_SKIP_VERIFY": ("BAO_SKIP_VERIFY", "VAULT_SKIP_VERIFY"),
}

_C = TypeVar("_C", bound="OpenBaoConfig")


@dataclasses.dataclass(frozen=True, repr=False)
class OpenBaoConfig(BaseConfig):
    """Immutable settings for :class:`~grow_openbao.OpenBaoClient`.

    Common fields (``url``, timeouts, ``retry``, ``tls``, ``proxy``, ``headers``,
    ``user_agent_suffix``, ``hooks``, ``logger``) come from :class:`BaseConfig`. Durations are
    float seconds; ``datetime.timedelta`` is accepted. ``token`` accepts a ``str`` and is stored
    as a :class:`Secret`; ``repr()`` never shows it.

    Service fields:

    * ``token`` — client token sent as ``X-Vault-Token``. Leave it unset when the client logs
      in with an auth method (``client.auth.login(...)``).
    * ``namespace`` — sent as ``X-Vault-Namespace``.
    * ``kv_mount`` — default KV mount of ``client.kv()`` / ``client.secrets()`` (``"secret"``).
    * ``kv_version`` — ``1`` or ``2`` to skip KV version auto-detection
      (``sys/internal/ui/mounts``) for tokens that cannot read it; ``None`` = auto-detect.
    * ``secrets_path`` — base path inside the KV mount of ``client.secrets()`` (``""`` = root).
    * ``value_field`` — KV data field that holds a ``client.secrets()`` value (``"value"``).

    Environment (``from_env``): ``GROW_OPENBAO_<NAME>`` first, then the vendor variables of
    :data:`VENDOR_ENV` (``BAO_*`` then ``VAULT_*``). Names: ``URL``, ``TOKEN``, ``NAMESPACE``,
    ``CONNECT_TIMEOUT``, ``REQUEST_TIMEOUT``, ``TOTAL_TIMEOUT``, ``MAX_RETRIES``, ``CA_CERT``,
    ``CLIENT_CERT``, ``CLIENT_KEY``, ``INSECURE_SKIP_VERIFY``, ``PROXY``, ``KV_MOUNT``,
    ``KV_VERSION`` (``1``, ``2``; ``0`` = auto-detect) and ``SECRETS_PATH``.
    """

    ENV_VENDOR: ClassVar[Mapping[str, tuple[str, ...]]] = VENDOR_ENV

    url: str = DEFAULT_URL
    token: Secret | None = None
    namespace: str | None = None
    kv_mount: str = DEFAULT_KV_MOUNT
    kv_version: Literal[1, 2] | None = None
    secrets_path: str = ""
    value_field: str = DEFAULT_VALUE_FIELD

    def __post_init__(self) -> None:
        super().__post_init__()
        if self.namespace == "":
            object.__setattr__(self, "namespace", None)
        if isinstance(self.secrets_path, str):
            object.__setattr__(self, "secrets_path", self.secrets_path.strip("/"))

    @classmethod
    def _env_values(cls, reader: EnvReader) -> dict[str, Any]:
        values = super()._env_values(reader)
        token = reader.string("TOKEN", cls.ENV_VENDOR.get("TOKEN", ()))
        if token is not None:
            values["token"] = Secret(token)
        namespace = reader.string("NAMESPACE", cls.ENV_VENDOR.get("NAMESPACE", ()))
        if namespace is not None:
            values["namespace"] = namespace
        kv_mount = reader.string("KV_MOUNT")
        if kv_mount is not None:
            values["kv_mount"] = kv_mount
        secrets_path = reader.string("SECRETS_PATH")
        if secrets_path is not None:
            values["secrets_path"] = secrets_path
        kv_version = reader.int("KV_VERSION")
        if kv_version is not None and kv_version != 0:
            if kv_version not in (1, 2):
                raise ConfigError(
                    f"config: invalid value in {reader.prefix}KV_VERSION (expected 1 or 2)"
                )
            values["kv_version"] = kv_version
        return values

    def validate(self: _C) -> _C:
        """Common checks plus service rules; raises :class:`ConfigError`."""
        super().validate()
        if self.token is not None and not self.token.reveal().strip():
            raise ConfigError("config: token must not be blank")
        if not isinstance(self.kv_mount, str) or not self.kv_mount.strip("/"):
            raise ConfigError("config: kv_mount must not be empty")
        if self.kv_version not in (None, 1, 2):
            raise ConfigError("config: kv_version must be 1 or 2")
        if not isinstance(self.secrets_path, str):
            raise ConfigError("config: secrets_path must be a string")
        if not isinstance(self.value_field, str) or not self.value_field.strip():
            raise ConfigError("config: value_field must not be empty")
        return self
