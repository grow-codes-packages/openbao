"""Grow Codes SDK for OpenBao.

>>> from grow_openbao import OpenBaoClient, OpenBaoConfig
>>> client = OpenBaoClient.from_env()  # doctest: +SKIP

Modules hang off the client: ``client.auth``, ``client.sys``, ``client.wrapping``,
``client.leases``, ``client.kv()``, ``client.transit()``, ``client.database()``,
``client.pki()`` and ``client.secrets()`` (the ``SecretsProvider``). Server lifecycle helpers
(init/unseal) live in :mod:`grow_openbao.testing.lifecycle`.
"""

from . import _core
from ._core import *  # noqa: F403
from ._version import __version__
from .auth import (
    AppRoleAuth,
    AsyncAuth,
    AsyncTokenRenewer,
    Auth,
    AuthInfo,
    AuthMethod,
    JwtAuth,
    KubernetesAuth,
    LeaseState,
    TokenAuth,
    TokenInfo,
    TokenRenewal,
    TokenRenewer,
    UserpassAuth,
)
from .client import AsyncOpenBaoClient, OpenBaoClient, RawResponse
from .config import DEFAULT_KV_MOUNT, DEFAULT_URL, DEFAULT_VALUE_FIELD, VENDOR_ENV, OpenBaoConfig
from .database import AsyncDatabase, ConnectionInfo, Database, DatabaseCredentials, RoleInfo
from .kv import (
    AsyncKvMount,
    AsyncKvV1,
    AsyncKvV2,
    KvMetadata,
    KvMount,
    KvSecret,
    KvV1,
    KvV2,
    KvVersionMetadata,
)
from .leases import (
    AsyncLeaseManager,
    AsyncManagedLease,
    Lease,
    LeaseInfo,
    LeaseManager,
    LeaseRenewal,
    ManagedLease,
)
from .pki import (
    AsyncPki,
    CertificateInfo,
    IssuedCertificate,
    Pki,
    RevocationInfo,
    SignedCertificate,
    TidyStatus,
)
from .provider import AsyncOpenBaoSecretsProvider, OpenBaoSecretsProvider
from .system import (
    AsyncSys,
    HealthResponse,
    LeaderStatus,
    MountInfo,
    Policy,
    SealStatus,
    SecretIdInfo,
    Sys,
)
from .transit import (
    AsyncTransit,
    Ciphertext,
    DataKey,
    DecryptBatchItem,
    DecryptBatchResult,
    EncryptBatchItem,
    EncryptBatchResult,
    Signature,
    Transit,
    TransitKey,
)
from .wrapping import AsyncWrapping, UnwrapResult, WrapInfo, Wrapping, WrappingLookup

__all__ = [
    "__version__",
    # client + config
    "OpenBaoClient",
    "AsyncOpenBaoClient",
    "RawResponse",
    "OpenBaoConfig",
    "DEFAULT_URL",
    "DEFAULT_KV_MOUNT",
    "DEFAULT_VALUE_FIELD",
    "VENDOR_ENV",
    # auth
    "Auth",
    "AsyncAuth",
    "AuthInfo",
    "TokenInfo",
    "AuthMethod",
    "TokenAuth",
    "AppRoleAuth",
    "KubernetesAuth",
    "JwtAuth",
    "UserpassAuth",
    "TokenRenewer",
    "AsyncTokenRenewer",
    "TokenRenewal",
    "LeaseState",
    # kv
    "KvV1",
    "KvV2",
    "KvMount",
    "AsyncKvV1",
    "AsyncKvV2",
    "AsyncKvMount",
    "KvSecret",
    "KvMetadata",
    "KvVersionMetadata",
    # transit
    "Transit",
    "AsyncTransit",
    "TransitKey",
    "Ciphertext",
    "DataKey",
    "Signature",
    "EncryptBatchItem",
    "DecryptBatchItem",
    "EncryptBatchResult",
    "DecryptBatchResult",
    # database + leases
    "Database",
    "AsyncDatabase",
    "DatabaseCredentials",
    "ConnectionInfo",
    "RoleInfo",
    "LeaseManager",
    "AsyncLeaseManager",
    "Lease",
    "LeaseRenewal",
    "LeaseInfo",
    "ManagedLease",
    "AsyncManagedLease",
    # pki
    "Pki",
    "AsyncPki",
    "SignedCertificate",
    "IssuedCertificate",
    "RevocationInfo",
    "CertificateInfo",
    "TidyStatus",
    # sys
    "Sys",
    "AsyncSys",
    "HealthResponse",
    "SealStatus",
    "LeaderStatus",
    "Policy",
    "MountInfo",
    "SecretIdInfo",
    # wrapping
    "Wrapping",
    "AsyncWrapping",
    "WrapInfo",
    "WrappingLookup",
    "UnwrapResult",
    # secrets provider
    "OpenBaoSecretsProvider",
    "AsyncOpenBaoSecretsProvider",
]
__all__ += _core.__all__

from . import _secrets  # noqa: E402
from ._secrets import *  # noqa: E402, F403

__all__ += _secrets.__all__
