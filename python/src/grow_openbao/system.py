"""System backend: health, seal status, leader, version, ACL policies, secrets engines, auth
methods and AppRole administration (API.md §2, §8)."""

from __future__ import annotations

import dataclasses
import datetime as _dt
import json
from collections.abc import Mapping, Sequence
from typing import Any, Literal

from ._api import (
    AsyncModule,
    Call,
    Duration,
    Op,
    SyncModule,
    async_op,
    compact,
    decode_envelope,
    encode_path,
    integer,
    list_keys,
    opt_duration,
    parse_time,
    require_text,
    seconds,
    send,
    string_map,
    strings,
    sync_op,
    text,
    trim_slashes,
    unexpected,
)
from ._api import data as get_data
from ._core import Secret, UnsupportedError

__all__ = [
    "HEALTH_QUERY",
    "NodeState",
    "HealthResponse",
    "SealStatus",
    "LeaderStatus",
    "Policy",
    "MountInfo",
    "SecretIdInfo",
    "Sys",
    "AsyncSys",
]

NodeState = Literal["active", "standby", "perfstandby", "sealed", "uninitialized"]

#: Query parameters that make ``sys/health`` answer 200 for every node state.
HEALTH_QUERY: Mapping[str, int] = {
    "uninitcode": 200,
    "sealedcode": 200,
    "standbycode": 200,
    "performancestandbycode": 200,
}


@dataclasses.dataclass(frozen=True)
class HealthResponse:
    """Raw ``sys/health`` answer (sealed/standby/uninitialised nodes are no error)."""

    #: Derived node state.
    state: NodeState
    initialized: bool
    sealed: bool
    standby: bool
    performance_standby: bool
    version: str
    cluster_name: str
    cluster_id: str
    server_time: _dt.datetime | None


@dataclasses.dataclass(frozen=True)
class SealStatus:
    """``sys/seal-status``."""

    #: ``shamir``, ``static``, ``transit`` …
    type: str
    initialized: bool
    sealed: bool
    #: Unseal threshold.
    threshold: int
    #: Number of key shares.
    shares: int
    #: Unseal keys provided so far.
    progress: int
    nonce: str
    recovery_seal: bool
    version: str
    cluster_name: str
    cluster_id: str
    storage_type: str


@dataclasses.dataclass(frozen=True)
class LeaderStatus:
    """``sys/leader``."""

    ha_enabled: bool
    is_self: bool
    active_time: _dt.datetime | None
    leader_address: str
    leader_cluster_address: str


@dataclasses.dataclass(frozen=True)
class Policy:
    """An ACL policy."""

    name: str
    #: HCL text.
    policy: str


@dataclasses.dataclass(frozen=True)
class MountInfo:
    """A secrets engine or auth method mount."""

    #: Engine/method type, e.g. ``kv``, ``approle``.
    type: str
    description: str
    accessor: str
    #: Mount options (e.g. ``{"version": "2"}`` for KV v2).
    options: dict[str, str]
    #: Mount config (TTLs etc., values as strings).
    config: dict[str, str]
    local: bool
    seal_wrap: bool


@dataclasses.dataclass(frozen=True)
class SecretIdInfo:
    """A generated AppRole secret id (:class:`Secret` values)."""

    secret_id: Secret
    secret_id_accessor: Secret
    #: Uses left (``0`` = unlimited).
    secret_id_num_uses: int
    #: TTL in seconds (``0`` = never expires).
    secret_id_ttl_s: float


def to_health(d: Mapping[str, Any]) -> HealthResponse:
    """Convert a raw ``sys/health`` body."""
    initialized = d.get("initialized") is True
    sealed = d.get("sealed") is True
    standby = d.get("standby") is True
    perf = d.get("performance_standby") is True
    state: NodeState
    if not initialized:
        state = "uninitialized"
    elif sealed:
        state = "sealed"
    elif perf:
        state = "perfstandby"
    elif standby:
        state = "standby"
    else:
        state = "active"
    return HealthResponse(
        state=state,
        initialized=initialized,
        sealed=sealed,
        standby=standby,
        performance_standby=perf,
        version=text(d.get("version")),
        cluster_name=text(d.get("cluster_name")),
        cluster_id=text(d.get("cluster_id")),
        server_time=parse_time(d.get("server_time_utc")),
    )


def to_seal_status(d: Mapping[str, Any]) -> SealStatus:
    """Convert a raw seal-status body."""
    return SealStatus(
        type=text(d.get("type")),
        initialized=d.get("initialized") is True,
        sealed=d.get("sealed") is True,
        threshold=integer(d.get("t")),
        shares=integer(d.get("n")),
        progress=integer(d.get("progress")),
        nonce=text(d.get("nonce")),
        recovery_seal=d.get("recovery_seal") is True,
        version=text(d.get("version")),
        cluster_name=text(d.get("cluster_name")),
        cluster_id=text(d.get("cluster_id")),
        storage_type=text(d.get("storage_type")),
    )


def _mount(raw: Mapping[str, Any]) -> MountInfo:
    return MountInfo(
        type=text(raw.get("type")),
        description=text(raw.get("description")),
        accessor=text(raw.get("accessor")),
        options=string_map(raw.get("options")),
        config=string_map(raw.get("config")),
        local=raw.get("local") is True,
        seal_wrap=raw.get("seal_wrap") is True,
    )


def _mounts(d: Mapping[str, Any]) -> dict[str, MountInfo]:
    return {
        str(path): _mount(raw)
        for path, raw in d.items()
        if isinstance(raw, Mapping) and "type" in raw
    }


def raw_body(call: Call) -> Op[dict[str, Any]]:
    """Send ``call``; the JSON body (which must be an object)."""
    resp = yield from send(call)
    body = decode_envelope(resp, call.operation)
    if not body:
        raise unexpected(call.operation, "empty response body")
    return body


def health_op(operation: str = "sys.health", **overrides: Any) -> Op[HealthResponse]:
    """``GET sys/health`` (unauthenticated, 200 in every node state)."""
    body = yield from raw_body(
        Call("GET", "sys/health", operation, params=HEALTH_QUERY, token=None, **overrides)
    )
    return to_health(body)


def _health(m: Any, /) -> Op[HealthResponse]:
    """``GET sys/health`` (unauthenticated); sealed, standby and uninitialised nodes are no
    error."""
    return health_op()


def _seal_status(m: Any, /) -> Op[SealStatus]:
    """``GET sys/seal-status`` (unauthenticated)."""
    body = yield from raw_body(Call("GET", "sys/seal-status", "sys.sealStatus", token=None))
    return to_seal_status(body)


def _leader(m: Any, /) -> Op[LeaderStatus]:
    """``GET sys/leader`` (unauthenticated)."""
    d = yield from raw_body(Call("GET", "sys/leader", "sys.leader", token=None))
    return LeaderStatus(
        ha_enabled=d.get("ha_enabled") is True,
        is_self=d.get("is_self") is True,
        active_time=parse_time(d.get("active_time")),
        leader_address=text(d.get("leader_address")),
        leader_cluster_address=text(d.get("leader_cluster_address")),
    )


def version_op() -> Op[str]:
    """Server version from ``sys/health``; :class:`UnsupportedError` when none is reported."""
    h = yield from health_op("sys.version")
    if not h.version:
        raise UnsupportedError("sys.version: the server reports no version")
    return h.version


def _version(m: Any, /) -> Op[str]:
    """Server version from ``sys/health`` (e.g. ``2.7.2``)."""
    return version_op()


def _policy_path(name: str, op: str) -> str:
    return encode_path("sys/policies/acl", require_text(name, "name", op))


def _write_policy(m: Any, /, name: str, policy: str) -> Op[None]:
    """Create or replace an ACL policy (``PUT sys/policies/acl/<name>``); invalid HCL raises
    :class:`ValidationError`."""
    op = f"sys.writePolicy {name}"
    yield Call(
        "PUT", _policy_path(name, op), op, json={"policy": require_text(policy, "policy", op)}
    )


def _read_policy(m: Any, /, name: str) -> Op[Policy]:
    """Read an ACL policy; :class:`NotFoundError` when missing."""
    op = f"sys.readPolicy {name}"
    d = yield from get_data(Call("GET", _policy_path(name, op), op))
    return Policy(text(d.get("name")) or name, text(d.get("policy")))


def _list_policies(m: Any, /) -> Op[list[str]]:
    """ACL policy names (includes ``default`` and ``root``)."""
    d = yield from get_data(Call("GET", "sys/policies/acl", "sys.listPolicies", list=True))
    return strings(d.get("keys"))


def _delete_policy(m: Any, /, name: str) -> Op[None]:
    """Delete an ACL policy."""
    op = f"sys.deletePolicy {name}"
    yield Call("DELETE", _policy_path(name, op), op)


def _list_mounts(m: Any, /) -> Op[dict[str, MountInfo]]:
    """Secrets engines by path (``"secret/"`` → info)."""
    d = yield from get_data(Call("GET", "sys/mounts", "sys.listMounts"))
    return _mounts(d)


def _ttl_config(default: Duration | None, maximum: Duration | None) -> dict[str, Any] | None:
    config = compact(
        {"default_lease_ttl": opt_duration(default), "max_lease_ttl": opt_duration(maximum)}
    )
    return config or None


def _enable_secrets_engine(
    m: Any,
    /,
    path: str,
    type: str,  # noqa: A002 - wire name
    *,
    description: str | None = None,
    options: Mapping[str, str] | None = None,
    default_lease_ttl_s: Duration | None = None,
    max_lease_ttl_s: Duration | None = None,
    local: bool | None = None,
    seal_wrap: bool | None = None,
) -> Op[None]:
    """Enable a secrets engine at ``path`` (e.g. ``type="kv", options={"version": "2"}``).

    A used path raises :class:`ValidationError`.
    """
    op = f"sys.enableSecretsEngine {path}"
    yield Call(
        "POST",
        encode_path("sys/mounts", require_text(trim_slashes(path), "path", op)),
        op,
        json=compact(
            {
                "type": require_text(type, "type", op),
                "description": description,
                "options": dict(options) if options is not None else None,
                "config": _ttl_config(default_lease_ttl_s, max_lease_ttl_s),
                "local": local,
                "seal_wrap": seal_wrap,
            }
        ),
    )


def _disable_secrets_engine(m: Any, /, path: str) -> Op[None]:
    """Disable (unmount) a secrets engine; its data is deleted."""
    op = f"sys.disableSecretsEngine {path}"
    yield Call(
        "DELETE", encode_path("sys/mounts", require_text(trim_slashes(path), "path", op)), op
    )


def _list_auth_methods(m: Any, /) -> Op[dict[str, MountInfo]]:
    """Auth methods by path (``"approle/"`` → info)."""
    d = yield from get_data(Call("GET", "sys/auth", "sys.listAuthMethods"))
    return _mounts(d)


def _enable_auth_method(
    m: Any,
    /,
    path: str,
    type: str,  # noqa: A002 - wire name
    *,
    description: str | None = None,
    default_lease_ttl_s: Duration | None = None,
    max_lease_ttl_s: Duration | None = None,
    local: bool | None = None,
) -> Op[None]:
    """Enable an auth method at ``path``."""
    op = f"sys.enableAuthMethod {path}"
    yield Call(
        "POST",
        encode_path("sys/auth", require_text(trim_slashes(path), "path", op)),
        op,
        json=compact(
            {
                "type": require_text(type, "type", op),
                "description": description,
                "config": _ttl_config(default_lease_ttl_s, max_lease_ttl_s),
                "local": local,
            }
        ),
    )


def _disable_auth_method(m: Any, /, path: str) -> Op[None]:
    """Disable an auth method; its tokens are revoked."""
    op = f"sys.disableAuthMethod {path}"
    yield Call("DELETE", encode_path("sys/auth", require_text(trim_slashes(path), "path", op)), op)


def _role_path(mount: str, name: str, op: str, *rest: str) -> str:
    return encode_path("auth", mount, "role", require_text(name, "name", op), *rest)


def _create_app_role(
    m: Any,
    /,
    name: str,
    *,
    mount: str = "approle",
    token_policies: Sequence[str] | None = None,
    token_ttl_s: Duration | None = None,
    token_max_ttl_s: Duration | None = None,
    secret_id_ttl_s: Duration | None = None,
    secret_id_num_uses: int | None = None,
    bind_secret_id: bool | None = None,
    token_type: str | None = None,
) -> Op[None]:
    """Create or update an AppRole role (``POST auth/<mount>/role/<name>``)."""
    op = f"sys.createAppRole {name}"
    yield Call(
        "POST",
        _role_path(mount, name, op),
        op,
        json=compact(
            {
                "token_policies": list(token_policies) if token_policies is not None else None,
                "token_ttl": opt_duration(token_ttl_s),
                "token_max_ttl": opt_duration(token_max_ttl_s),
                "secret_id_ttl": opt_duration(secret_id_ttl_s),
                "secret_id_num_uses": secret_id_num_uses,
                "bind_secret_id": bind_secret_id,
                "token_type": token_type,
            }
        ),
    )


def _list_app_roles(m: Any, /, *, mount: str = "approle") -> Op[list[str]]:
    """AppRole role names; ``[]`` when there is none."""
    return (
        yield from list_keys(Call("GET", encode_path("auth", mount, "role"), "sys.listAppRoles"))
    )


def _delete_app_role(m: Any, /, name: str, *, mount: str = "approle") -> Op[None]:
    """Delete an AppRole role."""
    op = f"sys.deleteAppRole {name}"
    yield Call("DELETE", _role_path(mount, name, op), op)


def _read_role_id(m: Any, /, name: str, *, mount: str = "approle") -> Op[str]:
    """The role id of an AppRole role; :class:`NotFoundError` for unknown roles."""
    op = f"sys.readRoleId {name}"
    d = yield from get_data(Call("GET", _role_path(mount, name, op, "role-id"), op))
    role_id = d.get("role_id")
    if not isinstance(role_id, str):
        raise unexpected(op, "no role_id")
    return role_id


def _generate_secret_id(
    m: Any,
    /,
    name: str,
    *,
    mount: str = "approle",
    metadata: Mapping[str, str] | None = None,
    cidr_list: Sequence[str] | None = None,
    ttl_s: Duration | None = None,
    num_uses: int | None = None,
) -> Op[SecretIdInfo]:
    """Generate a new secret id for an AppRole role."""
    op = f"sys.generateSecretId {name}"
    d = yield from get_data(
        Call(
            "POST",
            _role_path(mount, name, op, "secret-id"),
            op,
            json=compact(
                {
                    "metadata": json.dumps(dict(metadata)) if metadata is not None else None,
                    "cidr_list": list(cidr_list) if cidr_list is not None else None,
                    "ttl": opt_duration(ttl_s),
                    "num_uses": num_uses,
                }
            ),
        )
    )
    secret_id = d.get("secret_id")
    if not isinstance(secret_id, str):
        raise unexpected(op, "no secret_id")
    return SecretIdInfo(
        secret_id=Secret(secret_id),
        secret_id_accessor=Secret(text(d.get("secret_id_accessor"))),
        secret_id_num_uses=integer(d.get("secret_id_num_uses")),
        secret_id_ttl_s=seconds(d.get("secret_id_ttl")),
    )


class Sys(SyncModule):
    """System backend: ``client.sys``. Most write calls need a privileged (root/sudo) token."""

    __slots__ = ()

    health = sync_op(_health)
    seal_status = sync_op(_seal_status)
    leader = sync_op(_leader)
    version = sync_op(_version)
    write_policy = sync_op(_write_policy)
    read_policy = sync_op(_read_policy)
    list_policies = sync_op(_list_policies)
    delete_policy = sync_op(_delete_policy)
    list_mounts = sync_op(_list_mounts)
    enable_secrets_engine = sync_op(_enable_secrets_engine)
    disable_secrets_engine = sync_op(_disable_secrets_engine)
    list_auth_methods = sync_op(_list_auth_methods)
    enable_auth_method = sync_op(_enable_auth_method)
    disable_auth_method = sync_op(_disable_auth_method)
    create_app_role = sync_op(_create_app_role)
    list_app_roles = sync_op(_list_app_roles)
    delete_app_role = sync_op(_delete_app_role)
    read_role_id = sync_op(_read_role_id)
    generate_secret_id = sync_op(_generate_secret_id)


class AsyncSys(AsyncModule):
    """Async :class:`Sys`: ``async_client.sys``."""

    __slots__ = ()

    health = async_op(_health)
    seal_status = async_op(_seal_status)
    leader = async_op(_leader)
    version = async_op(_version)
    write_policy = async_op(_write_policy)
    read_policy = async_op(_read_policy)
    list_policies = async_op(_list_policies)
    delete_policy = async_op(_delete_policy)
    list_mounts = async_op(_list_mounts)
    enable_secrets_engine = async_op(_enable_secrets_engine)
    disable_secrets_engine = async_op(_disable_secrets_engine)
    list_auth_methods = async_op(_list_auth_methods)
    enable_auth_method = async_op(_enable_auth_method)
    disable_auth_method = async_op(_disable_auth_method)
    create_app_role = async_op(_create_app_role)
    list_app_roles = async_op(_list_app_roles)
    delete_app_role = async_op(_delete_app_role)
    read_role_id = async_op(_read_role_id)
    generate_secret_id = async_op(_generate_secret_id)
