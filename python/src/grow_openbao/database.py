"""Database secrets engine: dynamic credentials and admin helpers (API.md §6)."""

from __future__ import annotations

import dataclasses
from collections.abc import Mapping, Sequence
from typing import Any

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
    opt_duration,
    require_text,
    reveal,
    seconds,
    string_map,
    strings,
    sync_op,
    text,
    trim_slashes,
    unexpected,
)
from ._api import data as get_data
from ._core import Secret
from .leases import Lease, lease_from_envelope

__all__ = [
    "DatabaseCredentials",
    "ConnectionInfo",
    "RoleInfo",
    "Database",
    "AsyncDatabase",
]


@dataclasses.dataclass(frozen=True)
class DatabaseCredentials:
    """Dynamic database credentials (the password is a :class:`Secret`)."""

    username: str
    password: Secret


@dataclasses.dataclass(frozen=True)
class ConnectionInfo:
    """A connection as returned by :meth:`Database.read_connection` (never the password)."""

    plugin_name: str
    allowed_roles: list[str]
    #: Plugin connection details (e.g. ``connection_url``, ``username``).
    connection_details: dict[str, str]


@dataclasses.dataclass(frozen=True)
class RoleInfo:
    """A role as returned by :meth:`Database.read_role`."""

    db_name: str
    creation_statements: list[str]
    revocation_statements: list[str]
    renew_statements: list[str]
    rollback_statements: list[str]
    default_ttl_s: float
    max_ttl_s: float
    credential_type: str


def _path(m: Any, kind: str, name: str, what: str, op: str) -> str:
    return encode_path(m.mount, kind, require_text(name, what, op))


def _get_credentials(m: Any, /, role: str) -> Op[Lease[DatabaseCredentials]]:
    """Generate credentials for a role (``GET <mount>/creds/<role>``).

    Keep them alive with ``client.leases.manage(lease, on_expire=...)``. Unknown roles raise
    :class:`ValidationError`. Never retried (every call creates new credentials).
    """
    op = f"database.getCredentials {role}"
    env = yield from envelope(
        Call("GET", _path(m, "creds", role, "role", op), op, idempotent=False)
    )
    d = env.get("data")
    if not isinstance(d, Mapping) or not isinstance(d.get("username"), str):
        raise unexpected(op, "no credentials in response")
    return lease_from_envelope(
        env, DatabaseCredentials(d["username"], Secret(text(d.get("password"))))
    )


def _configure_connection(
    m: Any,
    /,
    name: str,
    *,
    plugin_name: str,
    connection_url: str,
    username: str | None = None,
    password: str | Secret | None = None,
    allowed_roles: Sequence[str] | None = None,
    verify_connection: bool | None = None,
    extra: Mapping[str, Any] | None = None,
) -> Op[None]:
    """Create or replace a connection (``POST <mount>/config/<name>``, verified by default).

    ``connection_url`` uses ``{{username}}``/``{{password}}`` templates; ``extra`` holds
    plugin-specific fields sent as is (snake_case).
    """
    op = f"database.configureConnection {name}"
    body = compact(
        {
            **(dict(extra) if extra else {}),
            "plugin_name": plugin_name,
            "connection_url": connection_url,
            "username": username,
            "password": None if password is None else reveal(password),
            "allowed_roles": list(allowed_roles) if allowed_roles is not None else None,
            "verify_connection": verify_connection,
        }
    )
    yield Call("POST", _path(m, "config", name, "name", op), op, json=body)


def _read_connection(m: Any, /, name: str) -> Op[ConnectionInfo]:
    """Read a connection (without its password); :class:`NotFoundError` when missing."""
    op = f"database.readConnection {name}"
    d = yield from get_data(Call("GET", _path(m, "config", name, "name", op), op))
    return ConnectionInfo(
        plugin_name=text(d.get("plugin_name")),
        allowed_roles=strings(d.get("allowed_roles")),
        connection_details=string_map(d.get("connection_details")),
    )


def _delete_connection(m: Any, /, name: str) -> Op[None]:
    """Delete a connection."""
    op = f"database.deleteConnection {name}"
    yield Call("DELETE", _path(m, "config", name, "name", op), op)


def _create_role(
    m: Any,
    /,
    name: str,
    *,
    db_name: str,
    creation_statements: Sequence[str],
    revocation_statements: Sequence[str] | None = None,
    renew_statements: Sequence[str] | None = None,
    rollback_statements: Sequence[str] | None = None,
    default_ttl_s: Duration | None = None,
    max_ttl_s: Duration | None = None,
) -> Op[None]:
    """Create or replace a dynamic role (``POST <mount>/roles/<name>``).

    Statements use ``{{name}}``, ``{{password}}`` and ``{{expiration}}``.
    """
    op = f"database.createRole {name}"

    def opt_list(values: Sequence[str] | None) -> list[str] | None:
        return None if values is None else list(values)

    body = compact(
        {
            "db_name": db_name,
            "creation_statements": list(creation_statements),
            "revocation_statements": opt_list(revocation_statements),
            "renew_statements": opt_list(renew_statements),
            "rollback_statements": opt_list(rollback_statements),
            "default_ttl": opt_duration(default_ttl_s),
            "max_ttl": opt_duration(max_ttl_s),
        }
    )
    yield Call("POST", _path(m, "roles", name, "name", op), op, json=body)


def _read_role(m: Any, /, name: str) -> Op[RoleInfo]:
    """Read a role; :class:`NotFoundError` when missing."""
    op = f"database.readRole {name}"
    d = yield from get_data(Call("GET", _path(m, "roles", name, "name", op), op))
    return RoleInfo(
        db_name=text(d.get("db_name")),
        creation_statements=strings(d.get("creation_statements")),
        revocation_statements=strings(d.get("revocation_statements")),
        renew_statements=strings(d.get("renew_statements")),
        rollback_statements=strings(d.get("rollback_statements")),
        default_ttl_s=seconds(d.get("default_ttl")),
        max_ttl_s=seconds(d.get("max_ttl")),
        credential_type=text(d.get("credential_type")),
    )


def _delete_role(m: Any, /, name: str) -> Op[None]:
    """Delete a role."""
    op = f"database.deleteRole {name}"
    yield Call("DELETE", _path(m, "roles", name, "name", op), op)


class Database(SyncModule):
    """Database engine on one mount: ``client.database(mount="database")``."""

    __slots__ = ("mount",)

    def __init__(self, runner: SyncRunner, mount: str = "database") -> None:
        super().__init__(runner)
        self.mount = trim_slashes(mount)

    get_credentials = sync_op(_get_credentials)
    configure_connection = sync_op(_configure_connection)
    read_connection = sync_op(_read_connection)
    delete_connection = sync_op(_delete_connection)
    create_role = sync_op(_create_role)
    read_role = sync_op(_read_role)
    delete_role = sync_op(_delete_role)


class AsyncDatabase(AsyncModule):
    """Async :class:`Database`."""

    __slots__ = ("mount",)

    def __init__(self, runner: AsyncRunner, mount: str = "database") -> None:
        super().__init__(runner)
        self.mount = trim_slashes(mount)

    get_credentials = async_op(_get_credentials)
    configure_connection = async_op(_configure_connection)
    read_connection = async_op(_read_connection)
    delete_connection = async_op(_delete_connection)
    create_role = async_op(_create_role)
    read_role = async_op(_read_role)
    delete_role = async_op(_delete_role)
