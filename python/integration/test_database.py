"""Dynamic database credentials, leases and the LeaseManager against the real server."""

from __future__ import annotations

import threading

import pytest

import grow_openbao as sdk


def test_get_credentials_and_lease_ops(client: sdk.OpenBaoClient, env: dict[str, str]) -> None:
    db = client.database(env["GROW_OPENBAO_TEST_DB_MOUNT"])
    lease = db.get_credentials(env["GROW_OPENBAO_TEST_DB_ROLE"])
    assert lease.lease_id.startswith("database/creds/")
    assert lease.renewable and lease.lease_duration_s == 3600
    assert lease.data.username.startswith("v-")
    assert lease.data.password.reveal() and lease.data.password.reveal() not in repr(lease)
    info = client.leases.lookup(lease.lease_id)
    assert info.id == lease.lease_id and info.ttl_s > 0 and info.renewable
    renewed = client.leases.renew(lease.lease_id, 600)
    assert renewed.lease_id == lease.lease_id and 0 < renewed.lease_duration_s <= 600
    capped = client.leases.renew(lease.lease_id, 100 * 3600)
    assert capped.warnings
    client.leases.revoke(lease.lease_id)
    with pytest.raises(sdk.ValidationError):
        client.leases.lookup(lease.lease_id)
    other = db.get_credentials(env["GROW_OPENBAO_TEST_DB_ROLE"])
    client.leases.revoke_prefix(f"database/creds/{env['GROW_OPENBAO_TEST_DB_ROLE']}")
    with pytest.raises(sdk.ValidationError):
        client.leases.renew(other.lease_id)
    with pytest.raises(sdk.ValidationError):
        db.get_credentials("no-such-role")


def test_connection_and_role_admin(
    client: sdk.OpenBaoClient, env: dict[str, str], run_id: str
) -> None:
    db = client.database()
    conn = f"py-{run_id}"
    role = f"py-role-{run_id}"
    url = (
        "postgresql://{{username}}:{{password}}@"
        f"{env['GROW_OPENBAO_TEST_PG_HOST']}:{env['GROW_OPENBAO_TEST_PG_PORT']}/"
        f"{env['GROW_OPENBAO_TEST_PG_DB']}?sslmode=disable"
    )
    db.configure_connection(
        conn,
        plugin_name="postgresql-database-plugin",
        connection_url=url,
        username=env["GROW_OPENBAO_TEST_PG_ADMIN_USER"],
        password=env["GROW_OPENBAO_TEST_PG_ADMIN_PASSWORD"],
        allowed_roles=[role],
    )
    info = db.read_connection(conn)
    assert info.plugin_name == "postgresql-database-plugin"
    assert info.allowed_roles == [role]
    assert "password" not in info.connection_details
    db.create_role(
        role,
        db_name=conn,
        creation_statements=[
            "CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' "
            "VALID UNTIL '{{expiration}}';"
        ],
        default_ttl_s=300,
        max_ttl_s=600,
    )
    r = db.read_role(role)
    assert r.db_name == conn and r.default_ttl_s == 300 and r.max_ttl_s == 600
    lease = db.get_credentials(role)
    client.leases.revoke(lease.lease_id)
    db.delete_role(role)
    with pytest.raises(sdk.NotFoundError):
        db.read_role(role)
    db.delete_connection(conn)
    with pytest.raises(sdk.NotFoundError):
        db.read_connection(conn)
    with pytest.raises(sdk.ValidationError):
        db.configure_connection(
            f"{conn}-bad",
            plugin_name="postgresql-database-plugin",
            connection_url=url,
            username=env["GROW_OPENBAO_TEST_PG_ADMIN_USER"],
            password="wrong-password",
            allowed_roles=["*"],
        )


def test_lease_manager_renews_then_expires(client: sdk.OpenBaoClient, env: dict[str, str]) -> None:
    """sdk-short: 10 s TTL, 30 s max → renewals, capping, then on_expire exactly once."""
    lease = client.database().get_credentials(env["GROW_OPENBAO_TEST_DB_SHORT_ROLE"])
    renewals: list[sdk.LeaseRenewal] = []
    expired = threading.Event()
    calls: list[int] = []

    def on_expire() -> None:
        calls.append(1)
        expired.set()

    handle = client.leases.manage(
        lease, increment_s=10, on_renew=renewals.append, on_expire=on_expire
    )
    assert handle.running and client.leases.active_leases == 1
    assert expired.wait(45), "lease never reported expiry"
    assert renewals, "lease was never renewed"
    assert handle.expired and calls == [1]
    assert client.leases.active_leases == 0
    handle.stop()


def test_managed_lease_revoke_on_stop(client: sdk.OpenBaoClient, env: dict[str, str]) -> None:
    lease = client.database().get_credentials(env["GROW_OPENBAO_TEST_DB_ROLE"])
    handle = client.leases.manage(lease, revoke_on_stop=True)
    handle.stop()
    assert not handle.running
    with pytest.raises(sdk.ValidationError):
        client.leases.lookup(lease.lease_id)
    other = client.database().get_credentials(env["GROW_OPENBAO_TEST_DB_ROLE"])
    client.leases.manage(other, revoke_on_stop=True)
    client.leases.stop_all()
    assert client.leases.active_leases == 0
