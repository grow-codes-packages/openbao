# Database credentials and leases

Dynamic database credentials from a database secrets engine (`client.database(mount =
"database")`) and the client's `LeaseManager` (`client.leases`) that renews, revokes and watches
leases.

| Function | What it does |
| - | - |
| `configureConnection(name, config)` | `pluginName`, `connectionUrl` (with `{{username}}`/`{{password}}`), `username`, `password`, `allowedRoles`, `verifyConnection`, `extra`; bad credentials → `VALIDATION` |
| `readConnection(name)` / `deleteConnection(name)` | read (without the password) / delete |
| `createRole(name, config)` | `dbName`, `creationStatements`, `revocationStatements`, `renewStatements`, `rollbackStatements`, `defaultTtl`, `maxTtl` |
| `readRole(name)` / `deleteRole(name)` | |
| `getCredentials(role)` → `Lease` | lease id, TTL, renewable flag and the generated username + password (redacted); unknown role → `VALIDATION` |
| `leases.renew(leaseId, increment?)` | renews; the server caps at the role's max TTL (see `warnings` / `capped`) |
| `leases.revoke(leaseId)` / `leases.revokePrefix(prefix)` | revokes now |
| `leases.lookup(leaseId)` | `issueTime`, `expireTime`, `ttl`, `renewable` |
| `leases.manage(lease, options)` → `ManagedLease` | renews at about 2/3 of the TTL until the max TTL, then calls `onExpire` exactly once; `onRenew`, `onError`; stopping it (or `client.close()`) ends the renewals (TypeScript and Java can also revoke on stop) |

The shape of `Lease` follows the language: TypeScript, Python and Java expose `leaseId`,
`leaseDuration` and `data.username` / `data.password`; Rust and Go expose `id`, `duration`,
`username` and `password` directly on the lease.

## Get credentials and keep them alive

=== "TypeScript"

    ```ts
    const lease = await client.database().getCredentials("readonly");
    const pool = connect(lease.data.username, lease.data.password.reveal());
    const managed = client.leases.manage(lease, {
      onExpire: () => pool.reconnectWithNewCredentials(),
    });
    // later: managed.stop(); client.leases.revoke(lease.leaseId)
    ```

=== "Rust"

    ```rust
    use std::sync::Arc;
    use grow_openbao::ManageOptions;

    let lease = client.database().get_credentials("readonly").await?;
    let password = lease.password.clone().expect("password");
    let managed = client.leases().manage(
        lease.clone(),
        ManageOptions {
            on_expire: Some(Arc::new(|_lease| eprintln!("credentials expired"))),
            ..Default::default()
        },
    );
    client.leases().revoke(&lease.id).await?;
    ```

=== "Go"

    ```go
    lease, err := client.Database("database").GetCredentials(ctx, "readonly")
    if err != nil {
        return err
    }
    db := connect(lease.Username, lease.Password.Reveal())
    managed := client.Leases().Manage(lease, &openbao.ManageOptions{
        OnExpire: func(*openbao.Lease) { db.ReconnectWithNewCredentials() },
    })
    _ = managed
    err = client.Leases().Revoke(ctx, lease.ID)
    ```

=== "Python"

    ```python
    lease = client.database().get_credentials("readonly")
    pool = connect(lease.data.username, lease.data.password.reveal())
    managed = client.leases.manage(lease, on_expire=pool.reconnect_with_new_credentials)
    managed.stop()
    client.leases.revoke(lease.lease_id)
    ```

=== "Java"

    ```java
    Lease<DatabaseCredentials> lease = client.database().getCredentials("readonly");
    DataSource ds = connect(lease.data().username(), lease.data().password().reveal());
    ManagedLease managed =
        client.leases()
            .manage(lease, RenewalOptions.builder().onExpire(() -> reconnect()).build());
    managed.close(); // stops renewing
    client.leases().revoke(lease.leaseId());
    ```

## Configure the engine (admin)

=== "TypeScript"

    ```ts
    const db = client.database();
    await db.configureConnection("app-db", {
      pluginName: "postgresql-database-plugin",
      connectionUrl: "postgresql://{{username}}:{{password}}@db:5432/app?sslmode=disable",
      username: "vault",
      password: adminPassword,
      allowedRoles: ["readonly"],
    });
    await db.createRole("readonly", {
      dbName: "app-db",
      creationStatements: [`CREATE ROLE "{{name}}" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}';`],
      defaultTtlMs: 3_600_000,
      maxTtlMs: 86_400_000,
    });
    ```

=== "Rust"

    ```rust
    use grow_openbao::{DatabaseConnectionConfig, DatabaseRole};

    let db = client.database();
    db.configure_connection("app-db", &DatabaseConnectionConfig {
        plugin_name: "postgresql-database-plugin".into(),
        connection_url: "postgresql://{{username}}:{{password}}@db:5432/app".into(),
        username: Some("vault".into()),
        password: Some(admin_password.into()),
        allowed_roles: vec!["readonly".into()],
        ..Default::default()
    }).await?;
    db.create_role("readonly", &DatabaseRole {
        db_name: "app-db".into(),
        creation_statements: vec![CREATE_SQL.into()],
        default_ttl: Some(Duration::from_secs(3600)),
        ..Default::default()
    }).await?;
    ```

=== "Go"

    ```go
    db := client.Database("database")
    err := db.ConfigureConnection(ctx, "app-db", openbao.DatabaseConnectionConfig{
        PluginName:    "postgresql-database-plugin",
        ConnectionURL: "postgresql://{{username}}:{{password}}@db:5432/app",
        Username:      "vault",
        Password:      openbao.NewSecret(adminPassword),
        AllowedRoles:  []string{"readonly"},
    })
    err = db.CreateRole(ctx, "readonly", openbao.DatabaseRoleConfig{
        DBName: "app-db", CreationStatements: []string{createSQL}, DefaultTTL: time.Hour,
    })
    ```

=== "Python"

    ```python
    db = client.database()
    db.configure_connection(
        "app-db",
        plugin_name="postgresql-database-plugin",
        connection_url="postgresql://{{username}}:{{password}}@db:5432/app",
        username="vault",
        password=admin_password,
        allowed_roles=["readonly"],
    )
    db.create_role("readonly", db_name="app-db", creation_statements=[CREATE_SQL], default_ttl_s=3600)
    ```

=== "Java"

    ```java
    Database db = client.database();
    db.configureConnection(
        "app-db",
        ConnectionConfig.builder(
                "postgresql-database-plugin",
                "postgresql://{{username}}:{{password}}@db:5432/app")
            .username("vault")
            .password(adminPassword)
            .allowedRoles("readonly")
            .build());
    db.createRole(
        "readonly",
        RoleConfig.builder("app-db", CREATE_SQL).defaultTtl(Duration.ofHours(1)).build());
    ```
