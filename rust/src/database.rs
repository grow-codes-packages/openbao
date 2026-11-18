//! Database secrets engine: dynamic credentials and admin helpers.

use std::fmt;
use std::time::Duration;

use serde_json::{json, Map, Value};
use tokio::time::Instant;

use crate::api::{self, ApiRequest};
use crate::client::OpenBaoClient;
use crate::core::{Result, Secret};

/// A leased secret such as dynamic database credentials.
#[derive(Clone)]
pub struct Lease {
    /// Lease id used by [`LeaseManager`](crate::LeaseManager) renew/revoke.
    pub id: String,
    /// Whether the lease can be renewed.
    pub renewable: bool,
    /// TTL at `issued_at`.
    pub duration: Duration,
    /// Client time the lease was received.
    pub issued_at: Instant,
    /// `data.username` when present.
    pub username: Option<String>,
    /// `data.password` when present (redacted when printed).
    pub password: Option<Secret>,
    /// The raw secret data without `password`.
    pub data: Map<String, Value>,
    /// Server warnings.
    pub warnings: Vec<String>,
}

impl fmt::Debug for Lease {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Lease")
            .field("id", &self.id)
            .field("renewable", &self.renewable)
            .field("duration", &self.duration)
            .field("username", &self.username)
            .field("password", &self.password)
            .field("data_keys", &self.data.keys().collect::<Vec<_>>())
            .field("warnings", &self.warnings)
            .finish()
    }
}

impl Lease {
    /// `issued_at + duration` (`None` when the lease never expires).
    pub fn expires_at(&self) -> Option<Instant> {
        (!self.duration.is_zero()).then(|| self.issued_at + self.duration)
    }
}

/// A database connection (`configure_connection`).
#[derive(Clone, Default)]
pub struct DatabaseConnectionConfig {
    /// Plugin, e.g. `postgresql-database-plugin`.
    pub plugin_name: String,
    /// Connection URL; may use `{{username}}` and `{{password}}` templates.
    pub connection_url: String,
    /// Admin user.
    pub username: Option<String>,
    /// Admin password (redacted when printed).
    pub password: Option<Secret>,
    /// Roles allowed to use the connection (`*` = all).
    pub allowed_roles: Vec<String>,
    /// Checks the connection at write time (server default true).
    pub verify_connection: Option<bool>,
    /// Plugin-specific fields sent as is.
    pub extra: Map<String, Value>,
}

impl fmt::Debug for DatabaseConnectionConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DatabaseConnectionConfig")
            .field("plugin_name", &self.plugin_name)
            .field(
                "connection_url",
                &crate::core::redact::redact_url(&self.connection_url),
            )
            .field("username", &self.username)
            .field("password", &self.password)
            .field("allowed_roles", &self.allowed_roles)
            .field("verify_connection", &self.verify_connection)
            .finish_non_exhaustive()
    }
}

/// A dynamic role (`create_role` / `read_role`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DatabaseRole {
    /// Connection name.
    pub db_name: String,
    /// SQL run to create a user.
    pub creation_statements: Vec<String>,
    /// SQL run to revoke a user.
    pub revocation_statements: Vec<String>,
    /// SQL run on rollback.
    pub rollback_statements: Vec<String>,
    /// SQL run on renewal.
    pub renew_statements: Vec<String>,
    /// Default TTL.
    pub default_ttl: Option<Duration>,
    /// Maximum TTL.
    pub max_ttl: Option<Duration>,
}

/// Database engine at one mount; get it with [`OpenBaoClient::database`].
#[derive(Debug, Clone)]
pub struct Database {
    client: OpenBaoClient,
    mount: String,
}

impl Database {
    pub(crate) fn new(client: OpenBaoClient, mount: &str) -> Self {
        Database {
            client,
            mount: mount.to_owned(),
        }
    }

    /// The same engine at another mount.
    pub fn at(mut self, mount: &str) -> Self {
        self.mount = api::mount_or(mount, &self.mount);
        self
    }

    /// The mount path.
    pub fn mount(&self) -> &str {
        &self.mount
    }

    fn path(&self, kind: &str, name: &str) -> String {
        api::encode_path(&api::join(&[&self.mount, kind, name]))
    }

    /// Writes a connection (`POST <mount>/config/<name>`); bad credentials are
    /// `VALIDATION` when the connection is verified.
    pub async fn configure_connection(
        &self,
        name: &str,
        cfg: &DatabaseConnectionConfig,
    ) -> Result<()> {
        let op = format!("database.configureConnection {name}");
        api::require_arg(&op, "name", name)?;
        let mut body = cfg.extra.clone();
        body.insert("plugin_name".into(), json!(cfg.plugin_name));
        body.insert("connection_url".into(), json!(cfg.connection_url));
        if let Some(u) = &cfg.username {
            body.insert("username".into(), json!(u));
        }
        if let Some(p) = &cfg.password {
            self.client.remember_secret(p);
            body.insert("password".into(), json!(p.expose_secret()));
        }
        if !cfg.allowed_roles.is_empty() {
            body.insert("allowed_roles".into(), json!(cfg.allowed_roles));
        }
        if let Some(v) = cfg.verify_connection {
            body.insert("verify_connection".into(), json!(v));
        }
        self.client
            .call(ApiRequest::post(self.path("config", name), op).json(Value::Object(body)))
            .await?;
        Ok(())
    }

    /// A connection's configuration (the password is never returned).
    pub async fn read_connection(&self, name: &str) -> Result<Map<String, Value>> {
        let d = self
            .client
            .data(ApiRequest::get(
                self.path("config", name),
                format!("database.readConnection {name}"),
            ))
            .await?;
        Ok(d.as_object().cloned().unwrap_or_default())
    }

    /// Removes a connection.
    pub async fn delete_connection(&self, name: &str) -> Result<()> {
        self.client
            .call(ApiRequest::delete(
                self.path("config", name),
                format!("database.deleteConnection {name}"),
            ))
            .await?;
        Ok(())
    }

    /// Writes a dynamic role (`POST <mount>/roles/<name>`).
    pub async fn create_role(&self, name: &str, role: &DatabaseRole) -> Result<()> {
        let op = format!("database.createRole {name}");
        api::require_arg(&op, "name", name)?;
        let mut body = json!({
            "db_name": role.db_name,
            "creation_statements": role.creation_statements,
        });
        for (k, v) in [
            ("revocation_statements", &role.revocation_statements),
            ("rollback_statements", &role.rollback_statements),
            ("renew_statements", &role.renew_statements),
        ] {
            if !v.is_empty() {
                body[k] = json!(v);
            }
        }
        for (k, d) in [("default_ttl", role.default_ttl), ("max_ttl", role.max_ttl)] {
            if let Some(d) = d.filter(|d| !d.is_zero()) {
                body[k] = json!(api::duration_string(d));
            }
        }
        self.client
            .call(ApiRequest::post(self.path("roles", name), op).json(body))
            .await?;
        Ok(())
    }

    /// Reads a dynamic role.
    pub async fn read_role(&self, name: &str) -> Result<DatabaseRole> {
        let d = self
            .client
            .data(ApiRequest::get(
                self.path("roles", name),
                format!("database.readRole {name}"),
            ))
            .await?;
        let ttl = |k: &str| Some(api::secs(&d, k)).filter(|t| !t.is_zero());
        Ok(DatabaseRole {
            db_name: api::s(&d, "db_name"),
            creation_statements: api::strings(&d, "creation_statements"),
            revocation_statements: api::strings(&d, "revocation_statements"),
            rollback_statements: api::strings(&d, "rollback_statements"),
            renew_statements: api::strings(&d, "renew_statements"),
            default_ttl: ttl("default_ttl"),
            max_ttl: ttl("max_ttl"),
        })
    }

    /// Removes a dynamic role.
    pub async fn delete_role(&self, name: &str) -> Result<()> {
        self.client
            .call(ApiRequest::delete(
                self.path("roles", name),
                format!("database.deleteRole {name}"),
            ))
            .await?;
        Ok(())
    }

    /// Issues credentials for `role` (`GET <mount>/creds/<role>`). An unknown role is
    /// `VALIDATION`. Keep the lease alive with [`LeaseManager::manage`](crate::LeaseManager::manage).
    pub async fn get_credentials(&self, role: &str) -> Result<Lease> {
        let op = format!("database.getCredentials {role}");
        api::require_arg(&op, "role", role)?;
        let env = self
            .client
            .call(ApiRequest::get(self.path("creds", role), op))
            .await?;
        let mut data = env.data.as_object().cloned().unwrap_or_default();
        let password = data
            .remove("password")
            .and_then(|p| p.as_str().map(Secret::new));
        if let Some(p) = &password {
            self.client.remember_secret(p);
        }
        Ok(Lease {
            id: env.lease_id,
            renewable: env.renewable,
            duration: env.lease_duration,
            issued_at: Instant::now(),
            username: data
                .get("username")
                .and_then(Value::as_str)
                .map(str::to_owned),
            password,
            data,
            warnings: env.warnings,
        })
    }
}
