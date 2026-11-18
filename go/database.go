package openbao

import (
	"context"
	"net/http"
	"time"
)

// Database is the database secrets engine (dynamic credentials).
type Database struct {
	c     *Client
	mount string
}

// Database returns the database engine at mount ("" = "database").
func (c *Client) Database(mount string) *Database {
	return &Database{c: c, mount: mountOr(mount, "database")}
}

// Mount returns the mount path.
func (d *Database) Mount() string { return d.mount }

// Lease is a leased secret such as dynamic database credentials.
type Lease struct {
	// ID is the lease id used by LeaseManager.Renew/Revoke.
	ID        string
	Renewable bool
	// Duration is the lease TTL at IssuedAt.
	Duration time.Duration
	// IssuedAt is the client time the lease was received.
	IssuedAt time.Time
	// Username is data["username"] when present.
	Username string
	// Password is data["password"] when present (redacted when printed).
	Password Secret
	// Data is the raw secret data without "password".
	Data     map[string]any
	Warnings []string
}

// ExpiresAt returns IssuedAt + Duration (zero when the lease never expires).
func (l *Lease) ExpiresAt() time.Time {
	if l.Duration <= 0 {
		return time.Time{}
	}
	return l.IssuedAt.Add(l.Duration)
}

// DatabaseConnectionConfig configures a database connection (ConfigureConnection).
type DatabaseConnectionConfig struct {
	// PluginName is e.g. "postgresql-database-plugin".
	PluginName string
	// ConnectionURL may use {{username}} and {{password}} templates.
	ConnectionURL string
	Username      string
	Password      Secret
	// AllowedRoles lists the roles allowed to use this connection ("*" = all).
	AllowedRoles []string
	// VerifyConnection checks the connection at write time (server default true).
	VerifyConnection *bool
	// Extra holds plugin-specific fields sent as is.
	Extra map[string]any
}

// ConfigureConnection writes a connection (POST <mount>/config/<name>); bad
// credentials are a VALIDATION error when the connection is verified.
func (d *Database) ConfigureConnection(ctx context.Context, name string, cfg DatabaseConnectionConfig) error {
	op := "database.configureConnection " + name
	if err := requireArg(op, "name", name); err != nil {
		return err
	}
	body := map[string]any{}
	for k, v := range cfg.Extra {
		body[k] = v
	}
	body["plugin_name"] = cfg.PluginName
	body["connection_url"] = cfg.ConnectionURL
	if cfg.Username != "" {
		body["username"] = cfg.Username
	}
	if !cfg.Password.IsZero() {
		d.c.rememberSecret(cfg.Password.Reveal())
		body["password"] = cfg.Password.Reveal()
	}
	if len(cfg.AllowedRoles) > 0 {
		body["allowed_roles"] = cfg.AllowedRoles
	}
	if cfg.VerifyConnection != nil {
		body["verify_connection"] = *cfg.VerifyConnection
	}
	_, err := d.c.call(ctx, apiRequest{method: http.MethodPost, path: joinPath(d.mount, "config", name), body: body, op: op})
	return err
}

// ReadConnection returns a connection's configuration (the password is never returned).
func (d *Database) ReadConnection(ctx context.Context, name string) (map[string]any, error) {
	var out map[string]any
	err := d.c.callData(ctx, apiRequest{method: http.MethodGet, path: joinPath(d.mount, "config", name), op: "database.readConnection " + name}, &out)
	return out, err
}

// DeleteConnection removes a connection.
func (d *Database) DeleteConnection(ctx context.Context, name string) error {
	_, err := d.c.call(ctx, apiRequest{method: http.MethodDelete, path: joinPath(d.mount, "config", name), op: "database.deleteConnection " + name})
	return err
}

// DatabaseRoleConfig configures a dynamic role (CreateRole).
type DatabaseRoleConfig struct {
	// DBName is the connection name.
	DBName               string
	CreationStatements   []string
	RevocationStatements []string
	RollbackStatements   []string
	RenewStatements      []string
	DefaultTTL           time.Duration
	MaxTTL               time.Duration
}

// DatabaseRole is a dynamic role as returned by ReadRole.
type DatabaseRole struct {
	DBName               string
	CreationStatements   []string
	RevocationStatements []string
	RollbackStatements   []string
	RenewStatements      []string
	DefaultTTL           time.Duration
	MaxTTL               time.Duration
}

// CreateRole writes a dynamic role (POST <mount>/roles/<name>).
func (d *Database) CreateRole(ctx context.Context, name string, cfg DatabaseRoleConfig) error {
	op := "database.createRole " + name
	if err := requireArg(op, "name", name); err != nil {
		return err
	}
	body := map[string]any{"db_name": cfg.DBName, "creation_statements": cfg.CreationStatements}
	if len(cfg.RevocationStatements) > 0 {
		body["revocation_statements"] = cfg.RevocationStatements
	}
	if len(cfg.RollbackStatements) > 0 {
		body["rollback_statements"] = cfg.RollbackStatements
	}
	if len(cfg.RenewStatements) > 0 {
		body["renew_statements"] = cfg.RenewStatements
	}
	if cfg.DefaultTTL > 0 {
		body["default_ttl"] = durationString(cfg.DefaultTTL)
	}
	if cfg.MaxTTL > 0 {
		body["max_ttl"] = durationString(cfg.MaxTTL)
	}
	_, err := d.c.call(ctx, apiRequest{method: http.MethodPost, path: joinPath(d.mount, "roles", name), body: body, op: op})
	return err
}

// ReadRole returns a dynamic role.
func (d *Database) ReadRole(ctx context.Context, name string) (*DatabaseRole, error) {
	var r struct {
		DBName               string       `json:"db_name"`
		CreationStatements   []string     `json:"creation_statements"`
		RevocationStatements []string     `json:"revocation_statements"`
		RollbackStatements   []string     `json:"rollback_statements"`
		RenewStatements      []string     `json:"renew_statements"`
		DefaultTTL           flexDuration `json:"default_ttl"`
		MaxTTL               flexDuration `json:"max_ttl"`
	}
	if err := d.c.callData(ctx, apiRequest{method: http.MethodGet, path: joinPath(d.mount, "roles", name), op: "database.readRole " + name}, &r); err != nil {
		return nil, err
	}
	return &DatabaseRole{
		DBName: r.DBName, CreationStatements: r.CreationStatements, RevocationStatements: r.RevocationStatements,
		RollbackStatements: r.RollbackStatements, RenewStatements: r.RenewStatements,
		DefaultTTL: r.DefaultTTL.Duration, MaxTTL: r.MaxTTL.Duration,
	}, nil
}

// DeleteRole removes a dynamic role.
func (d *Database) DeleteRole(ctx context.Context, name string) error {
	_, err := d.c.call(ctx, apiRequest{method: http.MethodDelete, path: joinPath(d.mount, "roles", name), op: "database.deleteRole " + name})
	return err
}

// GetCredentials issues credentials for role (GET <mount>/creds/<role>). An
// unknown role is a VALIDATION error. Manage the lease with LeaseManager.
func (d *Database) GetCredentials(ctx context.Context, role string) (*Lease, error) {
	op := "database.getCredentials " + role
	if err := requireArg(op, "role", role); err != nil {
		return nil, err
	}
	env, err := d.c.call(ctx, apiRequest{method: http.MethodGet, path: joinPath(d.mount, "creds", role), op: op})
	if err != nil {
		return nil, err
	}
	var data map[string]any
	if err := env.decodeData(&data); err != nil {
		return nil, err
	}
	l := &Lease{
		ID: env.LeaseID, Renewable: env.Renewable, Duration: seconds(env.LeaseDuration),
		IssuedAt: time.Now(), Data: map[string]any{}, Warnings: env.Warnings,
	}
	for k, v := range data {
		switch k {
		case "password":
			if s, ok := v.(string); ok {
				d.c.rememberSecret(s)
				l.Password = NewSecret(s)
			}
		case "username":
			l.Username, _ = v.(string)
			l.Data[k] = v
		default:
			l.Data[k] = v
		}
	}
	return l, nil
}
