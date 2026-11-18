package openbao

import (
	"fmt"
	"strings"
)

// DefaultURL is the default endpoint of OpenBao.
const DefaultURL = "http://127.0.0.1:8200"

// DefaultKVMount is the KV mount used by the SecretsProvider when Config.KVMount is empty.
const DefaultKVMount = "secret"

// DefaultValueField is the KV data field that holds a SecretsProvider value.
const DefaultValueField = "value"

// vendorEnv lists the vendor variables consulted after GROW_OPENBAO_*, in order.
var vendorEnv = VendorEnv{
	URL:                []string{"BAO_ADDR", "VAULT_ADDR"},
	CACert:             []string{"BAO_CACERT", "VAULT_CACERT"},
	ClientCert:         []string{"BAO_CLIENT_CERT", "VAULT_CLIENT_CERT"},
	ClientKey:          []string{"BAO_CLIENT_KEY", "VAULT_CLIENT_KEY"},
	InsecureSkipVerify: []string{"BAO_SKIP_VERIFY", "VAULT_SKIP_VERIFY"},
}

// vendorTokenEnv lists vendor variables for the token, in precedence order.
var vendorTokenEnv = []string{"BAO_TOKEN", "VAULT_TOKEN"}

// vendorNamespaceEnv lists vendor variables for the namespace, in precedence order.
var vendorNamespaceEnv = []string{"BAO_NAMESPACE", "VAULT_NAMESPACE"}

// Config configures a Client. Build it with a struct literal or ConfigFromEnv;
// zero values mean "use the default". Call Validate to check it.
//
// Environment variables read by ConfigFromEnv (explicit value > GROW_OPENBAO_* >
// vendor variables > default):
//
//	URL                  GROW_OPENBAO_URL, BAO_ADDR, VAULT_ADDR
//	Token                GROW_OPENBAO_TOKEN, BAO_TOKEN, VAULT_TOKEN
//	Namespace            GROW_OPENBAO_NAMESPACE, BAO_NAMESPACE, VAULT_NAMESPACE
//	TLS.CACertPath       GROW_OPENBAO_CA_CERT, BAO_CACERT, VAULT_CACERT
//	TLS.ClientCertPath   GROW_OPENBAO_CLIENT_CERT, BAO_CLIENT_CERT, VAULT_CLIENT_CERT
//	TLS.ClientKeyPath    GROW_OPENBAO_CLIENT_KEY, BAO_CLIENT_KEY, VAULT_CLIENT_KEY
//	TLS.InsecureSkipVerify GROW_OPENBAO_INSECURE_SKIP_VERIFY, BAO_SKIP_VERIFY, VAULT_SKIP_VERIFY
//	KVMount              GROW_OPENBAO_KV_MOUNT
//	KVVersion            GROW_OPENBAO_KV_VERSION
//	SecretsPath          GROW_OPENBAO_SECRETS_PATH
//
// plus the common GROW_OPENBAO_CONNECT_TIMEOUT, REQUEST_TIMEOUT, TOTAL_TIMEOUT,
// MAX_RETRIES and PROXY.
type Config struct {
	CommonConfig

	// Token authenticates requests (X-Vault-Token). It may be empty when the
	// client logs in with Auth().Login.
	Token Secret
	// Namespace is sent as X-Vault-Namespace on every request ("" = root namespace).
	Namespace string
	// KVMount is the KV mount the SecretsProvider uses (default "secret").
	KVMount string
	// KVVersion forces the KV version (1 or 2) of KVMount and of KV(); 0 auto-detects
	// it per mount through sys/internal/ui/mounts.
	KVVersion int
	// SecretsPath is the base path inside KVMount under which the SecretsProvider
	// stores secrets ("" = the mount root).
	SecretsPath string
	// ValueField is the KV data field holding a SecretsProvider value (default "value").
	ValueField string
}

// ConfigFromEnv reads the configuration from the process environment.
func ConfigFromEnv() (Config, error) { return ConfigFromEnvWith(Config{}, nil) }

// ConfigFromEnvWith resolves explicit values > GROW_OPENBAO_* > vendor
// variables > defaults. env replaces the process environment when non-nil.
func ConfigFromEnvWith(explicit Config, env map[string]string) (Config, error) {
	r := NewEnvReader(EnvPrefix, env)
	c := explicit
	if err := c.applyEnv(r, vendorEnv); err != nil {
		return Config{}, err
	}
	if c.Token.IsZero() {
		if v, ok := r.String("TOKEN", vendorTokenEnv...); ok {
			c.Token = NewSecret(v)
		}
	}
	if c.Namespace == "" {
		c.Namespace, _ = r.String("NAMESPACE", vendorNamespaceEnv...)
	}
	if c.KVMount == "" {
		c.KVMount, _ = r.String("KV_MOUNT")
	}
	if c.SecretsPath == "" {
		c.SecretsPath, _ = r.String("SECRETS_PATH")
	}
	if c.KVVersion == 0 {
		v, ok, err := r.Int("KV_VERSION")
		if err != nil {
			return Config{}, err
		}
		if ok {
			c.KVVersion = v
		}
	}
	c.CommonConfig = c.withDefaults(DefaultURL)
	if err := c.Validate(); err != nil {
		return Config{}, err
	}
	return c, nil
}

// Validate checks the configuration and returns a CONFIG error.
func (c Config) Validate() error {
	if err := c.withDefaults(DefaultURL).validate(); err != nil {
		return err
	}
	if c.KVVersion < 0 || c.KVVersion > 2 {
		return ConfigError("kvVersion must be 0 (auto), 1 or 2")
	}
	if strings.ContainsAny(c.Namespace, " \t\r\n") {
		return ConfigError("namespace must not contain whitespace")
	}
	return nil
}

// kvMount returns the effective KV mount without surrounding slashes.
func (c Config) kvMount() string {
	if m := strings.Trim(c.KVMount, "/"); m != "" {
		return m
	}
	return DefaultKVMount
}

// valueField returns the effective value field.
func (c Config) valueField() string {
	if c.ValueField != "" {
		return c.ValueField
	}
	return DefaultValueField
}

// String renders the configuration with every credential redacted.
func (c Config) String() string {
	return fmt.Sprintf("Config{%s Token:%s Namespace:%s KVMount:%s KVVersion:%d SecretsPath:%s}",
		c.describe(), c.Token, c.Namespace, c.kvMount(), c.KVVersion, c.SecretsPath)
}

// GoString renders the configuration with every credential redacted.
func (c Config) GoString() string { return c.String() }
