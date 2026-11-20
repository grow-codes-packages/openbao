package openbao

// Service-owned: generated once by sdk-kit, then maintained in this repository.

import "context"

// connectSecrets is the LoadConfig connector: a client from the GROW_SECRETS_* bootstrap
// (address, KV mount) and the package's own variables, an AppRole login when
// GROW_SECRETS_AUTH=approle, and the KV SecretsProvider rooted at the mount (LoadConfig reads
// GROW_SECRETS_PATH below it).
func connectSecrets(ctx context.Context, b *SecretsBootstrap, env map[string]string) (*SecretsConnection, error) {
	explicit := Config{KVMount: b.KVMount}
	explicit.URL = b.Addr
	cfg, err := ConfigFromEnvWith(explicit, env)
	if err != nil {
		return nil, err
	}
	cfg.SecretsPath = "" // LoadConfig passes the bootstrap path to GetAll
	if b.Auth == "approle" && cfg.KVVersion == 0 {
		cfg.KVVersion = 2 // AppRole tokens may not read the mount preflight endpoint
	}
	client, err := NewClient(cfg)
	if err != nil {
		return nil, err
	}
	if b.Auth == "approle" {
		login := &AppRoleAuth{RoleID: b.RoleID.Reveal(), SecretID: b.SecretID}
		if _, err := client.Auth().Login(ctx, login); err != nil {
			_ = client.Close()
			return nil, err
		}
	}
	return &SecretsConnection{Provider: client.Secrets(), Path: b.Path, Close: client.Close}, nil
}
