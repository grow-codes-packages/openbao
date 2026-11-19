// Package openbao is the Grow Codes SDK for OpenBao.
//
// Create a client from the environment (GROW_OPENBAO_URL / BAO_ADDR,
// GROW_OPENBAO_TOKEN / BAO_TOKEN, ...) or from a Config literal:
//
//	client, err := openbao.NewClientFromEnv()
//	if err != nil {
//		return err
//	}
//	defer client.Close()
//	status, err := client.Health(ctx)
//
// Every method takes a context.Context first. Service modules hang off the client:
//
//	client.Auth()            logins (TokenAuth, AppRoleAuth, KubernetesAuth, JWTAuth,
//	                         UserpassAuth), LookupSelf, RenewSelf, RevokeSelf,
//	                         CreateToken, StartRenewer
//	client.KV(ctx, mount)    KV engine with auto-detected version (KVv1 / KVv2)
//	client.Secrets()         SecretsProvider over KV (get/set/list/delete/metadata,
//	                         typed getters, LoadEnv, Watch; wrap in NewSecretCache)
//	client.Transit(mount)    encryption as a service
//	client.Database(mount)   dynamic database credentials (Lease)
//	client.Leases()          renew / revoke / auto-renew leases with OnExpire
//	client.PKI(mount)        issue / sign / revoke certificates
//	client.Sys()             seal status, leader, policies, mounts, auth methods,
//	                         AppRole admin
//	client.Wrapping()        response wrapping
//
// Init, Unseal and Seal for test fixtures live in the testkit subpackage.
//
// Every error is an *Error; compare codes with errors.Is against the Err*
// sentinels (errors.Is(err, openbao.ErrNotFound)). OpenBao answers 403 both
// for a missing/invalid token (ErrAuthentication) and for a policy denial
// (ErrPermissionDenied); a check-and-set mismatch is ErrConflict.
// Credentials are wrapped in Secret and never appear in errors, hooks or logs.
//
// OpenBao is a trademark of OpenBao a Series of LF Projects, LLC. This package is not affiliated
// with or endorsed by OpenBao a Series of LF Projects, LLC.
package openbao
