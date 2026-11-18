// Package openbao is the Grow Codes SDK for OpenBao.
//
// Create a client from the environment (GROW_OPENBAO_URL,
// GROW_OPENBAO_TOKEN, ...) or from a Config literal:
//
//	client, err := openbao.NewClientFromEnv()
//	if err != nil {
//		return err
//	}
//	defer client.Close()
//	status, err := client.Health(ctx)
//
// Every error is an *Error; compare codes with errors.Is against the Err*
// sentinels (errors.Is(err, openbao.ErrNotFound)). Credentials are wrapped in
// Secret and never appear in errors, hooks or logs.
//
// OpenBao is a trademark of OpenBao a Series of LF Projects, LLC. This package is not affiliated
// with or endorsed by OpenBao a Series of LF Projects, LLC.
package openbao
