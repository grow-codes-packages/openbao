// Command example shows the OpenBao Go SDK against a real server: health,
// an authenticated ping, the SecretsProvider over KV v2, a KV v2 round trip,
// transit encryption and response wrapping.
//
//	GROW_OPENBAO_URL=http://127.0.0.1:8200 GROW_OPENBAO_TOKEN=... go run .
//
// The token needs write access to secret/ (KV v2) and transit/ (the example
// creates the transit key "example-go" if it is missing).
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"time"

	openbao "github.com/grow-codes-packages/openbao/go"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := openbao.ConfigFromEnv()
	if err != nil {
		return err // CONFIG error naming the variable, never its value
	}
	cfg.Logger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	cfg.Hooks = &openbao.Hooks{
		OnError: func(info openbao.ErrorInfo) {
			if info.WillRetry {
				fmt.Fprintf(os.Stderr, "retrying %s %s (attempt %d)\n", info.Method, info.URL, info.Attempt)
			}
		},
	}
	fmt.Println("config:", cfg) // the token prints as [REDACTED]

	client, err := openbao.NewClient(cfg)
	if err != nil {
		return err
	}
	defer func() { _ = client.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	health, err := client.Health(ctx)
	if err != nil {
		return err
	}
	fmt.Printf("health: healthy=%t status=%s\n", health.Healthy, health.Status)

	latency, err := client.Ping(ctx)
	switch {
	case errors.Is(err, openbao.ErrAuthentication):
		return fmt.Errorf("check GROW_OPENBAO_TOKEN: %w", err)
	case err != nil:
		return err
	}
	version, err := client.ServerVersion(ctx)
	if err != nil {
		return err
	}
	fmt.Printf("ping: %s, server version %s\n", latency, version)

	// SecretsProvider over KV v2 (mount "secret", version auto-detected).
	secrets := client.Secrets()
	v, err := secrets.Set(ctx, "examples/go/db-password", "s3cr3t", &openbao.SetOptions{Tags: map[string]string{"app": "example"}})
	if err != nil {
		return err
	}
	value, err := secrets.Require(ctx, "examples/go/db-password", nil)
	if err != nil {
		return err
	}
	text, _ := value.Reveal()
	fmt.Printf("secret version %s read back (%d chars), printed as %s\n", v, len(text), value)

	// Native KV v2 with check-and-set.
	kv := client.KVv2("secret")
	md, err := kv.Write(ctx, "examples/go/config", map[string]any{"port": 5432}, nil)
	if err != nil {
		return err
	}
	if _, err := kv.Write(ctx, "examples/go/config", map[string]any{"port": 5433}, &openbao.KVWriteOptions{CAS: openbao.Ptr(md.Version)}); err != nil {
		return err
	}
	if _, err := kv.Write(ctx, "examples/go/config", map[string]any{"port": 1}, &openbao.KVWriteOptions{CAS: openbao.Ptr(md.Version)}); errors.Is(err, openbao.ErrConflict) {
		fmt.Println("stale check-and-set write rejected as CONFLICT")
	}

	// Transit: encryption as a service.
	transit := client.Transit("transit")
	if _, err := transit.CreateKey(ctx, "example-go", "aes256-gcm96", nil); err != nil {
		return err
	}
	ct, err := transit.Encrypt(ctx, "example-go", []byte("hello"), nil)
	if err != nil {
		return err
	}
	pt, err := transit.Decrypt(ctx, "example-go", ct.Ciphertext, nil)
	if err != nil {
		return err
	}
	fmt.Printf("transit: %s -> %q\n", ct.Ciphertext[:12]+"...", pt)

	// Response wrapping: hand a secret over with a single-use token.
	wrapped, err := client.Wrapping().Wrap(ctx, map[string]any{"api_key": "abc"}, time.Minute)
	if err != nil {
		return err
	}
	unwrapped, err := client.Wrapping().Unwrap(ctx, wrapped.Token.Reveal())
	if err != nil {
		return err
	}
	fmt.Printf("unwrapped %d field(s) with a token printed as %s\n", len(unwrapped.Data), wrapped.Token)

	// Clean up.
	if err := secrets.Delete(ctx, "examples/go/db-password", &openbao.DeleteOptions{Permanent: true}); err != nil {
		return err
	}
	return kv.DeleteMetadata(ctx, "examples/go/config")
}
