---
name: openbao-sdk
description: Add and use the Grow Codes SDK for OpenBao (`openbao`) in TypeScript, Rust, Go, Python or Java projects. Use when code must talk to OpenBao - installing @grow-codes/openbao, the grow-openbao crate or PyPI package, the Go module github.com/grow-codes-packages/openbao/go or Maven codes.grow.packages:openbao, configuring it with GROW_OPENBAO_* variables, handling OpenBaoError codes, testing with the bundled fakes, or running the Docker integration suite of this repository.
---

# OpenBao SDK (Grow Codes)

One API for OpenBao in five languages (categories: secrets). Pick the package for the
project's language, configure it from the environment, and handle errors by their canonical code.

## 1. Add the package

| Language | Command | Import |
| - | - | - |
| TypeScript | `npm install @grow-codes/openbao` | `import { OpenBaoClient } from "@grow-codes/openbao"` |
| Rust | `cargo add grow-openbao` (add `tokio` with `macros,rt-multi-thread`) | `use grow_openbao::OpenBaoClient;` |
| Go | `go get github.com/grow-codes-packages/openbao/go` | `openbao "github.com/grow-codes-packages/openbao/go"` |
| Python | `pip install grow-openbao` (or `uv add grow-openbao`) | `from grow_openbao import OpenBaoClient` |
| Java | Maven `codes.grow.packages:openbao` (Gradle `implementation("codes.grow.packages:openbao:<version>")`) | `import codes.grow.packages.openbao.OpenBaoClient;` |

Check the latest version in the README badges before pinning one.

## 2. Configure

Prefer environment configuration so no credential is written into code:

```sh
export GROW_OPENBAO_URL=https://openbao.example.internal
export GROW_OPENBAO_TOKEN=...            # from your secret store, never committed
```

Precedence: explicit config value > `GROW_OPENBAO_*` > vendor variables (`BAO_*` first, then the
HashiCorp Vault compatible `VAULT_*`: `ADDR`, `TOKEN`, `NAMESPACE`, `CACERT`, `CLIENT_CERT`,
`CLIENT_KEY`, `SKIP_VERIFY`) > default. OpenBao-specific: `GROW_OPENBAO_NAMESPACE`,
`GROW_OPENBAO_KV_MOUNT` (default `secret`), `GROW_OPENBAO_KV_VERSION` (`1`/`2`, default
auto-detect) and `GROW_OPENBAO_SECRETS_PATH` (base path of `client.secrets()`). Leave the token
unset when the application logs in with AppRole, JWT, Kubernetes or userpass.
Other variables: `…_CONNECT_TIMEOUT`, `…_REQUEST_TIMEOUT`, `…_TOTAL_TIMEOUT` (`10s`, `1500`),
`…_MAX_RETRIES`, `…_CA_CERT`, `…_CLIENT_CERT`, `…_CLIENT_KEY`, `…_PROXY`. Environment proxies
(`HTTPS_PROXY`) are ignored unless `proxy` is set.

## 3. Use

Create one client per process and close it on shutdown (TypeScript `await client.close()`, Rust
`client.close().await`, Go `defer client.Close()`, Python `with …`/`close()`, Java
try-with-resources).

- `health()` never throws for an unhealthy service; check `healthy`.
- `ping()` verifies credentials (`AUTHENTICATION` error when they are wrong).
- All I/O is retried with jitter on 429/502/503/504 and connection errors; only idempotent calls
  are retried on 500.
- Errors carry `code` (`CONFIG`, `AUTHENTICATION`, `PERMISSION_DENIED`, `NOT_FOUND`, `CONFLICT`,
  `RATE_LIMITED`, `VALIDATION`, `UNAVAILABLE`, `TIMEOUT`, `UNSUPPORTED`, `CANCELLED`), `retryable`,
  `httpStatus` and `requestId`. Branch on the code, not on the message text. Go:
  `errors.Is(err, openbao.ErrNotFound)`.

### Secrets

Read with `get`/`getString`/`getJson`/`require` (missing → `null`/`None`/`nil`, `require` →
`NOT_FOUND`), write with `set`, list with `list`, load into the environment with `loadEnv`, watch
with `watch`. Wrap the provider in `SecretCache` for hot paths. Values are `SecretValue` objects:
call `reveal()` only where the plain value is needed and never log it.

<!-- service:skill-usage — the service adds its own functions and examples here. -->

### OpenBao modules

| Need | Use (TypeScript names; other languages per their convention) |
| - | - |
| Log in without a static token | `client.auth.login(new AppRoleAuth(roleId, secretId))` (also `JwtAuth`, `KubernetesAuth(role)`, `UserpassAuth`, `TokenAuth`), then `client.auth.startRenewer({ onExpire })` |
| One secret value per path (portable code) | `client.secrets()` — the shared SecretsProvider over KV (`{"value": ...}`; versions = KV v2 versions) |
| Raw KV maps, versions, check-and-set | `client.kv(mount)` (`read`, `write(path, data, {cas})`, `patch`, `list`, `readMetadata`, `deleteVersions`, `undelete`, `destroy`) |
| Encrypt data without holding keys | `client.transit().encrypt(key, plaintext)` / `decrypt` / `rewrap`; `sign` / `verify`; `generateDataKey` |
| Short-lived database users | `client.database().getCredentials(role)` + `client.leases.manage(lease, { onExpire })` |
| TLS certificates | `client.pki().issueCertificate(role, commonName, { ttl })`, `revokeCertificate(serial)` |
| Policies, mounts, AppRole setup | `client.sys.writePolicy`, `enableSecretsEngine`, `enableAuthMethod`, `createAppRole`, `readRoleId`, `generateSecretId` |
| Hand a secret to another process once | `client.wrapping.wrap(data, ttl)` → token → `client.wrapping.unwrap(token)` |
| Initialise/unseal a test server | testing module: `init`, `unseal`, `seal`, `initStatus`, `waitForActive` (never in production code) |

Accessors per language: TypeScript/Python `client.auth`, `client.sys`, `client.wrapping`,
`client.leases` (properties) and `client.kv()`, `client.transit()`, `client.database()`,
`client.pki()`, `client.secrets()`; Rust/Java the same as methods (`client.auth()`, …; Rust
`client.kv().await?` detects the KV version); Go `client.Auth()`, `client.Leases()`,
`client.KV(ctx, mount)`, `client.Transit(mount)`, `client.Secrets()` / `client.SecretsWith(opts)`.

Errors to expect:

- `AUTHENTICATION`: bad, expired or revoked token (OpenBao answers a plain 403 "permission
  denied") and every rejected login (400/401/403).
- `PERMISSION_DENIED`: a valid token whose policy does not allow the path.
- `NOT_FOUND`: missing (or soft-deleted) secret; `SecretsProvider.get` returns null instead.
- `CONFLICT`: KV check-and-set mismatch.
- `UNSUPPORTED`: a KV v2-only call on a KV v1 mount (raised before any request).
- `VALIDATION`: invalid input, a policy with bad HCL, `get(name, {version})` on KV v1.

Details and examples for every function: `docs/functions/*.md` (published at
https://grow-codes-packages.github.io/openbao/).

## 4. Test code that uses the SDK

Use the in-memory fakes from the testing module instead of a real OpenBao in unit tests:
TypeScript `@grow-codes/openbao/testing`, Rust feature `testing`, Go package `testkit`, Python
`grow_openbao.testing`, Java `codes.grow.packages.openbao.testing`.

## 5. Work on this repository

Read `AGENTS.md` first. Short version: the five languages keep the same API; files with the
`Generated by sdk-kit` header are changed in sdk-kit, not here; `make lint coverage` must pass
(≥ 90 % lines and branches); `make test-docker LANGS="<lang>"` runs the integration suite against
`openbao/openbao:2.7.2`. Service rules every language follows (error mapping, KV/SecretsProvider
mapping, health states, environment variables) are listed under "Parity decisions" in
`docs/compatibility.md`; read them before changing behaviour in one language. Recorded responses
for unit tests live in each package's `fixtures` folder.
