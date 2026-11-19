# Compatibility

## Runtimes

| Language | Supported | Tested in CI |
| - | - | - |
| TypeScript | Node.js ≥ 22.12, ESM and CommonJS | Node 22, 24 |
| Rust | MSRV 1.88, edition 2021, tokio | stable, 1.88 |
| Go | Go ≥ 1.26 | 1.26, 1.27 |
| Python | ≥ 3.10 | 3.10, 3.13, 3.14 |
| Java | ≥ 17 (Java 17 bytecode) | Temurin 17, 21, 25 |

## OpenBao versions

The integration suite runs against `openbao/openbao:2.7.2` (the tag of the Grow Codes stack
catalog) in server mode with single-node Raft storage and a static auto-unseal key, plus a second,
never-initialised Shamir instance for the `testing` lifecycle helpers. OpenBao 2.7 removed the
`file` storage backend, so the fixture uses Raft. Other OpenBao versions with the same HTTP API are
expected to work.

The packages also speak to **HashiCorp Vault** for everything both products share (same paths,
headers and response envelope); `VAULT_ADDR`, `VAULT_TOKEN`, `VAULT_NAMESPACE`, `VAULT_CACERT`,
`VAULT_CLIENT_CERT`/`VAULT_CLIENT_KEY` and `VAULT_SKIP_VERIFY` are read as fallbacks. The dedicated
`hashicorp-vault` repository keeps the same module layout.

## Service behaviour the SDK normalises

| OpenBao behaviour | What the SDK does (all languages) |
| - | - |
| 403 for both a bad token and a policy denial; they differ only in the body | Plain `["permission denied"]` (missing, invalid, expired or revoked token) or no error text → `AUTHENTICATION`; the wrapped `1 error occurred: * permission denied` form (policy denial) → `PERMISSION_DENIED`; a message naming an invalid/missing token → `AUTHENTICATION` |
| Login endpoints answer 400 (`invalid role or secret ID`, `invalid username or password`, expired JWT), 401 or 403 for rejected credentials | `AUTHENTICATION` for every login method |
| 400 `check-and-set parameter did not match` | `CONFLICT` |
| 405 (e.g. `PATCH` on a KV v1 mount) | `UNSUPPORTED` |
| 501 (server not initialised) / 503 (sealed) | `UNAVAILABLE` (retryable) |
| KV `DELETE` answers 204 for missing paths | `SecretsProvider.delete` reads first and raises `NOT_FOUND` |
| KV v2 404 with `data.metadata` for a deleted or destroyed version | `NOT_FOUND`; a key whose current version is deleted counts as missing in `get`, `exists`, `metadata`, `list` and `delete` |
| Transit batch: HTTP 400 with per-item results when one item fails | requests send `partial_failure_response_code: 207`; per-item errors are returned, not thrown |
| `transit/verify` answers 200 `valid: false` for a bad signature | `verify` returns `false` |
| `pki/ca_chain` is raw PEM; `pki/tidy` is asynchronous (202) | `readCaChain` returns the PEM text; `tidy` returns the started status, `tidyStatus` polls |
| `sys/health` uses 429/472/473/501/503 for node states | `health()` asks for 200 in every state and maps the body to `active`, `standby`, `perfstandby`, `sealed` or `uninitialized`; any error is `unreachable`; `healthy` is true only for `active` |
| A newly enabled KV v2 mount answers 400 `Upgrading from non-versioned to versioned data` for a moment | callers that enable their own mounts should retry (the Docker suites do) |
| `Retry-After` on 429 only when `sys/quotas/config.enable_rate_limit_response_headers=true` | honoured when present, full-jitter backoff otherwise |

## Functions the Docker suite cannot serve

Every public function is called against the real service in the Docker suite. These parts cannot
be served by the single-node fixture; they are covered by unit tests with recorded responses:

| Function | Languages | Reason |
| - | - | - |
| `KubernetesAuth` successful login | all | The fixture has no Kubernetes API for the TokenReview call. The Docker suite verifies the request shape (OpenBao answers 403 → `AUTHENTICATION`); the success path is unit-tested. |
| `health()` states `standby` / `perfstandby` | all | Single node; 429/473 appear only for about a second after init. Unit tests use recorded bodies. |
| `TokenRenewer` / `LeaseManager.manage` timing edge cases (refresh-ahead, max-TTL capping, `onExpire` exactly once) | all | Fake clocks in unit tests; real renewals and a real 30 s lease expiry run in Docker too. |
| Retries on 5xx and network errors, `Retry-After` as an HTTP date, TLS/mTLS | all | Deterministic HTTP fixtures in the core unit tests (a real 429 with `Retry-After` was recorded). |

## Skipped conformance scenarios

| Scenario | Reason |
| - | - |
| — | none: the `core` and `secrets` scenarios run on KV v2 (`secret/`) and on KV v1 (`kv1/`) |

## Parity decisions

These rules are the same in all five packages (decided for the OpenBao pilot; they also apply to
the `hashicorp-vault` package):

- **Errors**: see the table above. Login 400/401/403 → `AUTHENTICATION` (TypeScript, Rust, Go,
  Python and Java identical).
- **SecretsProvider over KV**: one secret = one KV path stored as `{"value": "<string>"}` (field
  configurable with `valueField`); bytes that are not valid UTF-8 (TypeScript, Python, Rust: every
  byte input) are stored base64-encoded with `"encoding": "base64"`; objects are JSON-encoded into
  `value`. A path without the value field is returned as the JSON encoding of the whole map.
  Versions are the KV v2 version numbers as strings (`""` on KV v1). `list` returns names sorted,
  skips sub-folders, and on KV v2 reads metadata per key with a concurrency of 8.
- **Versions on KV v1**: `SecretsProvider.get(name, {version})` → `VALIDATION`; `KvV1.read` with a
  version and every v2-only operation (`patch`, `deleteVersions`, `undelete`, `destroy`, metadata
  calls, `cas`) → `UNSUPPORTED` without a request. A version must be a positive integer
  (`VALIDATION` otherwise).
- **Metadata `extra`** (KV v2): `maxVersions`, `casRequired` (`"true"`/`"false"`),
  `deleteVersionAfter` (whole seconds with an `s` suffix, e.g. `"0s"`, `"2592000s"`) and
  `oldestVersion`; `SetOptions.description` is stored as the custom metadata key `description`.
- **health()**: `details` holds `version`, `initialized`, `sealed`, `standby` and `clusterName`
  (when set); on errors `error` (and `httpStatus`). `sys.health()` returns the typed node state
  (`state`, `initialized`, `sealed`, `standby`, `performanceStandby`, `version`, `clusterName`,
  `clusterId`, `serverTime`).
- **Environment**: `GROW_OPENBAO_KV_MOUNT`, `GROW_OPENBAO_KV_VERSION` (`1`, `2`; `0` = auto-detect;
  anything else → `CONFIG`) and `GROW_OPENBAO_SECRETS_PATH` set the defaults of `client.secrets()`
  and `client.kv()` in every language. `~/.vault-token` is not read.

## Language differences

The API is the same in every language; only the conventions differ:

| Topic | TypeScript | Rust | Go | Python | Java |
| - | - | - | - | - | - |
| Durations | `…Ms` numbers | `Duration` | `time.Duration` | float seconds `…_s` (or `timedelta`) | `Duration` |
| Async | `Promise` + `AbortSignal` | `async` (tokio) + `blocking` feature | sync with `ctx` | `OpenBaoClient` + `AsyncOpenBaoClient` | sync + `…Async` |
| Module accessors | `client.auth`, `client.sys`, `client.wrapping`, `client.leases` (properties); `client.kv()`, `client.transit()`, … | `client.auth()`, `client.leases()`, `client.kv().await?` (detects the KV version on access), `client.transit()`, … | `client.Auth()`, `client.Leases()`, `client.KV(ctx, mount)` (detects on access), `client.Transit(mount)`, … | like TypeScript (`client.auth`, `client.leases`, `client.kv()`) | `client.auth()`, `client.leases()`, `client.kv()`, … |
| Provider options | `client.secrets({mount, path, valueField})` | `client.secrets_with(SecretsProviderOptions{..})` | `client.SecretsWith(SecretsProviderOptions{...})` | `client.secrets(mount, path=, value_field=)` | `client.secrets(SecretsOptions.builder()…build())` |
| Server lifecycle helpers | `@grow-codes/openbao/testing`: `init`, `unseal`, `seal`, `initStatus`, `waitForActive` | `grow_openbao::testing::{init, unseal, unseal_reset, seal, init_status, wait_for_active}` (feature `testing`) | package `testkit`: `Init`, `Unseal`, `Seal`, `InitStatus`, `WaitForActive` | `grow_openbao.testing.lifecycle`: `init`, `unseal`, `seal`, `init_status`, `wait_for_active` (+ `a…` async forms) | `codes.grow.packages.openbao.testing.OpenBaoTesting`: `init`, `initRecovery`, `unseal`, `resetUnseal`, `seal`, `initStatus`, `waitForActive` |
| Raw request escape hatch | `client.request(method, path, opts)` | — | — | `client.request(method, path, …)` | `client.request(method, path, body)` |
| `loadEnv` target | `process.env` | `std::env` | `os.Setenv` | `os.environ` | system properties (Java cannot change the environment) |

Rust exposes `Auth::login_with` and Go `Auth.LoginWith` as a building block for custom auth
methods; the other languages implement the `AuthMethod` interface instead.
