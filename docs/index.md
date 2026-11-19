# OpenBao SDK

[![Grow Codes](https://img.shields.io/badge/Grow%20Codes-grow.codes-2ea44f)](https://grow.codes)
[![CI](https://github.com/grow-codes-packages/openbao/actions/workflows/ci.yml/badge.svg)](https://github.com/grow-codes-packages/openbao/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](license.md)

One API for **OpenBao** in five languages: TypeScript, Rust, Go, Python and Java. Every package
has the same functions, options, defaults, error codes and behaviour, tested against a real
`openbao/openbao:2.7.2` in Docker.

| Language | Package | Coverage |
| - | - | - |
| TypeScript | [`@grow-codes/openbao`](https://www.npmjs.com/package/@grow-codes/openbao) | ![TypeScript coverage](https://img.shields.io/endpoint?url=https://grow-codes-packages.github.io/openbao/badges/coverage-typescript.json) |
| Rust | [`grow-openbao`](https://crates.io/crates/grow-openbao) | ![Rust coverage](https://img.shields.io/endpoint?url=https://grow-codes-packages.github.io/openbao/badges/coverage-rust.json) |
| Go | [`github.com/grow-codes-packages/openbao/go`](https://pkg.go.dev/github.com/grow-codes-packages/openbao/go) | ![Go coverage](https://img.shields.io/endpoint?url=https://grow-codes-packages.github.io/openbao/badges/coverage-go.json) |
| Python | [`grow-openbao`](https://pypi.org/project/grow-openbao/) | ![Python coverage](https://img.shields.io/endpoint?url=https://grow-codes-packages.github.io/openbao/badges/coverage-python.json) |
| Java | [`codes.grow.packages:openbao`](https://central.sonatype.com/artifact/codes.grow.packages/openbao) | ![Java coverage](https://img.shields.io/endpoint?url=https://grow-codes-packages.github.io/openbao/badges/coverage-java.json) |

## What you get

- **Client** with health, authenticated ping and server version ([Client](client.md)).
- **Configuration** from code or `GROW_OPENBAO_*` / vendor environment variables, immutable
  and validated ([Configuration](configuration.md)).
- **Retries** with full-jitter backoff and `Retry-After`, connect/request/total timeouts and
  cancellation in every language.
- **Typed errors** with one set of codes across languages ([Error handling](errors.md)).
- **Redaction everywhere**: credentials never appear in errors, logs, hooks or `toString`
  ([Redaction](redaction.md)).
- **Secrets**: typed getters, bulk reads, `loadEnv`, watch and a TTL cache ([Secrets](secrets.md)).
- **The OpenBao API** ([Functions](functions.md)): [auth](functions/auth.md) with token
  renewal, [KV v1/v2](functions/kv.md), [transit](functions/transit.md),
  [database credentials and leases](functions/database.md), [PKI](functions/pki.md),
  [system and admin](functions/system.md), [response wrapping](functions/wrapping.md) and
  [testing helpers](functions/testing.md).

Start with [Install](install.md) and the [Quickstart](quickstart.md).

!!! note "Independent project"
    This SDK is made by [Grow Codes](https://grow.codes). OpenBao is a trademark of
    its owner (OpenBao a Series of LF Projects, LLC); this project is not affiliated with or endorsed by it. See
    [License & disclaimer](license.md).
