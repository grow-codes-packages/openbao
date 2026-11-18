# grow-openbao (Python)

Python SDK for [OpenBao](https://grow-codes-packages.github.io/openbao/) by Grow Codes.
Unofficial and community maintained; "OpenBao" is a trademark of OpenBao a Series of LF Projects, LLC.

```bash
pip install grow-openbao
```

```python
from grow_openbao import OpenBaoClient, OpenBaoConfig

# Reads GROW_OPENBAO_URL, GROW_OPENBAO_TOKEN, ... from the environment.
with OpenBaoClient.from_env() as client:
    print(client.health())
    print(client.server_version())
```

The async client has the same methods:

```python
import asyncio
from grow_openbao import AsyncOpenBaoClient

async def main() -> None:
    async with AsyncOpenBaoClient.from_env() as client:
        print(await client.health())

asyncio.run(main())
```

Service modules hang off the client (the async client mirrors every one of them):

```python
from grow_openbao import AppRoleAuth, OpenBaoClient

with OpenBaoClient.from_env() as client:
    client.auth.login(AppRoleAuth(role_id, secret_id), auto_renew=True)   # TokenRenewer
    client.kv().write("app/db", {"password": "s3cret"})                    # KV v1/v2 auto-detected
    print(client.kv().read("app/db").metadata)
    ct = client.transit().encrypt("my-key", "hello")                       # transit
    lease = client.database().get_credentials("readonly")                  # dynamic credentials
    client.leases.manage(lease, on_expire=lambda: print("expired"))       # LeaseManager
    cert = client.pki().issue_certificate("web", "app.example.com")        # PKI
    token = client.wrapping.wrap({"one-time": "value"}, ttl_s=60).token    # response wrapping
    client.sys.write_policy("app", 'path "secret/data/app/*" { capabilities = ["read"] }')
    print(client.secrets(path="app").get_string("db"))                     # SecretsProvider
```

| Module | Accessor | Functions |
| - | - | - |
| Auth | `client.auth` | `login(TokenAuth / AppRoleAuth / KubernetesAuth / JwtAuth / UserpassAuth)`, `lookup_self`, `renew_self`, `revoke_self`, `create_token`, `start_renewer` (`TokenRenewer`) |
| KV | `client.kv(mount)`, `kv_v1`, `kv_v2` | `read`, `write`, `patch`, `delete`, `delete_versions`, `undelete`, `destroy`, `list`, `read_metadata`, `write_metadata`, `delete_metadata` |
| Transit | `client.transit(mount)` | `create_key`, `read_key`, `list_keys`, `rotate_key`, `update_key_config`, `delete_key`, `encrypt`, `decrypt`, `rewrap`, `encrypt_batch`, `decrypt_batch`, `generate_data_key`, `hmac`, `sign`, `verify`, `hash`, `random_bytes` |
| Database | `client.database(mount)` | `get_credentials` → `Lease`, `configure_connection`, `read_connection`, `delete_connection`, `create_role`, `read_role`, `delete_role` |
| Leases | `client.leases` | `renew`, `revoke`, `revoke_prefix`, `lookup`, `manage` (auto-renew + `on_expire`), `stop_all` |
| PKI | `client.pki(mount)` | `issue_certificate`, `sign_csr`, `revoke_certificate`, `read_ca_chain`, `read_certificate`, `list_certificates`, `tidy`, `tidy_status` |
| System | `client.sys` | `health`, `seal_status`, `leader`, `version`, policies, secrets engines, auth methods, AppRole admin (`create_app_role`, `read_role_id`, `generate_secret_id` …) |
| Wrapping | `client.wrapping` | `wrap`, `unwrap`, `lookup_wrapping` |
| Secrets | `client.secrets(mount, path=…)` | the shared `SecretsProvider` (`get`, `set`, `list`, `delete`, `metadata`, `load_env`, `watch` …) |
| Testing | `grow_openbao.testing.lifecycle` | `init`, `unseal`, `seal`, `init_status`, `wait_until_active` (+ `a…` async forms) |

Durations are float seconds (`…_s` parameters, `timedelta` accepted); timestamps are aware UTC
`datetime`s; tokens, keys and passwords are `Secret` values.

- Python 3.10 or newer, typed (`py.typed`), `httpx` based, environment proxies ignored unless
  configured.
- Retries with full-jitter backoff and `Retry-After`, connect/request/total timeouts,
  cancellation, hooks and a silent-by-default `logging` logger named `grow_openbao`.
- Credentials are wrapped in `Secret` and never appear in `repr()`, logs or error messages.
- `grow_openbao.testing` ships in-memory fakes and the conformance runner.

Documentation: https://grow-codes-packages.github.io/openbao/ ·
Source: https://github.com/grow-codes-packages/openbao · Licence: Apache-2.0
