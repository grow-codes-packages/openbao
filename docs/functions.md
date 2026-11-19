# Functions

The OpenBao API of this SDK. Every function exists in all five languages with the same
behaviour; the module pages show each one with an example per language. Names follow each
language's convention (`createKey` in TypeScript and Java, `create_key` in Rust and Python,
`CreateKey` in Go with `ctx` first).

| Module | Accessor (TypeScript) | Functions | Page |
| - | - | - | - |
| Client | `client` | `health`, `ping`, `serverVersion`, `close` | [Client](client.md) |
| Auth | `client.auth` | `TokenAuth`, `AppRoleAuth`, `UserpassAuth`, `JwtAuth`, `KubernetesAuth`, `login`, `lookupSelf`, `renewSelf`, `revokeSelf`, `createToken`, `startRenewer` → `TokenRenewer` | [Auth](functions/auth.md) |
| KV v1 + v2 | `client.kv(mount?)`, `client.kvV1()`, `client.kvV2()` | `read`, `write`, `patch`, `delete`, `deleteVersions`, `undelete`, `destroy`, `list`, `readMetadata`, `writeMetadata`, `deleteMetadata` | [KV](functions/kv.md) |
| SecretsProvider | `client.secrets(options?)` | the shared [Secrets](secrets.md) interface over KV | [Secrets over KV](functions/secrets-provider.md) |
| Transit | `client.transit(mount?)` | `createKey`, `readKey`, `listKeys`, `rotateKey`, `updateKeyConfig`, `deleteKey`, `encrypt`, `decrypt`, `rewrap`, `encryptBatch`, `decryptBatch`, `generateDataKey`, `hmac`, `sign`, `verify`, `hash`, `randomBytes` | [Transit](functions/transit.md) |
| Database + leases | `client.database(mount?)`, `client.leases` | `configureConnection`, `readConnection`, `deleteConnection`, `createRole`, `readRole`, `deleteRole`, `getCredentials` → `Lease`; `LeaseManager`: `renew`, `revoke`, `revokePrefix`, `lookup`, `manage` (auto-renew, `onExpire`) | [Database](functions/database.md) |
| PKI | `client.pki(mount?)` | `issueCertificate`, `signCsr`, `revokeCertificate`, `readCaChain`, `readCertificate`, `listCertificates`, `tidy`, `tidyStatus` | [PKI](functions/pki.md) |
| System + admin | `client.sys` | `health`, `sealStatus`, `leader`, `version`, `writePolicy`, `readPolicy`, `listPolicies`, `deletePolicy`, `listMounts`, `enableSecretsEngine`, `disableSecretsEngine`, `listAuthMethods`, `enableAuthMethod`, `disableAuthMethod`, `createAppRole`, `listAppRoles`, `deleteAppRole`, `readRoleId`, `generateSecretId` | [System](functions/system.md) |
| Response wrapping | `client.wrapping` | `wrap`, `unwrap`, `lookupWrapping` | [Wrapping](functions/wrapping.md) |
| Testing | testing module | `init`, `unseal`, `seal`, `initStatus`, `waitForActive` | [Testing helpers](functions/testing.md) |

Every function is called against a real `openbao/openbao:2.7.2` in the Docker suite of each
language, except the parts listed in [Compatibility](compatibility.md).

## Service configuration

| Setting | Default | Environment variables (precedence order) |
| - | - | - |
| `url` | `http://127.0.0.1:8200` | `GROW_OPENBAO_URL`, `BAO_ADDR`, `VAULT_ADDR` |
| `token` | none | `GROW_OPENBAO_TOKEN`, `BAO_TOKEN`, `VAULT_TOKEN` |
| `namespace` (`X-Vault-Namespace`) | none (root) | `GROW_OPENBAO_NAMESPACE`, `BAO_NAMESPACE`, `VAULT_NAMESPACE` |
| `tls.caCertPath` | none | `GROW_OPENBAO_CA_CERT`, `BAO_CACERT`, `VAULT_CACERT` |
| `tls.clientCertPath` / `clientKeyPath` | none | `GROW_OPENBAO_CLIENT_CERT` / `_KEY`, `BAO_CLIENT_CERT` / `_KEY`, `VAULT_CLIENT_CERT` / `_KEY` |
| `tls.insecureSkipVerify` | `false` | `GROW_OPENBAO_INSECURE_SKIP_VERIFY`, `BAO_SKIP_VERIFY`, `VAULT_SKIP_VERIFY` |
| `kvMount` | `secret` | `GROW_OPENBAO_KV_MOUNT` |
| `kvVersion` | auto-detect per mount | `GROW_OPENBAO_KV_VERSION` (`1`, `2`; `0` = auto) |
| `secretsPath` (base path of `client.secrets()`) | `""` (mount root) | `GROW_OPENBAO_SECRETS_PATH` |
| `valueField` (data field of a `client.secrets()` value) | `value` | — |

The common settings (timeouts, retries, proxy, hooks, logger) are described in
[Configuration](configuration.md). Explicit values win over `GROW_OPENBAO_*`, which wins over the
vendor variables. Leave `token` unset when the client logs in with an auth method.
