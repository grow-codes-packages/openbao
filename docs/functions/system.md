# System and admin

`client.sys` covers the system backend: node state, policies, secrets engines, auth methods and
AppRole administration. The admin functions need a token with the matching `sys/` or `auth/`
capabilities (a policy denial is `PERMISSION_DENIED`).

| Function | What it does |
| - | - |
| `health()` | typed `sys/health` node state: `state` (`active`, `standby`, `perfstandby`, `sealed`, `uninitialized`), `initialized`, `sealed`, `standby`, `performanceStandby`, `version`, `clusterName`, `clusterId`, `serverTime`; no token needed. `client.health()` is the never-failing SPEC health check on the same endpoint. |
| `sealStatus()` | `type` (`shamir`, `static`, …), `initialized`, `sealed`, threshold, shares, progress, version |
| `leader()` | HA leader: `haEnabled`, `isSelf`, `leaderAddress`, `activeTime`, Raft indexes |
| `version()` | server version (same as `client.serverVersion()`) |
| `writePolicy(name, hcl)` / `readPolicy(name)` / `listPolicies()` / `deletePolicy(name)` | ACL policies; invalid HCL → `VALIDATION`; unknown → `NOT_FOUND` |
| `listMounts()` | map `"<path>/"` → `type`, `description`, `options` (KV `version`), `config`, … |
| `enableSecretsEngine(path, type, options?)` / `disableSecretsEngine(path)` | `description`, `options` (e.g. `{"version": "2"}`), `defaultLeaseTtl`, `maxLeaseTtl`; path in use → `VALIDATION` |
| `listAuthMethods()` / `enableAuthMethod(path, type, options?)` / `disableAuthMethod(path)` | auth methods |
| `createAppRole(name, options)` / `listAppRoles(mount)` / `deleteAppRole(name, mount)` | AppRole roles: `mount` (default `approle`), `tokenPolicies`, `tokenTtl`, `tokenMaxTtl`, `secretIdTtl`, `secretIdNumUses`, `bindSecretId`, `tokenType` |
| `readRoleId(name, mount?)` | role id; unknown role → `NOT_FOUND` |
| `generateSecretId(name, options?)` | new secret id (redacted) with `metadata`, `ttl`, `numUses`, `cidrList` |

## Provision an application identity

=== "TypeScript"

    ```ts
    await client.sys.writePolicy("app", 'path "secret/data/app/*" { capabilities = ["read"] }');
    await client.sys.enableAuthMethod("approle", "approle");
    await client.sys.createAppRole("web", { tokenPolicies: ["app"], tokenTtlMs: 3_600_000 });
    const roleId = await client.sys.readRoleId("web");
    const { secretId } = await client.sys.generateSecretId("web");
    // hand roleId + secretId to the application (AppRoleAuth)
    ```

=== "Rust"

    ```rust
    use grow_openbao::{AppRoleOptions, SecretIdOptions};

    let sys = client.sys();
    sys.write_policy("app", r#"path "secret/data/app/*" { capabilities = ["read"] }"#).await?;
    sys.enable_auth_method("approle", "approle", None).await?;
    sys.create_app_role("web", &AppRoleOptions {
        token_policies: vec!["app".into()],
        token_ttl: Some(Duration::from_secs(3600)),
        ..Default::default()
    }).await?;
    let role_id = sys.read_role_id("web", None).await?;
    let secret = sys.generate_secret_id("web", &SecretIdOptions::default()).await?;
    ```

=== "Go"

    ```go
    sys := client.Sys()
    if err := sys.WritePolicy(ctx, "app", `path "secret/data/app/*" { capabilities = ["read"] }`); err != nil {
        return err
    }
    err := sys.EnableAuthMethod(ctx, "approle", "approle", nil)
    err = sys.CreateAppRole(ctx, "web", &openbao.AppRoleOptions{TokenPolicies: []string{"app"}, TokenTTL: time.Hour})
    roleID, err := sys.ReadRoleID(ctx, "web", "")
    secret, err := sys.GenerateSecretID(ctx, "web", nil)
    ```

=== "Python"

    ```python
    client.sys.write_policy("app", 'path "secret/data/app/*" { capabilities = ["read"] }')
    client.sys.enable_auth_method("approle", "approle")
    client.sys.create_app_role("web", token_policies=["app"], token_ttl_s=3600)
    role_id = client.sys.read_role_id("web")
    secret = client.sys.generate_secret_id("web")
    ```

=== "Java"

    ```java
    Sys sys = client.sys();
    sys.writePolicy("app", "path \"secret/data/app/*\" { capabilities = [\"read\"] }");
    sys.enableAuthMethod("approle", "approle");
    sys.createAppRole(
        "web",
        AppRoleOptions.builder().tokenPolicies("app").tokenTtl(Duration.ofHours(1)).build());
    String roleId = sys.readRoleId("web");
    SecretIdInfo secret = sys.generateSecretId("web");
    ```

## Check the node

=== "TypeScript"

    ```ts
    const h = await client.sys.health(); // { state: "active", version: "2.7.2", ... }
    const seal = await client.sys.sealStatus();
    ```

=== "Rust"

    ```rust
    let h = client.sys().health().await?; // h.state == "active"
    let seal = client.sys().seal_status().await?;
    ```

=== "Go"

    ```go
    h, err := client.Sys().Health(ctx) // h.State == "active"
    seal, err := client.Sys().SealStatus(ctx)
    ```

=== "Python"

    ```python
    h = client.sys.health()  # h.state == "active"
    seal = client.sys.seal_status()
    ```

=== "Java"

    ```java
    HealthResponse h = client.sys().health(); // h.state() == "active"
    SealStatus seal = client.sys().sealStatus();
    ```
