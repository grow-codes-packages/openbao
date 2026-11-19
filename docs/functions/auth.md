# Auth

Log in with an auth method, inspect and manage the client token and keep it renewed.

| Function | What it does | Errors |
| - | - | - |
| `TokenAuth(token)` | uses an existing token (verified with `lookup-self`) | `AUTHENTICATION` for a bad token |
| `AppRoleAuth(roleId, secretId, mount = "approle")` | `POST auth/<mount>/login` | `AUTHENTICATION` for a wrong or used-up secret id |
| `UserpassAuth(username, password, mount = "userpass")` | `POST auth/<mount>/login/<username>` | `AUTHENTICATION` |
| `JwtAuth(role, jwt, mount = "jwt")` | `POST auth/<mount>/login` | `AUTHENTICATION` (expired, malformed, wrong audience) |
| `KubernetesAuth(role, jwtPath = /var/run/secrets/kubernetes.io/serviceaccount/token, mount = "kubernetes")` | reads the service-account token and logs in | `AUTHENTICATION`; `VALIDATION` when the file is missing |
| `login(method)` | logs in, sets the token on the client and remembers the method for re-login | as the method |
| `lookupSelf()` | properties of the current token (`ttl`, `policies`, `renewable`, …) | `AUTHENTICATION` |
| `renewSelf(increment?)` | renews the current token, returns the granted TTL | `VALIDATION` for a non-renewable token |
| `revokeSelf()` | revokes the current token and clears it on the client | |
| `createToken(options)` | creates a child (or orphan) token: `policies`, `ttl`, `explicitMaxTtl`, `renewable`, `displayName`, `meta`, `numUses`, `noParent`, `noDefaultPolicy`, `period`, `role` | `PERMISSION_DENIED` |
| `startRenewer(options)` → `TokenRenewer` | renews the token at about 2/3 of its TTL, detects the max-TTL cap, optionally re-logs in with the remembered method, calls `onRenew` / `onError` / `onExpire` | |

Every login endpoint maps HTTP 400, 401 and 403 to `AUTHENTICATION`. A token that is missing,
invalid or revoked is `AUTHENTICATION` on every other call as well; a valid token without the
needed policy is `PERMISSION_DENIED`.

## Log in with AppRole and keep the token renewed

=== "TypeScript"

    ```ts
    import { AppRoleAuth, OpenBaoClient } from "@grow-codes/openbao";

    const client = new OpenBaoClient({ url: "https://openbao.example.internal" });
    const info = await client.auth.login(new AppRoleAuth(roleId, secretId));
    console.log(info.policies, info.leaseDurationMs);

    const renewer = await client.auth.startRenewer({
      onExpire: () => console.warn("token expired"),
    });
    const me = await client.auth.lookupSelf();
    // ... client.close() stops the renewer
    ```

=== "Rust"

    ```rust
    use grow_openbao::{AppRoleAuth, OpenBaoClient, OpenBaoConfig, TokenRenewerOptions};

    let client = OpenBaoClient::new(
        OpenBaoConfig::builder().url("https://openbao.example.internal").build()?,
    )?;
    let info = client.auth().login(AppRoleAuth::new(role_id, secret_id)).await?;
    println!("{:?} {:?}", info.policies, info.lease_duration);

    let renewer = client.auth().start_renewer(TokenRenewerOptions::default()).await?;
    let me = client.auth().lookup_self().await?;
    // client.close().await stops the renewer
    ```

=== "Go"

    ```go
    client, err := openbao.NewClient(openbao.Config{
        CommonConfig: openbao.CommonConfig{URL: "https://openbao.example.internal"},
    })
    if err != nil {
        return err
    }
    defer client.Close()

    info, err := client.Auth().Login(ctx, openbao.NewAppRoleAuth(roleID, secretID))
    if err != nil {
        return err
    }
    fmt.Println(info.Policies, info.LeaseDuration)

    renewer, err := client.Auth().StartRenewer(ctx, &openbao.TokenRenewerOptions{
        OnExpire: func() { log.Println("token expired") },
    })
    ```

=== "Python"

    ```python
    import grow_openbao as sdk

    with sdk.OpenBaoClient(sdk.OpenBaoConfig(url="https://openbao.example.internal")) as client:
        info = client.auth.login(sdk.AppRoleAuth(role_id, secret_id))
        print(info.policies, info.lease_duration_s)

        renewer = client.auth.start_renewer(on_expire=lambda: print("token expired"))
        me = client.auth.lookup_self()
    ```

=== "Java"

    ```java
    try (OpenBaoClient client =
        OpenBaoClient.builder().url("https://openbao.example.internal").build()) {
      AuthInfo info = client.auth().login(new AppRoleAuth(roleId, secretId));
      System.out.println(info.policies() + " " + info.leaseDuration());

      TokenRenewer renewer =
          client.auth().startRenewer(
              RenewalOptions.builder().onExpire(() -> System.err.println("expired")).build());
      TokenInfo me = client.auth().lookupSelf();
    }
    ```

## Create a child token

=== "TypeScript"

    ```ts
    const child = await client.auth.createToken({ policies: ["app"], ttlMs: 3_600_000 });
    ```

=== "Rust"

    ```rust
    let child = client
        .auth()
        .create_token(&TokenCreateOptions {
            policies: vec!["app".into()],
            ttl: Some(Duration::from_secs(3600)),
            ..Default::default()
        })
        .await?;
    ```

=== "Go"

    ```go
    child, err := client.Auth().CreateToken(ctx, &openbao.TokenCreateOptions{
        Policies: []string{"app"}, TTL: time.Hour,
    })
    ```

=== "Python"

    ```python
    child = client.auth.create_token(policies=["app"], ttl_s=3600)
    ```

=== "Java"

    ```java
    AuthInfo child =
        client.auth().createToken(
            CreateTokenOptions.builder().policies("app").ttl(Duration.ofHours(1)).build());
    ```

`child.clientToken` is a redacting `Secret`; call `reveal()` only where the value is needed.
