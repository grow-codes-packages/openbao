# Quickstart

Connect to OpenBao, check that it is healthy, make an authenticated call and close the client.
The client reads `GROW_OPENBAO_URL` and `GROW_OPENBAO_TOKEN` (and the vendor variables
listed in [Configuration](configuration.md)), or takes the values in code.

```sh
export GROW_OPENBAO_URL=http://127.0.0.1:8200
export GROW_OPENBAO_TOKEN=...   # never commit real tokens
```

=== "TypeScript"

    ```ts
    import { OpenBaoClient } from "@grow-codes/openbao";

    const client = OpenBaoClient.fromEnv();
    try {
      const health = await client.health();
      console.log("healthy:", health.healthy, health.status);
      console.log("ping:", await client.ping(), "ms");
      console.log("server version:", await client.serverVersion());
    } finally {
      await client.close();
    }
    ```

=== "Rust"

    ```rust
    use grow_openbao::OpenBaoClient;

    #[tokio::main]
    async fn main() -> grow_openbao::Result<()> {
        let client = OpenBaoClient::from_env()?;
        let health = client.health().await?;
        println!("healthy: {} {}", health.healthy, health.status);
        println!("ping: {:?}", client.ping().await?);
        println!("server version: {}", client.server_version().await?);
        client.close().await;
        Ok(())
    }
    ```

=== "Go"

    ```go
    package main

    import (
        "context"
        "fmt"
        "log"

        openbao "github.com/grow-codes-packages/openbao/go"
    )

    func main() {
        ctx := context.Background()
        client, err := openbao.NewClientFromEnv()
        if err != nil {
            log.Fatal(err)
        }
        defer client.Close()

        health, err := client.Health(ctx)
        if err != nil {
            log.Fatal(err)
        }
        fmt.Println("healthy:", health.Healthy, health.Status)

        latency, err := client.Ping(ctx)
        if err != nil {
            log.Fatal(err)
        }
        fmt.Println("ping:", latency)

        version, err := client.ServerVersion(ctx)
        if err != nil {
            log.Fatal(err)
        }
        fmt.Println("server version:", version)
    }
    ```

=== "Python"

    ```python
    from grow_openbao import OpenBaoClient

    with OpenBaoClient.from_env() as client:
        health = client.health()
        print("healthy:", health.healthy, health.status)
        print("ping:", client.ping(), "ms")
        print("server version:", client.server_version())
    ```

    Async code uses `AsyncOpenBaoClient` with the same methods:

    ```python
    import asyncio
    from grow_openbao import AsyncOpenBaoClient

    async def main() -> None:
        async with AsyncOpenBaoClient.from_env() as client:
            print(await client.health())

    asyncio.run(main())
    ```

=== "Java"

    ```java
    import codes.grow.packages.openbao.OpenBaoClient;
    import codes.grow.packages.openbao.core.HealthStatus;

    public final class Quickstart {
      public static void main(String[] args) {
        try (OpenBaoClient client = OpenBaoClient.fromEnv()) {
          HealthStatus health = client.health();
          System.out.println("healthy: " + health.healthy() + " " + health.status());
          System.out.println("ping: " + client.ping().toMillis() + " ms");
          System.out.println("server version: " + client.serverVersion());
        }
      }
    }
    ```

## Store and read a secret

The `SecretsProvider` keeps one value per KV path (mount `secret`, KV v1/v2 detected
automatically); `client.kv()` gives the raw KV engine.

=== "TypeScript"

    ```ts
    const secrets = client.secrets();
    await secrets.set("app/db-password", "s3cret");
    const value = await secrets.require("app/db-password");
    console.log(String(value), value.reveal().length); // SecretValue([REDACTED]) 6
    ```

=== "Rust"

    ```rust
    use grow_openbao::secrets::SecretsProvider;

    let secrets = client.secrets();
    secrets.set("app/db-password", "s3cret".into(), None).await?;
    let value = secrets.require("app/db-password", None).await?;
    println!("{value}"); // SecretValue([REDACTED])
    ```

=== "Go"

    ```go
    secrets := client.Secrets()
    if _, err := secrets.Set(ctx, "app/db-password", "s3cret", nil); err != nil {
        return err
    }
    value, err := secrets.Require(ctx, "app/db-password", nil)
    fmt.Println(value) // SecretValue([REDACTED])
    ```

=== "Python"

    ```python
    secrets = client.secrets()
    secrets.set("app/db-password", "s3cret")
    value = secrets.require("app/db-password")
    print(value, len(value.reveal()))  # SecretValue([REDACTED]) 6
    ```

=== "Java"

    ```java
    OpenBaoSecretsProvider secrets = client.secrets();
    secrets.set("app/db-password", "s3cret");
    SecretValue value = secrets.require("app/db-password");
    System.out.println(value); // SecretValue([REDACTED])
    ```

## Next steps

- [Configuration](configuration.md): timeouts, retries, TLS, proxy, environment variables.
- [Functions](functions.md): the OpenBao API of this SDK (auth, KV, transit, database
  credentials, PKI, system, wrapping).
- [Error handling](errors.md): error codes and retries.
