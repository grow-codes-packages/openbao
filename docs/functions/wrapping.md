# Response wrapping

Hand a secret over through a single-use, short-lived wrapping token (`client.wrapping`).

| Function | What it does |
| - | - |
| `wrap(data, ttl)` → `WrapInfo` | stores `data` behind a wrapping token (`token` redacted, `accessor`, `ttl`, `creationTime`, `creationPath`) |
| `lookupWrapping(token)` | `creationPath`, `creationTime`, `creationTtl` without using the token; used or invalid → `VALIDATION` |
| `unwrap(token)` | returns the wrapped data (or the full wrapped API response, including `auth` for a wrapped login); a second unwrap → `VALIDATION`, never retried |

=== "TypeScript"

    ```ts
    const info = await client.wrapping.wrap({ apiKey: "k-123" }, 60_000);
    const meta = await client.wrapping.lookupWrapping(info.token);
    // send info.token.reveal() to the receiver, which calls:
    const { data } = await client.wrapping.unwrap(info.token);
    ```

=== "Rust"

    ```rust
    let info = client.wrapping().wrap(json!({"apiKey": "k-123"}), Duration::from_secs(60)).await?;
    let meta = client.wrapping().lookup_wrapping(info.token.expose_secret()).await?;
    let unwrapped = client.wrapping().unwrap(info.token.expose_secret()).await?;
    println!("{:?}", unwrapped.data);
    ```

=== "Go"

    ```go
    info, err := client.Wrapping().Wrap(ctx, map[string]any{"apiKey": "k-123"}, time.Minute)
    if err != nil {
        return err
    }
    meta, err := client.Wrapping().LookupWrapping(ctx, info.Token.Reveal())
    unwrapped, err := client.Wrapping().Unwrap(ctx, info.Token.Reveal())
    fmt.Println(unwrapped.Data)
    ```

=== "Python"

    ```python
    info = client.wrapping.wrap({"apiKey": "k-123"}, 60)
    meta = client.wrapping.lookup_wrapping(info.token)
    data = client.wrapping.unwrap(info.token).data
    ```

=== "Java"

    ```java
    WrapInfo info = client.wrapping().wrap(Map.of("apiKey", "k-123"), Duration.ofMinutes(1));
    WrappingLookup meta = client.wrapping().lookupWrapping(info.token());
    UnwrapResult unwrapped = client.wrapping().unwrap(info.token());
    ```
