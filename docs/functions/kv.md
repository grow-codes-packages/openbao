# KV (v1 and v2)

`client.kv(mount)` returns the KV engine of a mount with its version detected automatically
(`GET sys/internal/ui/mounts/<mount>/<path>`, cached per mount; works for restricted tokens that
have any capability on the path). Set `kvVersion` in the config (or `GROW_OPENBAO_KV_VERSION`) to
skip detection for tokens that cannot read it. `client.kvV1(mount)` and `client.kvV2(mount)` give a
fixed version. The default mount is `kvMount` (`secret`).

| Function | KV v2 | KV v1 |
| - | - | - |
| `read(path, {version?})` | `GET <m>/data/<p>`; `NOT_FOUND` when missing, deleted or destroyed | `GET <m>/<p>`; a version → `UNSUPPORTED` |
| `write(path, data, {cas?})` | new version; `cas` mismatch → `CONFLICT`, `cas: 0` = create only | full replace; `cas` → `UNSUPPORTED` |
| `patch(path, data, {cas?})` | JSON merge patch (`null` removes a key); `NOT_FOUND` when missing | `UNSUPPORTED` |
| `delete(path)` | soft-deletes the latest version | deletes the key |
| `deleteVersions(path, versions)` / `undelete` / `destroy` | per-version lifecycle | `UNSUPPORTED` |
| `list(path)` | sorted keys, folders end with `/`; empty list when missing | same |
| `readMetadata(path)` | `currentVersion`, `oldestVersion`, `maxVersions`, `casRequired`, `deleteVersionAfter`, `customMetadata`, `versions` | `UNSUPPORTED` |
| `writeMetadata(path, {maxVersions, casRequired, deleteVersionAfter, customMetadata})` | updates metadata | `UNSUPPORTED` |
| `deleteMetadata(path)` | removes every version and the metadata | `UNSUPPORTED` |

`UNSUPPORTED` errors on KV v1 are raised before any request is sent. Paths are percent-encoded per
segment, so names with spaces work.

## Write, read, patch and list

=== "TypeScript"

    ```ts
    const kv = client.kv("secret");
    const meta = await kv.write("app/db", { user: "app", password: "s3cret" }, { cas: 0 });
    await kv.patch("app/db", { password: "rotated" });
    const secret = await kv.read("app/db");
    console.log(secret.data.user, secret.metadata?.version);
    const old = await kv.read("app/db", { version: 1 });
    const keys = await kv.list("app"); // ["db"]
    await kv.writeMetadata("app/db", { maxVersions: 5, customMetadata: { owner: "team-a" } });
    ```

=== "Rust"

    ```rust
    use serde_json::json;

    let kv = client.kv_at("secret").await?; // client.kv() uses config.kv_mount
    kv.write("app/db", json!({"user": "app", "password": "s3cret"}), Some(0)).await?;
    kv.patch("app/db", json!({"password": "rotated"}), None).await?;
    let secret = kv.read("app/db", None).await?;
    println!("{} {:?}", secret.data["user"], secret.metadata.map(|m| m.version));
    let old = kv.read("app/db", Some(1)).await?;
    let keys = kv.list("app").await?;
    ```

=== "Go"

    ```go
    kv, err := client.KV(ctx, "secret")
    if err != nil {
        return err
    }
    _, err = kv.Write(ctx, "app/db", map[string]any{"user": "app", "password": "s3cret"},
        &openbao.KVWriteOptions{CAS: openbao.Ptr(0)})
    _, err = kv.Patch(ctx, "app/db", map[string]any{"password": "rotated"}, nil)
    secret, err := kv.Read(ctx, "app/db", nil)
    old, err := kv.Read(ctx, "app/db", &openbao.KVReadOptions{Version: 1})
    keys, err := kv.List(ctx, "app")
    ```

=== "Python"

    ```python
    kv = client.kv("secret")
    kv.write("app/db", {"user": "app", "password": "s3cret"}, cas=0)
    kv.patch("app/db", {"password": "rotated"})
    secret = kv.read("app/db")
    print(secret.data["user"], secret.metadata.version if secret.metadata else None)
    old = kv.read("app/db", version=1)
    keys = kv.list("app")
    kv.write_metadata("app/db", max_versions=5, custom_metadata={"owner": "team-a"})
    ```

=== "Java"

    ```java
    KvMount kv = client.kv("secret");
    kv.write("app/db", Map.of("user", "app", "password", "s3cret"), 0);
    kv.patch("app/db", Map.of("password", "rotated"));
    KvSecret secret = kv.read("app/db");
    System.out.println(secret.data().get("user") + " " + secret.metadata().map(m -> m.version()));
    KvSecret old = kv.read("app/db", 1);
    List<String> keys = kv.list("app");
    ```

## Versions and check-and-set

A stale `cas` value is a `CONFLICT` and changes nothing. With `casRequired` set on the metadata,
writes without `cas` are rejected (`VALIDATION`). `delete` soft-deletes the latest version
(`undelete` restores it); `destroy` removes version data for good; `deleteMetadata` removes the key.
