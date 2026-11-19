# Secrets over KV

`client.secrets()` implements the shared Grow Codes [Secrets](../secrets.md) interface
(`get`, `getString`, `getJson`, `require`, `exists`, `getMany`, `getAll`, `list`, `set`,
`delete`, `metadata`, `loadEnv`, `watch`, `SecretCache`) on top of a KV mount. Code written
against it works unchanged with every other Grow Codes secrets package.

## Mapping

| Topic | Behaviour |
| - | - |
| Location | secret `name` → KV path `<secretsPath>/<name>` (or `<options.path>/<name>`) on `kvMount` (default `secret`, KV version auto-detected) |
| Value | stored as `{"value": "<text>"}` (field `valueField`); bytes that are not valid UTF-8 as base64 with `"encoding": "base64"`; objects JSON-encoded into `value` |
| Existing multi-field secrets | a path without the value field is returned as the JSON encoding of the whole map (`getJson` decodes it) |
| Versions | `SecretValue.version` and `set(...)` return the KV v2 version as a string; `""` on KV v1; `get(name, {version})` reads that version (KV v1 → `VALIDATION`) |
| `set` options | `cas` (check-and-set, `CONFLICT` on mismatch), `tags` and `description` (custom metadata); KV v1 → `UNSUPPORTED` |
| `delete` options | default soft-deletes the latest version; `versions` deletes those versions; `permanent` removes every version and the metadata; `NOT_FOUND` when missing |
| `list(prefix)` | names directly under the folder, sorted, sub-folders skipped; on KV v2 with metadata (read per key, 8 at a time) |
| `metadata(name)` | `version` (current), `createdAt`, `updatedAt`, `tags` (custom metadata), `versions` (count), `extra`: `maxVersions`, `casRequired`, `deleteVersionAfter` (e.g. `"0s"`), `oldestVersion` |
| Deleted versions | a key whose current version is deleted or destroyed counts as missing everywhere |

## Example

=== "TypeScript"

    ```ts
    const secrets = client.secrets({ path: "apps/web" }); // or GROW_OPENBAO_SECRETS_PATH
    const version = await secrets.set("db-password", "s3cret", { tags: { owner: "team-a" } });
    const password = await secrets.require("db-password");
    connect(password.reveal());
    await secrets.set("db-password", "rotated", { cas: Number(version) });
    const previous = await secrets.get("db-password", { version });
    console.log(await secrets.list()); // [{ name: "db-password", version: "2", tags: {...}, ... }]
    await secrets.delete("db-password", { permanent: true });
    ```

=== "Rust"

    ```rust
    use grow_openbao::secrets::{GetOptions, SecretsProvider};
    use grow_openbao::SecretsProviderOptions;

    let secrets = client.secrets_with(SecretsProviderOptions {
        path: Some("apps/web".into()),
        ..Default::default()
    });
    let version = secrets.set("db-password", "s3cret".into(), None).await?;
    let password = secrets.require("db-password", None).await?;
    connect(password.reveal()?);
    let previous = secrets
        .get("db-password", Some(&GetOptions { version: Some(version), ..Default::default() }))
        .await?;
    ```

=== "Go"

    ```go
    secrets := client.SecretsWith(openbao.SecretsProviderOptions{Path: "apps/web"})
    version, err := secrets.Set(ctx, "db-password", "s3cret", &openbao.SetOptions{Tags: map[string]string{"owner": "team-a"}})
    if err != nil {
        return err
    }
    password, err := secrets.Require(ctx, "db-password", nil)
    text, _ := password.Reveal()
    connect(text)
    previous, err := secrets.Get(ctx, "db-password", &openbao.GetOptions{Version: version})
    err = secrets.Delete(ctx, "db-password", &openbao.DeleteOptions{Permanent: true})
    ```

=== "Python"

    ```python
    secrets = client.secrets(path="apps/web")
    version = secrets.set("db-password", "s3cret", tags={"owner": "team-a"})
    connect(secrets.require("db-password").reveal())
    secrets.set("db-password", "rotated", cas=int(version))
    previous = secrets.get("db-password", version=version)
    secrets.delete("db-password", permanent=True)
    ```

=== "Java"

    ```java
    OpenBaoSecretsProvider secrets =
        client.secrets(SecretsOptions.builder().path("apps/web").build());
    String version = secrets.set("db-password", "s3cret");
    connect(secrets.require("db-password").reveal());
    Optional<SecretValue> previous =
        secrets.get("db-password", GetOptions.builder().version(version).build());
    secrets.delete("db-password", DeleteOptions.builder().permanent(true).build());
    ```
