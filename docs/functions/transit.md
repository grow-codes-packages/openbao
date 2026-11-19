# Transit

Encryption as a service on a transit mount (`client.transit(mount = "transit")`). Plaintext,
input and context values are bytes (text is UTF-8 encoded; the SDK base64-encodes them on the
wire). Ciphertexts, signatures and HMACs are strings of the form `vault:v<keyVersion>:<base64>`.

| Function | What it does |
| - | - |
| `createKey(name, type = "aes256-gcm96", options?)` | creates a key (idempotent); options `exportable`, `derived`, `autoRotatePeriod`, `allowPlaintextBackup`, `keySize` |
| `readKey(name)` / `listKeys()` | key properties (`latestVersion`, `minDecryptionVersion`, `keys`, `supportsSigning`, …) / key names |
| `rotateKey(name)` | adds a key version |
| `updateKeyConfig(name, config)` | `deletionAllowed`, `minDecryptionVersion`, `minEncryptionVersion`, `exportable`, `autoRotatePeriod` |
| `deleteKey(name)` | needs `deletionAllowed: true` first (`VALIDATION` otherwise) |
| `encrypt(name, plaintext, {context, keyVersion})` → `{ciphertext, keyVersion}` | |
| `decrypt(name, ciphertext, {context})` → bytes | `VALIDATION` for an invalid or too old ciphertext |
| `rewrap(name, ciphertext)` | re-encrypts with the latest key version without revealing the plaintext |
| `encryptBatch(name, items)` / `decryptBatch(name, items)` | one request; results in order with per-item `error` (a failed item does not throw) |
| `generateDataKey(name, {plaintext = true, bits = 256})` | data key for envelope encryption (`ciphertext`, `plaintext` when requested) |
| `hmac(name, input, {algorithm})` | `vault:vN:` HMAC |
| `sign(name, input, {hashAlgorithm, signatureAlgorithm, prehashed})` | signature with an asymmetric key (`VALIDATION` for a symmetric key) |
| `verify(name, input, signature or hmac)` → boolean | `false` for an invalid signature (not an error) |
| `hash(input, {algorithm = "sha2-256", format = "hex"})` | digest |
| `randomBytes(n, {format = "base64"})` | random bytes from the server |

How `verify` takes an HMAC instead of a signature: TypeScript `{ hmac }` target, Python `hmac=`,
Java `verifyHmac(...)`, Rust/Go a `hmac` field in the options.

## Encrypt and decrypt

=== "TypeScript"

    ```ts
    const transit = client.transit();
    await transit.createKey("orders", "aes256-gcm96");
    const { ciphertext } = await transit.encrypt("orders", "card 4111");
    const plain = new TextDecoder().decode(await transit.decrypt("orders", ciphertext));
    await transit.rotateKey("orders");
    const rewrapped = await transit.rewrap("orders", ciphertext);
    ```

=== "Rust"

    ```rust
    let transit = client.transit();
    transit.create_key("orders", "aes256-gcm96", None).await?;
    let ct = transit.encrypt("orders", b"card 4111", None).await?;
    let plain = transit.decrypt("orders", &ct.ciphertext, None).await?;
    transit.rotate_key("orders").await?;
    let rewrapped = transit.rewrap("orders", &ct.ciphertext, None).await?;
    ```

=== "Go"

    ```go
    transit := client.Transit("transit")
    if _, err := transit.CreateKey(ctx, "orders", "aes256-gcm96", nil); err != nil {
        return err
    }
    ct, err := transit.Encrypt(ctx, "orders", []byte("card 4111"), nil)
    plain, err := transit.Decrypt(ctx, "orders", ct.Ciphertext, nil)
    _, err = transit.RotateKey(ctx, "orders")
    rewrapped, err := transit.Rewrap(ctx, "orders", ct.Ciphertext, nil)
    ```

=== "Python"

    ```python
    transit = client.transit()
    transit.create_key("orders", "aes256-gcm96")
    ct = transit.encrypt("orders", "card 4111")
    plain = transit.decrypt("orders", ct.ciphertext).decode()
    transit.rotate_key("orders")
    rewrapped = transit.rewrap("orders", ct.ciphertext)
    ```

=== "Java"

    ```java
    Transit transit = client.transit();
    transit.createKey("orders", "aes256-gcm96");
    Ciphertext ct = transit.encrypt("orders", "card 4111");
    byte[] plain = transit.decrypt("orders", ct.ciphertext());
    transit.rotateKey("orders");
    Ciphertext rewrapped = transit.rewrap("orders", ct.ciphertext());
    ```

## Sign and verify

=== "TypeScript"

    ```ts
    await transit.createKey("signer", "ed25519");
    const { signature } = await transit.sign("signer", "message");
    const ok = await transit.verify("signer", "message", { signature }); // true
    ```

=== "Rust"

    ```rust
    transit.create_key("signer", "ed25519", None).await?;
    let sig = transit.sign("signer", b"message", None).await?;
    let ok = transit.verify("signer", b"message", &sig.signature, None).await?;
    ```

=== "Go"

    ```go
    _, err = transit.CreateKey(ctx, "signer", "ed25519", nil)
    sig, err := transit.Sign(ctx, "signer", []byte("message"), nil)
    ok, err := transit.Verify(ctx, "signer", []byte("message"), sig.Signature, nil)
    ```

=== "Python"

    ```python
    transit.create_key("signer", "ed25519")
    sig = transit.sign("signer", "message")
    ok = transit.verify("signer", "message", signature=sig.signature)
    ```

=== "Java"

    ```java
    transit.createKey("signer", "ed25519");
    byte[] msg = "message".getBytes(StandardCharsets.UTF_8);
    Signature sig = transit.sign("signer", msg);
    boolean ok = transit.verify("signer", msg, sig.signature());
    ```
