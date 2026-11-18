package codes.grow.packages.openbao;

import codes.grow.packages.openbao.core.HttpTransport;
import codes.grow.packages.openbao.core.ValidationException;
import com.fasterxml.jackson.databind.JsonNode;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.OptionalInt;
import java.util.concurrent.CompletableFuture;

/**
 * Transit engine on one mount: {@code client.transit()} (mount {@code transit}). Plaintexts are
 * bytes (text is UTF-8 encoded); ciphertexts, signatures and HMACs are {@code vault:v<n>:...}
 * strings.
 *
 * <pre>{@code
 * Transit transit = client.transit();
 * Ciphertext ct = transit.encrypt("app-key", "hello");
 * byte[] plain = transit.decrypt("app-key", ct.ciphertext());
 * }</pre>
 */
public final class Transit {
  private final ClientContext ctx;
  private final String mount;

  Transit(ClientContext ctx, String mount) {
    this.ctx = ctx;
    this.mount = Wire.trimSlashes(mount);
  }

  /**
   * Returns the mount.
   *
   * @return the mount path
   */
  public String mount() {
    return mount;
  }

  private String p(String... parts) {
    String[] all = new String[parts.length + 1];
    all[0] = mount;
    System.arraycopy(parts, 0, all, 1, parts.length);
    return Wire.encodePath(all);
  }

  private static String name(String name, String op) {
    return Wire.requireText(name, "key name", "transit." + op);
  }

  private CompletableFuture<JsonNode> post(
      String path, String op, Map<String, Object> body, boolean idempotent) {
    return ctx.http.call("POST", path, "transit." + op).json(body).idempotent(idempotent).data();
  }

  private static <T> T await(CompletableFuture<T> f, String op) {
    return HttpTransport.await(f, "transit." + op);
  }

  // ---- keys ----

  /**
   * Creates an {@code aes256-gcm96} key (idempotent: an existing key is returned unchanged).
   *
   * @param name key name
   * @return the key
   */
  public TransitKey createKey(String name) {
    return createKey(name, CreateKeyOptions.builder().build());
  }

  /**
   * Creates a key of a type.
   *
   * @param name key name
   * @param type key type, e.g. {@code ed25519}
   * @return the key
   */
  public TransitKey createKey(String name, String type) {
    return createKey(name, CreateKeyOptions.ofType(type));
  }

  /**
   * Creates a key with options.
   *
   * @param name key name
   * @param options key options
   * @return the key
   */
  public TransitKey createKey(String name, CreateKeyOptions options) {
    return await(createKeyAsync(name, options), "createKey");
  }

  /**
   * Asynchronous {@link #createKey(String, CreateKeyOptions)}.
   *
   * @param name key name
   * @param o key options
   * @return a future with the key
   */
  public CompletableFuture<TransitKey> createKeyAsync(String name, CreateKeyOptions o) {
    String op = "transit.createKey " + name;
    return Wire.async(
        () ->
            ctx.http
                .call("POST", p("keys", name(name, "createKey")), op)
                .json(
                    Wire.body()
                        .put("type", o.type)
                        .put("exportable", o.exportable)
                        .put("derived", o.derived)
                        .put("auto_rotate_period", Wire.optDuration(o.autoRotatePeriod))
                        .put("allow_plaintext_backup", o.allowPlaintextBackup)
                        .put("key_size", o.keySize)
                        .build())
                .envelope()
                .thenCompose(
                    env -> {
                      JsonNode d = env == null ? null : env.get("data");
                      return d == null || d.isNull()
                          ? readKeyAsync(name)
                          : CompletableFuture.completedFuture(TransitKey.from(d));
                    }));
  }

  /**
   * Reads a key; {@code NotFoundException} when missing.
   *
   * @param name key name
   * @return the key
   */
  public TransitKey readKey(String name) {
    return await(readKeyAsync(name), "readKey");
  }

  /**
   * Asynchronous {@link #readKey(String)}.
   *
   * @param name key name
   * @return a future with the key
   */
  public CompletableFuture<TransitKey> readKeyAsync(String name) {
    return Wire.async(
        () ->
            ctx.http
                .call("GET", p("keys", name(name, "readKey")), "transit.readKey " + name)
                .data()
                .thenApply(TransitKey::from));
  }

  /**
   * Key names (sorted); empty when there is none.
   *
   * @return the names
   */
  public List<String> listKeys() {
    return listKeys(null, null);
  }

  /**
   * One page of key names.
   *
   * @param after start after this name, may be null
   * @param limit maximum names, may be null
   * @return the names
   */
  public List<String> listKeys(String after, Integer limit) {
    return await(listKeysAsync(after, limit), "listKeys");
  }

  /**
   * Asynchronous {@link #listKeys(String, Integer)}.
   *
   * @param after start after this name, may be null
   * @param limit maximum names, may be null
   * @return a future with the names
   */
  public CompletableFuture<List<String>> listKeysAsync(String after, Integer limit) {
    return Wire.orElseOnNotFound(
        ctx.http
            .call("GET", p("keys") + "/", "transit.listKeys")
            .list()
            .query("after", after)
            .query("limit", limit)
            .data()
            .thenApply(d -> Wire.strings(d.get("keys"))),
        List.of());
  }

  /**
   * Adds a new key version.
   *
   * @param name key name
   * @return the updated key
   */
  public TransitKey rotateKey(String name) {
    return await(rotateKeyAsync(name), "rotateKey");
  }

  /**
   * Asynchronous {@link #rotateKey(String)}.
   *
   * @param name key name
   * @return a future with the updated key
   */
  public CompletableFuture<TransitKey> rotateKeyAsync(String name) {
    return Wire.async(
        () ->
            post(p("keys", name(name, "rotateKey"), "rotate"), "rotateKey " + name, Map.of(), false)
                .thenApply(TransitKey::from));
  }

  /**
   * Updates key settings.
   *
   * @param name key name
   * @param config settings
   * @return the updated key
   */
  public TransitKey updateKeyConfig(String name, KeyConfig config) {
    return await(updateKeyConfigAsync(name, config), "updateKeyConfig");
  }

  /**
   * Asynchronous {@link #updateKeyConfig(String, KeyConfig)}.
   *
   * @param name key name
   * @param c settings
   * @return a future with the updated key
   */
  public CompletableFuture<TransitKey> updateKeyConfigAsync(String name, KeyConfig c) {
    return Wire.async(
        () ->
            post(
                    p("keys", name(name, "updateKeyConfig"), "config"),
                    "updateKeyConfig " + name,
                    Wire.body()
                        .put("deletion_allowed", c.deletionAllowed)
                        .put("min_decryption_version", c.minDecryptionVersion)
                        .put("min_encryption_version", c.minEncryptionVersion)
                        .put("exportable", c.exportable)
                        .put("allow_plaintext_backup", c.allowPlaintextBackup)
                        .put("auto_rotate_period", Wire.optDuration(c.autoRotatePeriod))
                        .build(),
                    true)
                .thenApply(TransitKey::from));
  }

  /**
   * Deletes a key (needs {@code deletionAllowed}, else {@code ValidationException}).
   *
   * @param name key name
   */
  public void deleteKey(String name) {
    await(deleteKeyAsync(name), "deleteKey");
  }

  /**
   * Asynchronous {@link #deleteKey(String)}.
   *
   * @param name key name
   * @return a future completed when done
   */
  public CompletableFuture<Void> deleteKeyAsync(String name) {
    return Wire.async(
        () ->
            ctx.http
                .call("DELETE", p("keys", name(name, "deleteKey")), "transit.deleteKey " + name)
                .run());
  }

  // ---- encryption ----

  private static Ciphertext ciphertext(JsonNode d, String op) {
    if (!d.path("ciphertext").isTextual()) {
      throw Wire.unexpected(op, "no ciphertext");
    }
    return new Ciphertext(d.get("ciphertext").asText(), Wire.num(d, "key_version"));
  }

  /**
   * Encrypts UTF-8 text.
   *
   * @param name key name
   * @param plaintext text
   * @return the ciphertext
   */
  public Ciphertext encrypt(String name, String plaintext) {
    return encrypt(name, plaintext.getBytes(StandardCharsets.UTF_8), TransitOptions.none());
  }

  /**
   * Encrypts bytes.
   *
   * @param name key name
   * @param plaintext bytes
   * @param options context, key version, associated data
   * @return the ciphertext
   */
  public Ciphertext encrypt(String name, byte[] plaintext, TransitOptions options) {
    return await(encryptAsync(name, plaintext, options), "encrypt");
  }

  /**
   * Asynchronous {@link #encrypt(String, byte[], TransitOptions)}.
   *
   * @param name key name
   * @param plaintext bytes
   * @param o options
   * @return a future with the ciphertext
   */
  public CompletableFuture<Ciphertext> encryptAsync(
      String name, byte[] plaintext, TransitOptions o) {
    String op = "encrypt " + name;
    return Wire.async(
        () ->
            post(
                    p("encrypt", name(name, "encrypt")),
                    op,
                    Wire.body()
                        .put("plaintext", Wire.b64(plaintext))
                        .put("context", Wire.optB64(o.context))
                        .put("key_version", o.keyVersion)
                        .put("associated_data", Wire.optB64(o.associatedData))
                        .build(),
                    false)
                .thenApply(d -> ciphertext(d, "transit." + op)));
  }

  /**
   * Decrypts a ciphertext.
   *
   * @param name key name
   * @param ciphertext {@code vault:v<n>:} ciphertext
   * @return the plaintext bytes
   */
  public byte[] decrypt(String name, String ciphertext) {
    return decrypt(name, ciphertext, TransitOptions.none());
  }

  /**
   * Decrypts a ciphertext with options.
   *
   * @param name key name
   * @param ciphertext ciphertext
   * @param options context, associated data
   * @return the plaintext bytes
   */
  public byte[] decrypt(String name, String ciphertext, TransitOptions options) {
    return await(decryptAsync(name, ciphertext, options), "decrypt");
  }

  /**
   * Asynchronous {@link #decrypt(String, String, TransitOptions)}.
   *
   * @param name key name
   * @param ciphertext ciphertext
   * @param o options
   * @return a future with the plaintext bytes
   */
  public CompletableFuture<byte[]> decryptAsync(String name, String ciphertext, TransitOptions o) {
    String op = "decrypt " + name;
    return Wire.async(
        () ->
            post(
                    p("decrypt", name(name, "decrypt")),
                    op,
                    Wire.body()
                        .put(
                            "ciphertext",
                            Wire.requireText(ciphertext, "ciphertext", "transit.decrypt"))
                        .put("context", Wire.optB64(o.context))
                        .put("associated_data", Wire.optB64(o.associatedData))
                        .build(),
                    true)
                .thenApply(d -> Wire.unb64(Wire.str(d, "plaintext"), "transit." + op)));
  }

  /**
   * Re-encrypts a ciphertext with the latest key version without revealing the plaintext.
   *
   * @param name key name
   * @param ciphertext ciphertext
   * @return the new ciphertext
   */
  public Ciphertext rewrap(String name, String ciphertext) {
    return rewrap(name, ciphertext, TransitOptions.none());
  }

  /**
   * Re-encrypts with options (key version, context).
   *
   * @param name key name
   * @param ciphertext ciphertext
   * @param options options
   * @return the new ciphertext
   */
  public Ciphertext rewrap(String name, String ciphertext, TransitOptions options) {
    return await(rewrapAsync(name, ciphertext, options), "rewrap");
  }

  /**
   * Asynchronous {@link #rewrap(String, String, TransitOptions)}.
   *
   * @param name key name
   * @param ciphertext ciphertext
   * @param o options
   * @return a future with the new ciphertext
   */
  public CompletableFuture<Ciphertext> rewrapAsync(
      String name, String ciphertext, TransitOptions o) {
    String op = "rewrap " + name;
    return Wire.async(
        () ->
            post(
                    p("rewrap", name(name, "rewrap")),
                    op,
                    Wire.body()
                        .put(
                            "ciphertext",
                            Wire.requireText(ciphertext, "ciphertext", "transit.rewrap"))
                        .put("context", Wire.optB64(o.context))
                        .put("key_version", o.keyVersion)
                        .build(),
                    false)
                .thenApply(d -> ciphertext(d, "transit." + op)));
  }

  private CompletableFuture<List<JsonNode>> batch(
      String kind, String name, List<Map<String, Object>> input) {
    String op = kind + "Batch " + name;
    if (input.isEmpty()) {
      return CompletableFuture.completedFuture(List.of());
    }
    return post(
            p(kind, name(name, kind + "Batch")),
            op,
            Map.of("batch_input", input, "partial_failure_response_code", 207),
            kind.equals("decrypt"))
        .thenApply(
            d -> {
              JsonNode r = d.get("batch_results");
              if (r == null || !r.isArray()) {
                throw Wire.unexpected("transit." + op, "no batch_results");
              }
              List<JsonNode> out = new ArrayList<>();
              r.forEach(out::add);
              return out;
            });
  }

  private static Optional<String> optText(JsonNode r, String field) {
    String s = Wire.str(r, field);
    return s.isEmpty() ? Optional.empty() : Optional.of(s);
  }

  /**
   * Encrypts many items in one request. Results are in input order; a failed item has {@code error}
   * set (the call itself fails only when the whole request fails).
   *
   * @param name key name
   * @param items items
   * @return the results
   */
  public List<EncryptBatchResult> encryptBatch(String name, List<EncryptBatchItem> items) {
    return await(encryptBatchAsync(name, items), "encryptBatch");
  }

  /**
   * Asynchronous {@link #encryptBatch(String, List)}.
   *
   * @param name key name
   * @param items items
   * @return a future with the results
   */
  public CompletableFuture<List<EncryptBatchResult>> encryptBatchAsync(
      String name, List<EncryptBatchItem> items) {
    return Wire.async(
        () -> {
          List<Map<String, Object>> input = new ArrayList<>();
          for (EncryptBatchItem i : items) {
            input.add(
                Wire.body()
                    .put("plaintext", Wire.b64(i.plaintext()))
                    .put("context", Wire.optB64(i.context()))
                    .put("reference", i.reference())
                    .build());
          }
          return batch("encrypt", name, input)
              .thenApply(
                  results -> {
                    List<EncryptBatchResult> out = new ArrayList<>();
                    for (JsonNode r : results) {
                      JsonNode kv = r.get("key_version");
                      out.add(
                          new EncryptBatchResult(
                              optText(r, "ciphertext"),
                              kv != null && kv.isNumber()
                                  ? OptionalInt.of(kv.asInt())
                                  : OptionalInt.empty(),
                              optText(r, "reference"),
                              optText(r, "error")));
                    }
                    return out;
                  });
        });
  }

  /**
   * Decrypts many items in one request; see {@link #encryptBatch} for error handling.
   *
   * @param name key name
   * @param items items
   * @return the results
   */
  public List<DecryptBatchResult> decryptBatch(String name, List<DecryptBatchItem> items) {
    return await(decryptBatchAsync(name, items), "decryptBatch");
  }

  /**
   * Asynchronous {@link #decryptBatch(String, List)}.
   *
   * @param name key name
   * @param items items
   * @return a future with the results
   */
  public CompletableFuture<List<DecryptBatchResult>> decryptBatchAsync(
      String name, List<DecryptBatchItem> items) {
    return Wire.async(
        () -> {
          List<Map<String, Object>> input = new ArrayList<>();
          for (DecryptBatchItem i : items) {
            input.add(
                Wire.body()
                    .put("ciphertext", i.ciphertext())
                    .put("context", Wire.optB64(i.context()))
                    .put("reference", i.reference())
                    .build());
          }
          return batch("decrypt", name, input)
              .thenApply(
                  results -> {
                    List<DecryptBatchResult> out = new ArrayList<>();
                    for (JsonNode r : results) {
                      Optional<String> error = optText(r, "error");
                      Optional<byte[]> plain =
                          error.isEmpty() && r.path("plaintext").isTextual()
                              ? Optional.of(
                                  Wire.unb64(r.get("plaintext").asText(), "transit.decryptBatch"))
                              : Optional.empty();
                      out.add(new DecryptBatchResult(plain, optText(r, "reference"), error));
                    }
                    return out;
                  });
        });
  }

  /**
   * Generates a 256-bit data key encrypted with the transit key, plus its plaintext.
   *
   * @param name key name
   * @return the data key
   */
  public DataKey generateDataKey(String name) {
    return generateDataKey(name, true, 256);
  }

  /**
   * Generates a data key.
   *
   * @param name key name
   * @param plaintext also return the plaintext ({@code plaintext} variant) instead of only the
   *     ciphertext ({@code wrapped} variant)
   * @param bits 128, 256 or 512
   * @return the data key
   */
  public DataKey generateDataKey(String name, boolean plaintext, int bits) {
    return await(
        generateDataKeyAsync(name, plaintext, bits, TransitOptions.none()), "generateDataKey");
  }

  /**
   * Asynchronous {@link #generateDataKey(String, boolean, int)} (options: context).
   *
   * @param name key name
   * @param plaintext also return the plaintext
   * @param bits key size
   * @param o options
   * @return a future with the data key
   */
  public CompletableFuture<DataKey> generateDataKeyAsync(
      String name, boolean plaintext, int bits, TransitOptions o) {
    String op = "generateDataKey " + name;
    return Wire.async(
        () ->
            post(
                    p(
                        "datakey",
                        plaintext ? "plaintext" : "wrapped",
                        name(name, "generateDataKey")),
                    op,
                    Wire.body().put("bits", bits).put("context", Wire.optB64(o.context)).build(),
                    false)
                .thenApply(
                    d -> {
                      Ciphertext c = ciphertext(d, "transit." + op);
                      String pt = Wire.str(d, "plaintext");
                      return new DataKey(
                          c.ciphertext(),
                          c.keyVersion(),
                          pt.isEmpty()
                              ? Optional.empty()
                              : Optional.of(Wire.unb64(pt, "transit." + op)));
                    }));
  }

  // ---- hmac / sign / verify ----

  /**
   * HMAC of the input with the key ({@code vault:v<n>:<base64>}).
   *
   * @param name key name
   * @param input bytes
   * @return the HMAC
   */
  public String hmac(String name, byte[] input) {
    return hmac(name, input, TransitOptions.none());
  }

  /**
   * HMAC with options (hash algorithm, key version).
   *
   * @param name key name
   * @param input bytes
   * @param options options
   * @return the HMAC
   */
  public String hmac(String name, byte[] input, TransitOptions options) {
    return await(hmacAsync(name, input, options), "hmac");
  }

  /**
   * Asynchronous {@link #hmac(String, byte[], TransitOptions)}.
   *
   * @param name key name
   * @param input bytes
   * @param o options
   * @return a future with the HMAC
   */
  public CompletableFuture<String> hmacAsync(String name, byte[] input, TransitOptions o) {
    String op = "hmac " + name;
    return Wire.async(
        () ->
            post(
                    p("hmac", name(name, "hmac"), o.hashAlgorithm == null ? "" : o.hashAlgorithm),
                    op,
                    Wire.body()
                        .put("input", Wire.b64(input))
                        .put("key_version", o.keyVersion)
                        .build(),
                    true)
                .thenApply(
                    d -> {
                      if (!d.path("hmac").isTextual()) {
                        throw Wire.unexpected("transit." + op, "no hmac");
                      }
                      return d.get("hmac").asText();
                    }));
  }

  /**
   * Signs the input with an asymmetric key.
   *
   * @param name key name
   * @param input bytes
   * @return the signature
   */
  public Signature sign(String name, byte[] input) {
    return sign(name, input, TransitOptions.none());
  }

  /**
   * Signs with options (hash algorithm, signature algorithm, prehashed, key version, context).
   *
   * @param name key name
   * @param input bytes
   * @param options options
   * @return the signature
   */
  public Signature sign(String name, byte[] input, TransitOptions options) {
    return await(signAsync(name, input, options), "sign");
  }

  /**
   * Asynchronous {@link #sign(String, byte[], TransitOptions)}.
   *
   * @param name key name
   * @param input bytes
   * @param o options
   * @return a future with the signature
   */
  public CompletableFuture<Signature> signAsync(String name, byte[] input, TransitOptions o) {
    String op = "sign " + name;
    return Wire.async(
        () ->
            post(
                    p("sign", name(name, "sign"), o.hashAlgorithm == null ? "" : o.hashAlgorithm),
                    op,
                    Wire.body()
                        .put("input", Wire.b64(input))
                        .put("signature_algorithm", o.signatureAlgorithm)
                        .put("prehashed", o.prehashed)
                        .put("key_version", o.keyVersion)
                        .put("context", Wire.optB64(o.context))
                        .build(),
                    false)
                .thenApply(
                    d -> {
                      if (!d.path("signature").isTextual()) {
                        throw Wire.unexpected("transit." + op, "no signature");
                      }
                      return new Signature(d.get("signature").asText(), Wire.num(d, "key_version"));
                    }));
  }

  /**
   * Verifies a signature; {@code false} for an invalid signature (not an error).
   *
   * @param name key name
   * @param input signed bytes
   * @param signature {@code vault:v<n>:} signature
   * @return whether the signature is valid
   */
  public boolean verify(String name, byte[] input, String signature) {
    return verify(name, input, signature, TransitOptions.none());
  }

  /**
   * Verifies a signature with options.
   *
   * @param name key name
   * @param input signed bytes
   * @param signature signature
   * @param options options
   * @return whether the signature is valid
   */
  public boolean verify(String name, byte[] input, String signature, TransitOptions options) {
    return await(verifyAsync(name, input, signature, null, options), "verify");
  }

  /**
   * Verifies an HMAC produced by {@link #hmac}.
   *
   * @param name key name
   * @param input bytes
   * @param hmac {@code vault:v<n>:} HMAC
   * @return whether the HMAC is valid
   */
  public boolean verifyHmac(String name, byte[] input, String hmac) {
    return await(verifyAsync(name, input, null, hmac, TransitOptions.none()), "verify");
  }

  /**
   * Asynchronous verification of a signature or an HMAC (exactly one must be given).
   *
   * @param name key name
   * @param input bytes
   * @param signature signature, or null
   * @param hmac HMAC, or null
   * @param o options
   * @return a future with the result
   */
  public CompletableFuture<Boolean> verifyAsync(
      String name, byte[] input, String signature, String hmac, TransitOptions o) {
    String op = "verify " + name;
    return Wire.async(
        () -> {
          if ((signature == null) == (hmac == null)) {
            throw new ValidationException("transit.verify: pass exactly one of signature or hmac");
          }
          return post(
                  p("verify", name(name, "verify"), o.hashAlgorithm == null ? "" : o.hashAlgorithm),
                  op,
                  Wire.body()
                      .put("input", Wire.b64(input))
                      .put("signature", signature)
                      .put("hmac", hmac)
                      .put("signature_algorithm", o.signatureAlgorithm)
                      .put("prehashed", o.prehashed)
                      .put("context", Wire.optB64(o.context))
                      .build(),
                  true)
              .thenApply(d -> Wire.bool(d, "valid"));
        });
  }

  // ---- utilities ----

  /**
   * SHA2-256 hash of the input, hex encoded.
   *
   * @param input bytes
   * @return the hash
   */
  public String hash(byte[] input) {
    return hash(input, null, null);
  }

  /**
   * Hash of the input.
   *
   * @param input bytes
   * @param algorithm e.g. {@code sha2-256} (default), {@code sha2-512}, {@code sha3-256}; may be
   *     null
   * @param format {@code hex} (default) or {@code base64}; may be null
   * @return the hash
   */
  public String hash(byte[] input, String algorithm, String format) {
    return await(hashAsync(input, algorithm, format), "hash");
  }

  /**
   * Asynchronous {@link #hash(byte[], String, String)}.
   *
   * @param input bytes
   * @param algorithm algorithm, may be null
   * @param format format, may be null
   * @return a future with the hash
   */
  public CompletableFuture<String> hashAsync(byte[] input, String algorithm, String format) {
    return Wire.async(
        () ->
            post(
                    p("hash", algorithm == null ? "" : algorithm),
                    "hash",
                    Wire.body().put("input", Wire.b64(input)).put("format", format).build(),
                    true)
                .thenApply(
                    d -> {
                      if (!d.path("sum").isTextual()) {
                        throw Wire.unexpected("transit.hash", "no sum");
                      }
                      return d.get("sum").asText();
                    }));
  }

  /**
   * Random bytes from the server, base64 encoded.
   *
   * @param bytes number of bytes
   * @return the base64 text
   */
  public String randomBytes(int bytes) {
    return randomBytes(bytes, "base64");
  }

  /**
   * Random bytes from the server.
   *
   * @param bytes number of bytes (positive)
   * @param format {@code base64} or {@code hex}
   * @return the encoded bytes
   */
  public String randomBytes(int bytes, String format) {
    return await(randomBytesAsync(bytes, format), "randomBytes");
  }

  /**
   * Asynchronous {@link #randomBytes(int, String)}.
   *
   * @param bytes number of bytes
   * @param format format, may be null for base64
   * @return a future with the encoded bytes
   */
  public CompletableFuture<String> randomBytesAsync(int bytes, String format) {
    return Wire.async(
        () -> {
          if (bytes <= 0) {
            throw new ValidationException("transit.randomBytes: bytes must be a positive integer");
          }
          return post(
                  p("random"),
                  "randomBytes",
                  Map.of("bytes", bytes, "format", format == null ? "base64" : format),
                  true)
              .thenApply(
                  d -> {
                    if (!d.path("random_bytes").isTextual()) {
                      throw Wire.unexpected("transit.randomBytes", "no random_bytes");
                    }
                    return d.get("random_bytes").asText();
                  });
        });
  }

  @Override
  public String toString() {
    return "Transit(" + mount + ")";
  }
}
