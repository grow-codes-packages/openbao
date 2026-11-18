package codes.grow.packages.openbao;

import codes.grow.packages.openbao.core.HttpTransport;
import codes.grow.packages.openbao.core.Json;
import codes.grow.packages.openbao.core.NotFoundException;
import codes.grow.packages.openbao.core.UnsupportedException;
import codes.grow.packages.openbao.core.ValidationException;
import codes.grow.packages.openbao.secrets.BaseSecretsProvider;
import codes.grow.packages.openbao.secrets.DeleteOptions;
import codes.grow.packages.openbao.secrets.GetOptions;
import codes.grow.packages.openbao.secrets.SecretMetadata;
import codes.grow.packages.openbao.secrets.SecretValue;
import codes.grow.packages.openbao.secrets.SetOptions;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.function.Supplier;

/**
 * {@code SecretsProvider} over an OpenBao KV mount (v1 or v2, auto-detected): {@code
 * client.secrets()}.
 *
 * <ul>
 *   <li>One secret is one KV path ({@code <path>/<name>}) whose data is {@code {"value":
 *       "<string>"}}; binary values are stored as base64 with {@code "encoding": "base64"}; objects
 *       are JSON-encoded. A path without a {@code value} field reads as the JSON of the whole map.
 *   <li>The KV v2 version is the {@link SecretValue} version ({@code ""} on KV v1).
 *   <li>{@code delete} soft-deletes the latest version (KV v2), {@code versions} deletes those
 *       versions, {@code permanent} removes every version and the metadata. Missing secrets raise
 *       {@code NotFoundException}.
 *   <li>{@code list(prefix)} lists one folder level (sub-folders skipped); on KV v2 every entry
 *       carries its metadata (read with up to {@value #LIST_METADATA_CONCURRENCY} parallel calls)
 *       and secrets whose current version is deleted are skipped.
 * </ul>
 */
public final class OpenBaoSecretsProvider extends BaseSecretsProvider {
  /** Parallel metadata reads in {@code list()}. */
  public static final int LIST_METADATA_CONCURRENCY = 8;

  /** Capabilities for the conformance runner. */
  public static final List<String> CAPABILITIES = List.of("write", "versions", "delete");

  private static final String ENCODING_FIELD = "encoding";

  private final KvMount kv;
  private final String path;
  private final String valueField;
  private final Runnable onClose;

  OpenBaoSecretsProvider(KvMount kv, SecretsOptions options, Runnable onClose) {
    this.kv = kv;
    this.path = Wire.trimSlashes(options.path == null ? "" : options.path);
    this.valueField = options.valueField == null ? "value" : options.valueField;
    this.onClose = onClose;
  }

  /**
   * Returns the KV mount.
   *
   * @return the mount
   */
  public KvMount kv() {
    return kv;
  }

  /**
   * Returns the KV path of a secret: {@code <path or provider path>/<name>}.
   *
   * @param name secret name
   * @param path explicit base path, or null for the provider path
   * @return the KV path
   */
  public String fullPath(String name, String path) {
    return Wire.join(path == null ? this.path : path, name);
  }

  private Kv engine(String p) {
    return HttpTransport.await(kv.engineAsync(p), "secrets.detectVersion");
  }

  private static <T> Optional<T> orEmpty(Supplier<T> call) {
    try {
      return Optional.ofNullable(call.get());
    } catch (NotFoundException e) {
      return Optional.empty();
    }
  }

  private SecretValue decode(Map<String, Object> data, String version) {
    Object raw = data.get(valueField);
    if (raw == null && !data.containsKey(valueField)) {
      return SecretValue.ofBytes(Json.encode(data), version);
    }
    if (!(raw instanceof String)) {
      return SecretValue.ofBytes(Json.encode(raw), version);
    }
    String s = (String) raw;
    if ("base64".equals(data.get(ENCODING_FIELD))) {
      try {
        return SecretValue.ofBytes(Base64.getDecoder().decode(s), version);
      } catch (IllegalArgumentException e) {
        throw new ValidationException("secrets.get: value is not valid base64");
      }
    }
    return SecretValue.of(s, version);
  }

  private static String utf8(byte[] value) {
    try {
      return StandardCharsets.UTF_8
          .newDecoder()
          .onMalformedInput(CodingErrorAction.REPORT)
          .onUnmappableCharacter(CodingErrorAction.REPORT)
          .decode(ByteBuffer.wrap(value))
          .toString();
    } catch (CharacterCodingException e) {
      return null;
    }
  }

  private Map<String, Object> payload(byte[] value) {
    String text = utf8(value);
    if (text != null) {
      return Map.of(valueField, text);
    }
    return Map.of(valueField, Base64.getEncoder().encodeToString(value), ENCODING_FIELD, "base64");
  }

  @Override
  protected Optional<SecretValue> fetchSecret(String name, GetOptions opts) {
    String p = fullPath(name, opts.path().orElse(null));
    Kv engine = engine(p);
    Integer version = null;
    if (opts.version().isPresent()) {
      if (engine instanceof KvV1) {
        throw new UnsupportedException(
            "secrets.get " + name + ": versions need a KV version 2 mount");
      }
      try {
        version = Integer.parseInt(opts.version().get());
      } catch (NumberFormatException e) {
        throw new ValidationException("secrets.get " + name + ": version must be an integer");
      }
    }
    Integer v = version;
    return orEmpty(() -> v == null ? engine.read(p) : engine.read(p, v))
        .map(
            s -> decode(s.data(), s.metadata().map(m -> String.valueOf(m.version())).orElse(null)));
  }

  @Override
  protected List<SecretMetadata> listSecrets(String prefixOrPath) {
    String prefix = Wire.trimSlashes(prefixOrPath);
    String folder = fullPath(prefix, null);
    Kv engine = engine(folder);
    List<String> names = new ArrayList<>();
    for (String k : engine.list(folder)) {
      if (!k.endsWith("/")) {
        names.add(prefix.isEmpty() ? k : prefix + "/" + k);
      }
    }
    names.sort(null);
    List<SecretMetadata> out = new ArrayList<>();
    if (engine instanceof KvV1) {
      for (String n : names) {
        out.add(basic(n, null).build());
      }
      return out;
    }
    for (int i = 0; i < names.size(); i += LIST_METADATA_CONCURRENCY) {
      List<CompletableFuture<Optional<SecretMetadata>>> batch = new ArrayList<>();
      for (String n : names.subList(i, Math.min(names.size(), i + LIST_METADATA_CONCURRENCY))) {
        batch.add(metaV2Async(engine, n, null));
      }
      for (CompletableFuture<Optional<SecretMetadata>> f : batch) {
        HttpTransport.await(f, "secrets.list").ifPresent(out::add);
      }
    }
    return out;
  }

  private SecretMetadata.Builder basic(String name, String basePath) {
    String full = fullPath(name, basePath);
    int slash = full.lastIndexOf('/');
    SecretMetadata.Builder b = SecretMetadata.builder(name);
    if (slash > 0) {
      b.path(full.substring(0, slash));
    }
    return b;
  }

  private CompletableFuture<Optional<SecretMetadata>> metaV2Async(
      Kv engine, String name, String basePath) {
    return Wire.orElseOnNotFound(
        engine
            .readMetadataAsync(fullPath(name, basePath))
            .thenApply(
                m -> {
                  if (m.currentDeleted()) {
                    return Optional.<SecretMetadata>empty();
                  }
                  SecretMetadata.Builder b =
                      basic(name, basePath)
                          .version(String.valueOf(m.currentVersion()))
                          .tags(m.customMetadata())
                          .versions(m.versions().size())
                          .extra("maxVersions", String.valueOf(m.maxVersions()))
                          .extra("casRequired", String.valueOf(m.casRequired()))
                          .extra(
                              "deleteVersionAfterMs",
                              String.valueOf(m.deleteVersionAfter().toMillis()))
                          .extra("oldestVersion", String.valueOf(m.oldestVersion()));
                  m.createdTime().ifPresent(b::createdAt);
                  m.updatedTime().ifPresent(b::updatedAt);
                  return Optional.of(b.build());
                }),
        Optional.empty());
  }

  @Override
  protected String putSecret(String name, byte[] value, SetOptions opts) {
    String p = fullPath(name, opts.path().orElse(null));
    Kv engine = engine(p);
    Map<String, Object> data = payload(value);
    if (engine instanceof KvV1) {
      if (opts.cas().isPresent() || !opts.tags().isEmpty()) {
        throw new UnsupportedException(
            "secrets.set " + name + ": cas and tags need a KV version 2 mount");
      }
      engine.write(p, data);
      return "";
    }
    Optional<KvVersionMetadata> meta =
        opts.cas().isPresent()
            ? engine.write(p, data, opts.cas().getAsInt())
            : engine.write(p, data);
    if (!opts.tags().isEmpty()) {
      engine.writeMetadata(p, KvMetadataOptions.builder().customMetadata(opts.tags()).build());
    }
    return meta.map(m -> String.valueOf(m.version())).orElse("");
  }

  @Override
  protected void removeSecret(String name, DeleteOptions opts) {
    String p = fullPath(name, opts.path().orElse(null));
    Kv engine = engine(p);
    NotFoundException notFound = new NotFoundException("secrets.delete " + name + ": not found");
    // KV DELETE answers 204 for missing paths, so check first (DECISIONS.md #6).
    if (engine instanceof KvV1) {
      if (orEmpty(() -> engine.read(p)).isEmpty()) {
        throw notFound;
      }
      engine.delete(p);
      return;
    }
    if (!opts.versions().isEmpty() || opts.permanent()) {
      if (orEmpty(() -> engine.readMetadata(p)).isEmpty()) {
        throw notFound;
      }
      if (opts.permanent()) {
        engine.deleteMetadata(p);
      } else {
        List<Integer> versions = new ArrayList<>();
        for (String v : opts.versions()) {
          try {
            versions.add(Integer.parseInt(v));
          } catch (NumberFormatException e) {
            throw new ValidationException("secrets.delete " + name + ": versions must be integers");
          }
        }
        engine.deleteVersions(p, versions);
      }
      return;
    }
    if (orEmpty(() -> engine.read(p)).isEmpty()) {
      throw notFound;
    }
    engine.delete(p);
  }

  @Override
  protected Optional<SecretMetadata> fetchMetadata(String name, GetOptions opts) {
    String base = opts.path().orElse(null);
    String p = fullPath(name, base);
    Kv engine = engine(p);
    if (engine instanceof KvV2) {
      return HttpTransport.await(metaV2Async(engine, name, base), "secrets.metadata");
    }
    return orEmpty(() -> engine.read(p)).map(s -> basic(name, base).build());
  }

  /** Stops watchers and detaches from the client. Idempotent. */
  @Override
  public void close() {
    super.close();
    onClose.run();
  }

  @Override
  public String toString() {
    return "OpenBaoSecretsProvider(" + kv.mount() + "/" + path + ")";
  }
}
