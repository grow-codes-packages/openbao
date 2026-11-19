package codes.grow.packages.openbao;

import codes.grow.packages.openbao.core.HttpTransport;
import codes.grow.packages.openbao.core.ValidationException;
import com.fasterxml.jackson.databind.JsonNode;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.function.Function;

/**
 * A KV mount whose version is detected on first use ({@code GET sys/internal/ui/mounts/<mount>}) or
 * taken from {@link OpenBaoConfig#kvVersion()}, then delegates to {@link KvV1} or {@link KvV2}.
 * Returned by {@code client.kv()}.
 */
public final class KvMount implements Kv {
  private final ClientContext ctx;
  private final String mount;
  private volatile Kv engine;
  private CompletableFuture<Kv> detecting;

  KvMount(ClientContext ctx, String mount, Integer version) {
    this.ctx = ctx;
    this.mount = Wire.trimSlashes(mount);
    if (version != null) {
      this.engine = make(version);
    }
  }

  private Kv make(int version) {
    return version == 2 ? new KvV2(ctx, mount) : new KvV1(ctx, mount);
  }

  @Override
  public String mount() {
    return mount;
  }

  /**
   * Detects the KV version of a mount: {@code GET sys/internal/ui/mounts/<mount>/<path>}.
   * Restricted tokens need some capability on {@code path}.
   *
   * @param ctx client context
   * @param mount mount path
   * @param path a path inside the mount the token can access, may be empty
   * @return a future with 1 or 2; fails with {@code ValidationException} for non-KV mounts
   */
  static CompletableFuture<Integer> detect(ClientContext ctx, String mount, String path) {
    String op = "kv.detectVersion " + mount;
    return Wire.async(
        () ->
            ctx.http
                .call("GET", Wire.encodePath("sys/internal/ui/mounts", mount, path), op)
                .data()
                .thenApply(
                    d -> {
                      String type = Wire.str(d, "type");
                      if (!type.equals("kv")) {
                        throw new ValidationException(
                            op + ": not a KV mount (type " + d.path("type").asText() + ")");
                      }
                      JsonNode v = d.path("options").path("version");
                      String s = v.isMissingNode() || v.isNull() ? "1" : v.asText();
                      if (s.equals("2")) {
                        return 2;
                      }
                      if (s.equals("1")) {
                        return 1;
                      }
                      throw Wire.unexpected(op, "unknown KV version " + s);
                    }));
  }

  /**
   * Returns the KV version (detects it when unknown).
   *
   * @return 1 or 2
   */
  public int version() {
    return HttpTransport.await(engineAsync(""), "kv.detectVersion") instanceof KvV2 ? 2 : 1;
  }

  /**
   * Returns the concrete engine (detects the version on first use).
   *
   * @return {@link KvV1} or {@link KvV2}
   */
  public Kv engine() {
    return HttpTransport.await(engineAsync(""), "kv.detectVersion");
  }

  /**
   * Asynchronous {@link #engine()}.
   *
   * @param path a path the token can access (used by the detection preflight)
   * @return a future with the engine
   */
  public synchronized CompletableFuture<Kv> engineAsync(String path) {
    Kv e = engine;
    if (e != null) {
      return CompletableFuture.completedFuture(e);
    }
    if (detecting == null) {
      CompletableFuture<Kv> f = detect(ctx, mount, path == null ? "" : path).thenApply(this::make);
      detecting = f;
      f.whenComplete(
          (k, err) -> {
            synchronized (this) {
              if (err == null) {
                engine = k;
              }
              detecting = null;
            }
          });
      return f;
    }
    return detecting;
  }

  private <T> CompletableFuture<T> with(String path, Function<Kv, CompletableFuture<T>> fn) {
    return engineAsync(path).thenCompose(fn);
  }

  @Override
  public CompletableFuture<KvSecret> readAsync(String path, Integer version) {
    return with(path, k -> k.readAsync(path, version));
  }

  @Override
  public CompletableFuture<Optional<KvVersionMetadata>> writeAsync(
      String path, Map<String, ?> data, Integer cas) {
    return with(path, k -> k.writeAsync(path, data, cas));
  }

  @Override
  public CompletableFuture<KvVersionMetadata> patchAsync(
      String path, Map<String, ?> data, Integer cas) {
    return with(path, k -> k.patchAsync(path, data, cas));
  }

  @Override
  public CompletableFuture<Void> deleteAsync(String path) {
    return with(path, k -> k.deleteAsync(path));
  }

  @Override
  public CompletableFuture<Void> deleteVersionsAsync(String path, List<Integer> versions) {
    return with(path, k -> k.deleteVersionsAsync(path, versions));
  }

  @Override
  public CompletableFuture<Void> undeleteAsync(String path, List<Integer> versions) {
    return with(path, k -> k.undeleteAsync(path, versions));
  }

  @Override
  public CompletableFuture<Void> destroyAsync(String path, List<Integer> versions) {
    return with(path, k -> k.destroyAsync(path, versions));
  }

  @Override
  public CompletableFuture<List<String>> listAsync(String path, String after, Integer limit) {
    return with(path, k -> k.listAsync(path, after, limit));
  }

  @Override
  public CompletableFuture<KvMetadata> readMetadataAsync(String path) {
    return with(path, k -> k.readMetadataAsync(path));
  }

  @Override
  public CompletableFuture<Void> writeMetadataAsync(String path, KvMetadataOptions options) {
    return with(path, k -> k.writeMetadataAsync(path, options));
  }

  @Override
  public CompletableFuture<Void> deleteMetadataAsync(String path) {
    return with(path, k -> k.deleteMetadataAsync(path));
  }

  @Override
  public String toString() {
    return "KvMount(" + mount + ")";
  }
}
