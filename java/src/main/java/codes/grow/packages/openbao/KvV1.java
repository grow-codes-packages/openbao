package codes.grow.packages.openbao;

import codes.grow.packages.openbao.core.UnsupportedException;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;

/** KV version 1 (unversioned) mount. Version-only operations raise {@code UnsupportedException}. */
public final class KvV1 implements Kv {
  private final ClientContext ctx;
  private final String mount;

  KvV1(ClientContext ctx, String mount) {
    this.ctx = ctx;
    this.mount = Wire.trimSlashes(mount);
  }

  @Override
  public String mount() {
    return mount;
  }

  /**
   * Returns the KV version.
   *
   * @return always 1
   */
  public int version() {
    return 1;
  }

  private String path(String path, String op) {
    return Wire.encodePath(mount, Wire.requireText(path, "path", op));
  }

  private <T> CompletableFuture<T> unsupported(String op, String path) {
    return CompletableFuture.failedFuture(
        new UnsupportedException(
            "kv." + op + " " + Wire.join(mount, path) + ": not supported by KV version 1"));
  }

  @Override
  public CompletableFuture<KvSecret> readAsync(String path, Integer version) {
    if (version != null) {
      return unsupported("read with version", path);
    }
    String op = "kv.read " + Wire.join(mount, path);
    return Wire.async(
        () ->
            ctx.http
                .call("GET", path(path, op), op)
                .data()
                .thenApply(d -> new KvSecret(Wire.toMap(d), Optional.empty())));
  }

  @Override
  public CompletableFuture<Optional<KvVersionMetadata>> writeAsync(
      String path, Map<String, ?> data, Integer cas) {
    if (cas != null) {
      return unsupported("write with cas", path);
    }
    String op = "kv.write " + Wire.join(mount, path);
    return Wire.async(
        () ->
            ctx.http
                .call("POST", path(path, op), op)
                .json(data)
                .run()
                .thenApply(v -> Optional.empty()));
  }

  @Override
  public CompletableFuture<KvVersionMetadata> patchAsync(
      String path, Map<String, ?> data, Integer cas) {
    return unsupported("patch", path);
  }

  @Override
  public CompletableFuture<Void> deleteAsync(String path) {
    String op = "kv.delete " + Wire.join(mount, path);
    return Wire.async(() -> ctx.http.call("DELETE", path(path, op), op).run());
  }

  @Override
  public CompletableFuture<Void> deleteVersionsAsync(String path, List<Integer> versions) {
    return unsupported("deleteVersions", path);
  }

  @Override
  public CompletableFuture<Void> undeleteAsync(String path, List<Integer> versions) {
    return unsupported("undelete", path);
  }

  @Override
  public CompletableFuture<Void> destroyAsync(String path, List<Integer> versions) {
    return unsupported("destroy", path);
  }

  @Override
  public CompletableFuture<List<String>> listAsync(String path, String after, Integer limit) {
    String p = path == null ? "" : path;
    String op = "kv.list " + Wire.join(mount, p);
    return Wire.orElseOnNotFound(
        ctx.http
            .call("GET", Wire.encodePath(mount, p) + "/", op)
            .list()
            .data()
            .thenApply(d -> Wire.strings(d.get("keys"))),
        List.of());
  }

  @Override
  public CompletableFuture<KvMetadata> readMetadataAsync(String path) {
    return unsupported("readMetadata", path);
  }

  @Override
  public CompletableFuture<Void> writeMetadataAsync(String path, KvMetadataOptions options) {
    return unsupported("writeMetadata", path);
  }

  @Override
  public CompletableFuture<Void> deleteMetadataAsync(String path) {
    return unsupported("deleteMetadata", path);
  }

  @Override
  public String toString() {
    return "KvV1(" + mount + ")";
  }
}
