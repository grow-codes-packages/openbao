package codes.grow.packages.openbao;

import codes.grow.packages.openbao.core.NotFoundException;
import codes.grow.packages.openbao.core.ValidationException;
import com.fasterxml.jackson.databind.JsonNode;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;

/** KV version 2 (versioned) mount. */
public final class KvV2 implements Kv {
  private final ClientContext ctx;
  private final String mount;

  KvV2(ClientContext ctx, String mount) {
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
   * @return always 2
   */
  public int version() {
    return 2;
  }

  private String path(String kind, String path, String op) {
    return Wire.encodePath(mount, kind, Wire.requireText(path, "path", op));
  }

  private String op(String name, String path) {
    return "kv." + name + " " + Wire.join(mount, path == null ? "" : path);
  }

  private static Map<String, Object> casBody(Map<String, ?> data, Integer cas) {
    Map<String, Object> body = new LinkedHashMap<>();
    if (cas != null) {
      body.put("options", Map.of("cas", cas));
    }
    body.put("data", data);
    return body;
  }

  @Override
  public CompletableFuture<KvSecret> readAsync(String path, Integer version) {
    String op = op("read", path);
    return Wire.async(
        () ->
            ctx.http
                .call("GET", path("data", path, op), op)
                .query("version", version)
                .data()
                .thenApply(
                    d -> {
                      JsonNode data = d.get("data");
                      if (data == null || !data.isObject()) {
                        throw new NotFoundException(op + ": version is deleted or destroyed");
                      }
                      JsonNode meta = d.get("metadata");
                      return new KvSecret(
                          Wire.toMap(data),
                          meta != null && meta.isObject()
                              ? Optional.of(KvVersionMetadata.from(meta))
                              : Optional.empty());
                    }));
  }

  @Override
  public CompletableFuture<Optional<KvVersionMetadata>> writeAsync(
      String path, Map<String, ?> data, Integer cas) {
    String op = op("write", path);
    return Wire.async(
        () ->
            ctx.http
                .call("POST", path("data", path, op), op)
                .json(casBody(data, cas))
                .data()
                .thenApply(d -> Optional.of(KvVersionMetadata.from(d))));
  }

  @Override
  public CompletableFuture<KvVersionMetadata> patchAsync(
      String path, Map<String, ?> data, Integer cas) {
    String op = op("patch", path);
    return Wire.async(
        () ->
            ctx.http
                .call("PATCH", path("data", path, op), op)
                .json(casBody(data, cas))
                .contentType("application/merge-patch+json")
                .data()
                .thenApply(KvVersionMetadata::from));
  }

  @Override
  public CompletableFuture<Void> deleteAsync(String path) {
    String op = op("delete", path);
    return Wire.async(() -> ctx.http.call("DELETE", path("data", path, op), op).run());
  }

  private CompletableFuture<Void> versions(
      String kind, String name, String path, List<Integer> versions) {
    String op = op(name, path);
    return Wire.async(
        () -> {
          if (versions == null
              || versions.isEmpty()
              || versions.stream().anyMatch(v -> v == null || v <= 0)) {
            throw new ValidationException(
                op + ": versions must be a non-empty list of positive integers");
          }
          return ctx.http
              .call(kind.equals("destroy") ? "PUT" : "POST", path(kind, path, op), op)
              .json(Map.of("versions", versions))
              .run();
        });
  }

  @Override
  public CompletableFuture<Void> deleteVersionsAsync(String path, List<Integer> versions) {
    return versions("delete", "deleteVersions", path, versions);
  }

  @Override
  public CompletableFuture<Void> undeleteAsync(String path, List<Integer> versions) {
    return versions("undelete", "undelete", path, versions);
  }

  @Override
  public CompletableFuture<Void> destroyAsync(String path, List<Integer> versions) {
    return versions("destroy", "destroy", path, versions);
  }

  @Override
  public CompletableFuture<List<String>> listAsync(String path, String after, Integer limit) {
    String p = path == null ? "" : path;
    String op = op("list", p);
    return Wire.orElseOnNotFound(
        ctx.http
            .call("GET", Wire.encodePath(mount, "metadata", p) + "/", op)
            .list()
            .query("after", after)
            .query("limit", limit)
            .data()
            .thenApply(d -> Wire.strings(d.get("keys"))),
        List.of());
  }

  @Override
  public CompletableFuture<KvMetadata> readMetadataAsync(String path) {
    String op = op("readMetadata", path);
    return Wire.async(
        () ->
            ctx.http.call("GET", path("metadata", path, op), op).data().thenApply(KvV2::metadata));
  }

  static KvMetadata metadata(JsonNode d) {
    Map<Integer, KvVersionMetadata> versions = new LinkedHashMap<>();
    JsonNode raw = d.get("versions");
    if (raw != null && raw.isObject()) {
      for (Map.Entry<String, JsonNode> e : raw.properties()) {
        try {
          int v = Integer.parseInt(e.getKey());
          versions.put(v, KvVersionMetadata.from(e.getValue(), v));
        } catch (NumberFormatException ignored) {
          // not a version number
        }
      }
    }
    return new KvMetadata(
        Wire.bool(d, "cas_required"),
        Wire.time(d.get("created_time")),
        Wire.time(d.get("updated_time")),
        Wire.num(d, "current_version"),
        Wire.num(d, "oldest_version"),
        Wire.num(d, "max_versions"),
        Wire.vaultDuration(d.get("delete_version_after")),
        Wire.stringMap(d.get("custom_metadata")),
        versions);
  }

  @Override
  public CompletableFuture<Void> writeMetadataAsync(String path, KvMetadataOptions o) {
    String op = op("writeMetadata", path);
    return Wire.async(
        () ->
            ctx.http
                .call("POST", path("metadata", path, op), op)
                .json(
                    Wire.body()
                        .put("max_versions", o.maxVersions)
                        .put("cas_required", o.casRequired)
                        .put("delete_version_after", Wire.optDuration(o.deleteVersionAfter))
                        .put("custom_metadata", o.customMetadata)
                        .build())
                .run());
  }

  @Override
  public CompletableFuture<Void> deleteMetadataAsync(String path) {
    String op = op("deleteMetadata", path);
    return Wire.async(() -> ctx.http.call("DELETE", path("metadata", path, op), op).run());
  }

  @Override
  public String toString() {
    return "KvV2(" + mount + ")";
  }
}
