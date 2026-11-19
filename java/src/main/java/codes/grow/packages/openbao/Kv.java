package codes.grow.packages.openbao;

import codes.grow.packages.openbao.core.HttpTransport;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;

/**
 * Operations of a KV secrets engine mount ({@link KvV1}, {@link KvV2} or the auto-detecting {@link
 * KvMount}). Version-only operations raise {@code UnsupportedException} on KV v1. Paths are
 * relative to the mount; each segment is percent-encoded.
 */
public interface Kv {
  /**
   * Returns the mount path.
   *
   * @return the mount, without slashes
   */
  String mount();

  /**
   * Reads the latest version; {@code NotFoundException} when missing, deleted or destroyed.
   *
   * @param path secret path
   * @return the secret
   */
  default KvSecret read(String path) {
    return HttpTransport.await(readAsync(path, null), "kv.read");
  }

  /**
   * Reads a specific version (KV v2).
   *
   * @param path secret path
   * @param version version number
   * @return the secret
   */
  default KvSecret read(String path, int version) {
    return HttpTransport.await(readAsync(path, version), "kv.read");
  }

  /**
   * Asynchronous read.
   *
   * @param path secret path
   * @param version version, or null for the latest
   * @return a future with the secret
   */
  CompletableFuture<KvSecret> readAsync(String path, Integer version);

  /**
   * Writes (replaces) a secret.
   *
   * @param path secret path
   * @param data data map
   * @return the new version metadata (empty on KV v1)
   */
  default Optional<KvVersionMetadata> write(String path, Map<String, ?> data) {
    return HttpTransport.await(writeAsync(path, data, null), "kv.write");
  }

  /**
   * Writes with check-and-set (KV v2): fails with {@code ConflictException} unless the current
   * version equals {@code cas} (0 = must not exist).
   *
   * @param path secret path
   * @param data data map
   * @param cas expected current version
   * @return the new version metadata
   */
  default Optional<KvVersionMetadata> write(String path, Map<String, ?> data, int cas) {
    return HttpTransport.await(writeAsync(path, data, cas), "kv.write");
  }

  /**
   * Asynchronous write.
   *
   * @param path secret path
   * @param data data map
   * @param cas expected current version, or null
   * @return a future with the new version metadata
   */
  CompletableFuture<Optional<KvVersionMetadata>> writeAsync(
      String path, Map<String, ?> data, Integer cas);

  /**
   * Merges {@code data} into the latest version (KV v2, RFC 7386: a null value removes the key).
   *
   * @param path secret path
   * @param data fields to merge
   * @return the new version metadata
   */
  default KvVersionMetadata patch(String path, Map<String, ?> data) {
    return HttpTransport.await(patchAsync(path, data, null), "kv.patch");
  }

  /**
   * Patch with check-and-set (KV v2).
   *
   * @param path secret path
   * @param data fields to merge
   * @param cas expected current version
   * @return the new version metadata
   */
  default KvVersionMetadata patch(String path, Map<String, ?> data, int cas) {
    return HttpTransport.await(patchAsync(path, data, cas), "kv.patch");
  }

  /**
   * Asynchronous patch.
   *
   * @param path secret path
   * @param data fields to merge
   * @param cas expected current version, or null
   * @return a future with the new version metadata
   */
  CompletableFuture<KvVersionMetadata> patchAsync(String path, Map<String, ?> data, Integer cas);

  /**
   * Deletes a secret (KV v2: soft-deletes the latest version). Missing paths are no error.
   *
   * @param path secret path
   */
  default void delete(String path) {
    HttpTransport.await(deleteAsync(path), "kv.delete");
  }

  /**
   * Asynchronous delete.
   *
   * @param path secret path
   * @return a future completed when done
   */
  CompletableFuture<Void> deleteAsync(String path);

  /**
   * Soft-deletes versions (KV v2).
   *
   * @param path secret path
   * @param versions positive version numbers
   */
  default void deleteVersions(String path, List<Integer> versions) {
    HttpTransport.await(deleteVersionsAsync(path, versions), "kv.deleteVersions");
  }

  /**
   * Asynchronous deleteVersions.
   *
   * @param path secret path
   * @param versions versions
   * @return a future completed when done
   */
  CompletableFuture<Void> deleteVersionsAsync(String path, List<Integer> versions);

  /**
   * Restores soft-deleted versions (KV v2).
   *
   * @param path secret path
   * @param versions versions
   */
  default void undelete(String path, List<Integer> versions) {
    HttpTransport.await(undeleteAsync(path, versions), "kv.undelete");
  }

  /**
   * Asynchronous undelete.
   *
   * @param path secret path
   * @param versions versions
   * @return a future completed when done
   */
  CompletableFuture<Void> undeleteAsync(String path, List<Integer> versions);

  /**
   * Permanently destroys versions (KV v2).
   *
   * @param path secret path
   * @param versions versions
   */
  default void destroy(String path, List<Integer> versions) {
    HttpTransport.await(destroyAsync(path, versions), "kv.destroy");
  }

  /**
   * Asynchronous destroy.
   *
   * @param path secret path
   * @param versions versions
   * @return a future completed when done
   */
  CompletableFuture<Void> destroyAsync(String path, List<Integer> versions);

  /**
   * Lists the keys of a folder (sorted; sub-folders end in {@code /}); empty when missing.
   *
   * @param path folder path, {@code ""} for the mount root
   * @return the keys
   */
  default List<String> list(String path) {
    return HttpTransport.await(listAsync(path, null, null), "kv.list");
  }

  /**
   * Lists one page of keys (KV v2 honours {@code after} and {@code limit}).
   *
   * @param path folder path
   * @param after start after this key, may be null
   * @param limit maximum keys, may be null
   * @return the keys
   */
  default List<String> list(String path, String after, Integer limit) {
    return HttpTransport.await(listAsync(path, after, limit), "kv.list");
  }

  /**
   * Asynchronous list.
   *
   * @param path folder path
   * @param after start after this key, may be null
   * @param limit maximum keys, may be null
   * @return a future with the keys
   */
  CompletableFuture<List<String>> listAsync(String path, String after, Integer limit);

  /**
   * Reads the metadata of a secret (KV v2); {@code NotFoundException} when missing.
   *
   * @param path secret path
   * @return the metadata
   */
  default KvMetadata readMetadata(String path) {
    return HttpTransport.await(readMetadataAsync(path), "kv.readMetadata");
  }

  /**
   * Asynchronous readMetadata.
   *
   * @param path secret path
   * @return a future with the metadata
   */
  CompletableFuture<KvMetadata> readMetadataAsync(String path);

  /**
   * Writes metadata settings of a secret (KV v2).
   *
   * @param path secret path
   * @param options settings
   */
  default void writeMetadata(String path, KvMetadataOptions options) {
    HttpTransport.await(writeMetadataAsync(path, options), "kv.writeMetadata");
  }

  /**
   * Asynchronous writeMetadata.
   *
   * @param path secret path
   * @param options settings
   * @return a future completed when done
   */
  CompletableFuture<Void> writeMetadataAsync(String path, KvMetadataOptions options);

  /**
   * Deletes all versions and the metadata of a secret (KV v2). Missing paths are no error.
   *
   * @param path secret path
   */
  default void deleteMetadata(String path) {
    HttpTransport.await(deleteMetadataAsync(path), "kv.deleteMetadata");
  }

  /**
   * Asynchronous deleteMetadata.
   *
   * @param path secret path
   * @return a future completed when done
   */
  CompletableFuture<Void> deleteMetadataAsync(String path);
}
