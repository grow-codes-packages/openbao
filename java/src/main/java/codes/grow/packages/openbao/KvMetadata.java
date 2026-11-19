package codes.grow.packages.openbao;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.Optional;

/**
 * Metadata of a KV v2 secret ({@code GET <mount>/metadata/<path>}).
 *
 * @param casRequired whether writes need {@code cas}
 * @param createdTime creation time
 * @param updatedTime last update time
 * @param currentVersion current version
 * @param oldestVersion oldest kept version
 * @param maxVersions maximum versions kept (0 = mount default)
 * @param deleteVersionAfter automatic deletion delay (zero = never)
 * @param customMetadata custom metadata
 * @param versions metadata per version number
 */
public record KvMetadata(
    boolean casRequired,
    Optional<Instant> createdTime,
    Optional<Instant> updatedTime,
    int currentVersion,
    int oldestVersion,
    int maxVersions,
    Duration deleteVersionAfter,
    Map<String, String> customMetadata,
    Map<Integer, KvVersionMetadata> versions) {
  /**
   * Creates the record; maps are copied.
   *
   * @param casRequired cas flag
   * @param createdTime creation time
   * @param updatedTime update time
   * @param currentVersion current version
   * @param oldestVersion oldest version
   * @param maxVersions max versions
   * @param deleteVersionAfter deletion delay
   * @param customMetadata custom metadata
   * @param versions versions
   */
  public KvMetadata {
    customMetadata = Map.copyOf(customMetadata);
    versions = Map.copyOf(versions);
  }

  /**
   * Returns whether the current version is soft-deleted or destroyed.
   *
   * @return true when the latest data is gone
   */
  public boolean currentDeleted() {
    KvVersionMetadata v = versions.get(currentVersion);
    return v == null || v.deleted();
  }
}
