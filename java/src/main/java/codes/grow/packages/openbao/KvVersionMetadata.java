package codes.grow.packages.openbao;

import com.fasterxml.jackson.databind.JsonNode;
import java.time.Instant;
import java.util.Map;
import java.util.Optional;

/**
 * Metadata of one KV v2 version.
 *
 * @param version version number
 * @param createdTime creation time
 * @param deletionTime soft-deletion time (empty when not deleted)
 * @param destroyed whether the version is destroyed
 * @param customMetadata custom metadata of the secret
 */
public record KvVersionMetadata(
    int version,
    Optional<Instant> createdTime,
    Optional<Instant> deletionTime,
    boolean destroyed,
    Map<String, String> customMetadata) {
  /**
   * Creates the record; the map is copied.
   *
   * @param version version
   * @param createdTime creation time
   * @param deletionTime deletion time
   * @param destroyed destroyed flag
   * @param customMetadata custom metadata
   */
  public KvVersionMetadata {
    customMetadata = Map.copyOf(customMetadata);
  }

  /**
   * Returns whether the version is soft-deleted or destroyed.
   *
   * @return true when the data is gone
   */
  public boolean deleted() {
    return destroyed || deletionTime.isPresent();
  }

  static KvVersionMetadata from(JsonNode m, int version) {
    return new KvVersionMetadata(
        version,
        Wire.time(m.get("created_time")),
        Wire.time(m.get("deletion_time")),
        Wire.bool(m, "destroyed"),
        Wire.stringMap(m.get("custom_metadata")));
  }

  static KvVersionMetadata from(JsonNode m) {
    return from(m, Wire.num(m, "version"));
  }
}
