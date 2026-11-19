package codes.grow.packages.openbao;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

/**
 * A KV secret: its data map (any JSON values) and, on KV v2, the version metadata. {@link
 * #toString()} never prints the data.
 *
 * @param data secret data (unmodifiable)
 * @param metadata version metadata (KV v2 only)
 */
public record KvSecret(Map<String, Object> data, Optional<KvVersionMetadata> metadata) {
  /**
   * Creates the record; the data map is copied (null values allowed).
   *
   * @param data data
   * @param metadata metadata
   */
  public KvSecret {
    data = Collections.unmodifiableMap(new LinkedHashMap<>(data));
  }

  @Override
  public String toString() {
    return "KvSecret{data=[REDACTED], metadata=" + metadata + "}";
  }
}
