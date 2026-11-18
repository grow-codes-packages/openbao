package codes.grow.packages.openbao;

import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;

/** Options of {@link Kv#writeMetadata(String, KvMetadataOptions)} (KV v2). */
public final class KvMetadataOptions {
  final Integer maxVersions;
  final Boolean casRequired;
  final Duration deleteVersionAfter;
  final Map<String, String> customMetadata;

  private KvMetadataOptions(Builder b) {
    this.maxVersions = b.maxVersions;
    this.casRequired = b.casRequired;
    this.deleteVersionAfter = b.deleteVersionAfter;
    this.customMetadata = b.customMetadata == null ? null : Map.copyOf(b.customMetadata);
  }

  /**
   * Starts a builder.
   *
   * @return a new builder
   */
  public static Builder builder() {
    return new Builder();
  }

  /** Builder of {@link KvMetadataOptions}. */
  public static final class Builder {
    private Integer maxVersions;
    private Boolean casRequired;
    private Duration deleteVersionAfter;
    private Map<String, String> customMetadata;

    private Builder() {}

    /**
     * Sets the maximum number of versions kept.
     *
     * @param maxVersions count (0 = mount default)
     * @return this builder
     */
    public Builder maxVersions(int maxVersions) {
      this.maxVersions = maxVersions;
      return this;
    }

    /**
     * Requires {@code cas} on every write.
     *
     * @param casRequired flag
     * @return this builder
     */
    public Builder casRequired(boolean casRequired) {
      this.casRequired = casRequired;
      return this;
    }

    /**
     * Deletes versions automatically after this delay.
     *
     * @param deleteVersionAfter delay (zero = never)
     * @return this builder
     */
    public Builder deleteVersionAfter(Duration deleteVersionAfter) {
      this.deleteVersionAfter = deleteVersionAfter;
      return this;
    }

    /**
     * Replaces the custom metadata.
     *
     * @param customMetadata key/value pairs
     * @return this builder
     */
    public Builder customMetadata(Map<String, String> customMetadata) {
      this.customMetadata = new LinkedHashMap<>(customMetadata);
      return this;
    }

    /**
     * Builds the options.
     *
     * @return the options
     */
    public KvMetadataOptions build() {
      return new KvMetadataOptions(this);
    }
  }
}
