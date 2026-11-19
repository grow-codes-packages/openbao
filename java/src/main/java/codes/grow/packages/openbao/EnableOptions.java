package codes.grow.packages.openbao;

import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Options of {@link Sys#enableSecretsEngine} and {@link Sys#enableAuthMethod} ({@code options} and
 * {@code sealWrap} apply to secrets engines only).
 */
public final class EnableOptions {
  private static final EnableOptions NONE = builder().build();

  final String description;
  final Map<String, String> options;
  final Duration defaultLeaseTtl;
  final Duration maxLeaseTtl;
  final Boolean local;
  final Boolean sealWrap;

  private EnableOptions(Builder b) {
    this.description = b.description;
    this.options = b.options.isEmpty() ? null : Map.copyOf(b.options);
    this.defaultLeaseTtl = b.defaultLeaseTtl;
    this.maxLeaseTtl = b.maxLeaseTtl;
    this.local = b.local;
    this.sealWrap = b.sealWrap;
  }

  /**
   * Returns the empty options.
   *
   * @return the defaults
   */
  public static EnableOptions none() {
    return NONE;
  }

  /**
   * Starts a builder.
   *
   * @return a new builder
   */
  public static Builder builder() {
    return new Builder();
  }

  Map<String, Object> config() {
    Map<String, Object> c =
        Wire.body()
            .put("default_lease_ttl", Wire.optDuration(defaultLeaseTtl))
            .put("max_lease_ttl", Wire.optDuration(maxLeaseTtl))
            .build();
    return c.isEmpty() ? null : c;
  }

  /** Builder of {@link EnableOptions}. */
  public static final class Builder {
    private String description;
    private final Map<String, String> options = new LinkedHashMap<>();
    private Duration defaultLeaseTtl;
    private Duration maxLeaseTtl;
    private Boolean local;
    private Boolean sealWrap;

    private Builder() {}

    /**
     * Sets the description.
     *
     * @param description text
     * @return this builder
     */
    public Builder description(String description) {
      this.description = description;
      return this;
    }

    /**
     * Adds an engine option (e.g. {@code version} = {@code 2} for KV v2).
     *
     * @param key key
     * @param value value
     * @return this builder
     */
    public Builder option(String key, String value) {
      this.options.put(key, value);
      return this;
    }

    /**
     * Sets the default lease TTL.
     *
     * @param ttl TTL
     * @return this builder
     */
    public Builder defaultLeaseTtl(Duration ttl) {
      this.defaultLeaseTtl = ttl;
      return this;
    }

    /**
     * Sets the maximum lease TTL.
     *
     * @param ttl TTL
     * @return this builder
     */
    public Builder maxLeaseTtl(Duration ttl) {
      this.maxLeaseTtl = ttl;
      return this;
    }

    /**
     * Makes the mount local (not replicated).
     *
     * @param local flag
     * @return this builder
     */
    public Builder local(boolean local) {
      this.local = local;
      return this;
    }

    /**
     * Enables seal wrapping.
     *
     * @param sealWrap flag
     * @return this builder
     */
    public Builder sealWrap(boolean sealWrap) {
      this.sealWrap = sealWrap;
      return this;
    }

    /**
     * Builds the options.
     *
     * @return the options
     */
    public EnableOptions build() {
      return new EnableOptions(this);
    }
  }
}
