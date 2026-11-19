package codes.grow.packages.openbao;

import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Options of {@link Sys#generateSecretId(String, SecretIdOptions)}. */
public final class SecretIdOptions {
  private static final SecretIdOptions NONE = builder().build();

  final String mount;
  final Map<String, String> metadata;
  final List<String> cidrList;
  final Duration ttl;
  final Integer numUses;

  private SecretIdOptions(Builder b) {
    this.mount = b.mount;
    this.metadata = b.metadata.isEmpty() ? null : Map.copyOf(b.metadata);
    this.cidrList = b.cidrList;
    this.ttl = b.ttl;
    this.numUses = b.numUses;
  }

  /**
   * Returns the empty options (mount {@code approle}).
   *
   * @return the defaults
   */
  public static SecretIdOptions none() {
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

  /** Builder of {@link SecretIdOptions}. */
  public static final class Builder {
    private String mount = "approle";
    private final Map<String, String> metadata = new LinkedHashMap<>();
    private List<String> cidrList;
    private Duration ttl;
    private Integer numUses;

    private Builder() {}

    /**
     * Sets the AppRole mount (default {@code approle}).
     *
     * @param mount mount path
     * @return this builder
     */
    public Builder mount(String mount) {
      this.mount = mount;
      return this;
    }

    /**
     * Adds a metadata entry (attached to tokens issued with this secret id).
     *
     * @param key key
     * @param value value
     * @return this builder
     */
    public Builder metadata(String key, String value) {
      this.metadata.put(key, value);
      return this;
    }

    /**
     * Restricts the secret id to CIDR blocks.
     *
     * @param cidrs blocks
     * @return this builder
     */
    public Builder cidrList(String... cidrs) {
      this.cidrList = List.of(cidrs);
      return this;
    }

    /**
     * Sets the TTL of the secret id.
     *
     * @param ttl TTL
     * @return this builder
     */
    public Builder ttl(Duration ttl) {
      this.ttl = ttl;
      return this;
    }

    /**
     * Sets the uses of the secret id (0 = unlimited).
     *
     * @param numUses uses
     * @return this builder
     */
    public Builder numUses(int numUses) {
      this.numUses = numUses;
      return this;
    }

    /**
     * Builds the options.
     *
     * @return the options
     */
    public SecretIdOptions build() {
      return new SecretIdOptions(this);
    }
  }
}
