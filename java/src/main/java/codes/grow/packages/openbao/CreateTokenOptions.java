package codes.grow.packages.openbao;

import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Options of {@link Auth#createToken(CreateTokenOptions)}. */
public final class CreateTokenOptions {
  final List<String> policies;
  final Duration ttl;
  final Duration explicitMaxTtl;
  final Boolean renewable;
  final String displayName;
  final Map<String, String> meta;
  final Integer numUses;
  final Boolean noParent;
  final Boolean noDefaultPolicy;
  final Duration period;
  final String role;

  private CreateTokenOptions(Builder b) {
    this.policies = b.policies == null ? null : List.copyOf(b.policies);
    this.ttl = b.ttl;
    this.explicitMaxTtl = b.explicitMaxTtl;
    this.renewable = b.renewable;
    this.displayName = b.displayName;
    this.meta = b.meta.isEmpty() ? null : Map.copyOf(b.meta);
    this.numUses = b.numUses;
    this.noParent = b.noParent;
    this.noDefaultPolicy = b.noDefaultPolicy;
    this.period = b.period;
    this.role = b.role;
  }

  /**
   * Returns the empty options (child token with the parent's policies).
   *
   * @return the defaults
   */
  public static CreateTokenOptions defaults() {
    return builder().build();
  }

  /**
   * Starts a builder.
   *
   * @return a new builder
   */
  public static Builder builder() {
    return new Builder();
  }

  /** Builder of {@link CreateTokenOptions}. */
  public static final class Builder {
    private List<String> policies;
    private Duration ttl;
    private Duration explicitMaxTtl;
    private Boolean renewable;
    private String displayName;
    private final Map<String, String> meta = new LinkedHashMap<>();
    private Integer numUses;
    private Boolean noParent;
    private Boolean noDefaultPolicy;
    private Duration period;
    private String role;

    private Builder() {}

    /**
     * Sets the policies.
     *
     * @param policies policy names
     * @return this builder
     */
    public Builder policies(String... policies) {
      this.policies = List.of(policies);
      return this;
    }

    /**
     * Sets the TTL.
     *
     * @param ttl TTL
     * @return this builder
     */
    public Builder ttl(Duration ttl) {
      this.ttl = ttl;
      return this;
    }

    /**
     * Sets the explicit maximum TTL.
     *
     * @param explicitMaxTtl maximum TTL
     * @return this builder
     */
    public Builder explicitMaxTtl(Duration explicitMaxTtl) {
      this.explicitMaxTtl = explicitMaxTtl;
      return this;
    }

    /**
     * Sets whether the token is renewable.
     *
     * @param renewable flag
     * @return this builder
     */
    public Builder renewable(boolean renewable) {
      this.renewable = renewable;
      return this;
    }

    /**
     * Sets the display name.
     *
     * @param displayName name
     * @return this builder
     */
    public Builder displayName(String displayName) {
      this.displayName = displayName;
      return this;
    }

    /**
     * Adds a metadata entry.
     *
     * @param key key
     * @param value value
     * @return this builder
     */
    public Builder meta(String key, String value) {
      this.meta.put(key, value);
      return this;
    }

    /**
     * Sets the number of uses (0 = unlimited).
     *
     * @param numUses uses, {@code >= 0}
     * @return this builder
     */
    public Builder numUses(int numUses) {
      this.numUses = numUses;
      return this;
    }

    /**
     * Creates an orphan token (needs root or sudo).
     *
     * @param noParent flag
     * @return this builder
     */
    public Builder noParent(boolean noParent) {
      this.noParent = noParent;
      return this;
    }

    /**
     * Leaves out the {@code default} policy.
     *
     * @param noDefaultPolicy flag
     * @return this builder
     */
    public Builder noDefaultPolicy(boolean noDefaultPolicy) {
      this.noDefaultPolicy = noDefaultPolicy;
      return this;
    }

    /**
     * Creates a periodic token.
     *
     * @param period renewal period
     * @return this builder
     */
    public Builder period(Duration period) {
      this.period = period;
      return this;
    }

    /**
     * Creates the token from a token role ({@code auth/token/create/<role>}).
     *
     * @param role role name
     * @return this builder
     */
    public Builder role(String role) {
      this.role = role;
      return this;
    }

    /**
     * Builds the options.
     *
     * @return the options
     */
    public CreateTokenOptions build() {
      return new CreateTokenOptions(this);
    }
  }
}
