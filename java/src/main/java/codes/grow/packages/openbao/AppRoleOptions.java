package codes.grow.packages.openbao;

import java.time.Duration;
import java.util.List;

/** Options of {@link Sys#createAppRole(String, AppRoleOptions)}. */
public final class AppRoleOptions {
  private static final AppRoleOptions NONE = builder().build();

  final String mount;
  final List<String> tokenPolicies;
  final Duration tokenTtl;
  final Duration tokenMaxTtl;
  final Duration secretIdTtl;
  final Integer secretIdNumUses;
  final Boolean bindSecretId;
  final String tokenType;

  private AppRoleOptions(Builder b) {
    this.mount = b.mount;
    this.tokenPolicies = b.tokenPolicies;
    this.tokenTtl = b.tokenTtl;
    this.tokenMaxTtl = b.tokenMaxTtl;
    this.secretIdTtl = b.secretIdTtl;
    this.secretIdNumUses = b.secretIdNumUses;
    this.bindSecretId = b.bindSecretId;
    this.tokenType = b.tokenType;
  }

  /**
   * Returns the empty options (mount {@code approle}).
   *
   * @return the defaults
   */
  public static AppRoleOptions none() {
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

  /** Builder of {@link AppRoleOptions}. */
  public static final class Builder {
    private String mount = "approle";
    private List<String> tokenPolicies;
    private Duration tokenTtl;
    private Duration tokenMaxTtl;
    private Duration secretIdTtl;
    private Integer secretIdNumUses;
    private Boolean bindSecretId;
    private String tokenType;

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
     * Sets the policies of issued tokens.
     *
     * @param policies policy names
     * @return this builder
     */
    public Builder tokenPolicies(String... policies) {
      this.tokenPolicies = List.of(policies);
      return this;
    }

    /**
     * Sets the TTL of issued tokens.
     *
     * @param ttl TTL
     * @return this builder
     */
    public Builder tokenTtl(Duration ttl) {
      this.tokenTtl = ttl;
      return this;
    }

    /**
     * Sets the maximum TTL of issued tokens.
     *
     * @param ttl TTL
     * @return this builder
     */
    public Builder tokenMaxTtl(Duration ttl) {
      this.tokenMaxTtl = ttl;
      return this;
    }

    /**
     * Sets the TTL of secret ids.
     *
     * @param ttl TTL
     * @return this builder
     */
    public Builder secretIdTtl(Duration ttl) {
      this.secretIdTtl = ttl;
      return this;
    }

    /**
     * Sets the uses of a secret id (0 = unlimited).
     *
     * @param uses uses
     * @return this builder
     */
    public Builder secretIdNumUses(int uses) {
      this.secretIdNumUses = uses;
      return this;
    }

    /**
     * Requires a secret id at login (server default true).
     *
     * @param bind flag
     * @return this builder
     */
    public Builder bindSecretId(boolean bind) {
      this.bindSecretId = bind;
      return this;
    }

    /**
     * Sets the token type: {@code service}, {@code batch} or {@code default}.
     *
     * @param tokenType type
     * @return this builder
     */
    public Builder tokenType(String tokenType) {
      this.tokenType = tokenType;
      return this;
    }

    /**
     * Builds the options.
     *
     * @return the options
     */
    public AppRoleOptions build() {
      return new AppRoleOptions(this);
    }
  }
}
