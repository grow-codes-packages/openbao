package codes.grow.packages.openbao;

import java.util.Optional;

/** Options of {@link Auth#login(AuthMethod, LoginOptions)}. */
public final class LoginOptions {
  private static final LoginOptions DEFAULTS = builder().build();

  private final boolean setToken;
  private final RenewalOptions autoRenew;

  private LoginOptions(Builder b) {
    this.setToken = b.setToken;
    this.autoRenew = b.autoRenew;
  }

  /**
   * Returns the defaults: use the new token for the client, no automatic renewal.
   *
   * @return the defaults
   */
  public static LoginOptions defaults() {
    return DEFAULTS;
  }

  /**
   * Starts a builder.
   *
   * @return a new builder
   */
  public static Builder builder() {
    return new Builder();
  }

  /**
   * Returns whether the client switches to the new token.
   *
   * @return the flag (default true)
   */
  public boolean setToken() {
    return setToken;
  }

  /**
   * Returns the renewal options when automatic renewal is on.
   *
   * @return the options, or empty
   */
  public Optional<RenewalOptions> autoRenew() {
    return Optional.ofNullable(autoRenew);
  }

  /** Builder of {@link LoginOptions}. */
  public static final class Builder {
    private boolean setToken = true;
    private RenewalOptions autoRenew;

    private Builder() {}

    /**
     * Sets whether the client switches to the new token (default true).
     *
     * @param setToken flag
     * @return this builder
     */
    public Builder setToken(boolean setToken) {
      this.setToken = setToken;
      return this;
    }

    /**
     * Starts a {@link TokenRenewer} that renews the token and logs in again with the same method
     * when it cannot be renewed any more.
     *
     * @param options renewal options
     * @return this builder
     */
    public Builder autoRenew(RenewalOptions options) {
      this.autoRenew = options;
      return this;
    }

    /**
     * Builds the options.
     *
     * @return the options
     */
    public LoginOptions build() {
      return new LoginOptions(this);
    }
  }
}
