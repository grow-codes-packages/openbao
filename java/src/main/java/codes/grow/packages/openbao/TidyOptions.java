package codes.grow.packages.openbao;

import java.time.Duration;

/** Options of {@link Pki#tidy(TidyOptions)}. */
public final class TidyOptions {
  private static final TidyOptions DEFAULTS = builder().build();

  final boolean tidyCertStore;
  final boolean tidyRevokedCerts;
  final Duration safetyBuffer;
  final boolean await;
  final Duration timeout;
  final Duration interval;

  private TidyOptions(Builder b) {
    this.tidyCertStore = b.tidyCertStore;
    this.tidyRevokedCerts = b.tidyRevokedCerts;
    this.safetyBuffer = b.safetyBuffer;
    this.await = b.await;
    this.timeout = b.timeout;
    this.interval = b.interval;
  }

  /**
   * Returns the defaults: tidy the store and revoked entries, wait up to 60 s.
   *
   * @return the defaults
   */
  public static TidyOptions defaults() {
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

  /** Builder of {@link TidyOptions}. */
  public static final class Builder {
    private boolean tidyCertStore = true;
    private boolean tidyRevokedCerts = true;
    private Duration safetyBuffer;
    private boolean await = true;
    private Duration timeout = Duration.ofSeconds(60);
    private Duration interval = Duration.ofMillis(500);

    private Builder() {}

    /**
     * Removes expired certificates from the store (default true).
     *
     * @param tidy flag
     * @return this builder
     */
    public Builder tidyCertStore(boolean tidy) {
      this.tidyCertStore = tidy;
      return this;
    }

    /**
     * Removes expired revoked entries (default true).
     *
     * @param tidy flag
     * @return this builder
     */
    public Builder tidyRevokedCerts(boolean tidy) {
      this.tidyRevokedCerts = tidy;
      return this;
    }

    /**
     * Sets how long past expiry a certificate is kept.
     *
     * @param buffer duration
     * @return this builder
     */
    public Builder safetyBuffer(Duration buffer) {
      this.safetyBuffer = buffer;
      return this;
    }

    /**
     * Waits until the run is {@code Finished}, {@code Error} or {@code Cancelled} (default true).
     *
     * @param await flag
     * @return this builder
     */
    public Builder await(boolean await) {
      this.await = await;
      return this;
    }

    /**
     * Sets the maximum wait (default 60 s).
     *
     * @param timeout duration
     * @return this builder
     */
    public Builder timeout(Duration timeout) {
      this.timeout = timeout;
      return this;
    }

    /**
     * Sets the poll interval (default 500 ms).
     *
     * @param interval duration
     * @return this builder
     */
    public Builder interval(Duration interval) {
      this.interval = interval;
      return this;
    }

    /**
     * Builds the options.
     *
     * @return the options
     */
    public TidyOptions build() {
      return new TidyOptions(this);
    }
  }
}
