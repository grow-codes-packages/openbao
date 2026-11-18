package codes.grow.packages.openbao;

import java.time.Duration;
import java.util.Optional;
import java.util.function.Consumer;

/**
 * Options of {@link TokenRenewer} and {@link LeaseManager#manage}: renew at {@code renewFraction}
 * of the TTL (default 2/3) until the maximum TTL is reached, then call {@code onExpire} once at
 * expiry (or log in again for a token renewer with a re-login method).
 */
public final class RenewalOptions {
  private static final RenewalOptions DEFAULTS = builder().build();

  private final Duration increment;
  private final double renewFraction;
  private final Duration minDelay;
  private final Consumer<Throwable> onError;
  private final Runnable onExpire;
  private final Consumer<RenewalEvent> onRenew;
  private final Scheduler scheduler;
  private final boolean revokeOnStop;

  private RenewalOptions(Builder b) {
    this.increment = b.increment;
    this.renewFraction = b.renewFraction > 0 && b.renewFraction < 1 ? b.renewFraction : 2.0 / 3;
    this.minDelay = b.minDelay.isNegative() ? Duration.ZERO : b.minDelay;
    this.onError = b.onError;
    this.onExpire = b.onExpire;
    this.onRenew = b.onRenew;
    this.scheduler = b.scheduler != null ? b.scheduler : Scheduler.system();
    this.revokeOnStop = b.revokeOnStop;
  }

  /**
   * Returns the defaults.
   *
   * @return the default options
   */
  public static RenewalOptions defaults() {
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
   * Returns the TTL requested on each renewal.
   *
   * @return the increment, or empty to keep the server default
   */
  public Optional<Duration> increment() {
    return Optional.ofNullable(increment);
  }

  /**
   * Returns the fraction of the TTL after which a renewal runs.
   *
   * @return a value in (0, 1), default 2/3
   */
  public double renewFraction() {
    return renewFraction;
  }

  /**
   * Returns the minimum delay between two renewals.
   *
   * @return the delay (default 500 ms)
   */
  public Duration minDelay() {
    return minDelay;
  }

  /**
   * Returns the scheduler.
   *
   * @return the scheduler
   */
  public Scheduler scheduler() {
    return scheduler;
  }

  /**
   * Returns whether a managed lease is revoked when stopped.
   *
   * @return the flag (default false)
   */
  public boolean revokeOnStop() {
    return revokeOnStop;
  }

  Consumer<Throwable> onError() {
    return onError;
  }

  Runnable onExpire() {
    return onExpire;
  }

  Consumer<RenewalEvent> onRenew() {
    return onRenew;
  }

  /** Builder of {@link RenewalOptions}. */
  public static final class Builder {
    private Duration increment;
    private double renewFraction = 2.0 / 3;
    private Duration minDelay = Duration.ofMillis(500);
    private Consumer<Throwable> onError;
    private Runnable onExpire;
    private Consumer<RenewalEvent> onRenew;
    private Scheduler scheduler;
    private boolean revokeOnStop;

    private Builder() {}

    /**
     * Sets the TTL requested on each renewal.
     *
     * @param increment requested TTL
     * @return this builder
     */
    public Builder increment(Duration increment) {
      this.increment = increment;
      return this;
    }

    /**
     * Sets the fraction of the TTL after which a renewal runs (default 2/3).
     *
     * @param renewFraction value in (0, 1); other values fall back to 2/3
     * @return this builder
     */
    public Builder renewFraction(double renewFraction) {
      this.renewFraction = renewFraction;
      return this;
    }

    /**
     * Sets the minimum delay between renewals (default 500 ms).
     *
     * @param minDelay delay
     * @return this builder
     */
    public Builder minDelay(Duration minDelay) {
      this.minDelay = minDelay;
      return this;
    }

    /**
     * Sets the callback for renewal failures (the loop keeps going while time is left).
     *
     * @param onError callback
     * @return this builder
     */
    public Builder onError(Consumer<Throwable> onError) {
      this.onError = onError;
      return this;
    }

    /**
     * Sets the callback run once when the token or lease expires for good.
     *
     * @param onExpire callback
     * @return this builder
     */
    public Builder onExpire(Runnable onExpire) {
      this.onExpire = onExpire;
      return this;
    }

    /**
     * Sets the callback run after every successful renewal or re-login.
     *
     * @param onRenew callback
     * @return this builder
     */
    public Builder onRenew(Consumer<RenewalEvent> onRenew) {
      this.onRenew = onRenew;
      return this;
    }

    /**
     * Sets the scheduler (tests).
     *
     * @param scheduler scheduler
     * @return this builder
     */
    public Builder scheduler(Scheduler scheduler) {
      this.scheduler = scheduler;
      return this;
    }

    /**
     * Revokes a managed lease when it is stopped or the client closes (default false).
     *
     * @param revokeOnStop flag
     * @return this builder
     */
    public Builder revokeOnStop(boolean revokeOnStop) {
      this.revokeOnStop = revokeOnStop;
      return this;
    }

    /**
     * Builds the options.
     *
     * @return the options
     */
    public RenewalOptions build() {
      return new RenewalOptions(this);
    }
  }
}
