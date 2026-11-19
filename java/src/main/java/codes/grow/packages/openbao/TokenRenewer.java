package codes.grow.packages.openbao;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Renews the client token in the background ({@code auth/token/renew-self} at 2/3 of the TTL). When
 * the token cannot be renewed any more it logs in again (when a re-login method is set) or calls
 * {@code onExpire} once at expiry. Stopped by {@link #close()} or {@link OpenBaoClient#close()}.
 */
public final class TokenRenewer implements AutoCloseable {
  private final Auth auth;
  private final RenewalLoop loop;
  private final AtomicBoolean started = new AtomicBoolean();

  TokenRenewer(Auth auth, RenewalOptions options, AuthMethod reauth) {
    this.auth = auth;
    this.loop =
        new RenewalLoop(
            options,
            increment ->
                auth.renewSelfAsync(increment)
                    .thenApply(
                        i ->
                            new RenewalEvent(
                                "", i.leaseDuration(), i.renewable(), false, List.of())),
            reauth == null
                ? null
                : () ->
                    auth.loginAsync(reauth, LoginOptions.defaults())
                        .thenApply(
                            i ->
                                new RenewalEvent(
                                    "", i.leaseDuration(), i.renewable(), true, List.of())),
            null);
  }

  CompletableFuture<TokenRenewer> start(AuthInfo initial) {
    if (!started.compareAndSet(false, true)) {
      return CompletableFuture.completedFuture(this);
    }
    if (initial != null) {
      loop.start(initial.leaseDuration(), initial.renewable());
      return CompletableFuture.completedFuture(this);
    }
    return auth.lookupSelfAsync()
        .thenApply(
            info -> {
              loop.start(info.ttl(), info.renewable());
              return this;
            });
  }

  /**
   * Returns whether the renewer is active.
   *
   * @return true while renewing
   */
  public boolean running() {
    return started.get() && loop.running();
  }

  /**
   * Returns whether {@code onExpire} fired.
   *
   * @return true once expired
   */
  public boolean expired() {
    return loop.expired();
  }

  /**
   * Returns the expiry of the current token.
   *
   * @return the expiry, or empty when the token never expires
   */
  public Optional<Instant> expiresAt() {
    return Optional.ofNullable(loop.expiresAt());
  }

  /** Stops renewing. Idempotent; {@code onExpire} is not called. */
  @Override
  public void close() {
    loop.stop();
    auth.forget(this);
  }
}
