package codes.grow.packages.openbao;

import codes.grow.packages.openbao.core.HttpTransport;
import codes.grow.packages.openbao.core.OpenBaoException;
import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.CompletableFuture;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.function.Supplier;

/**
 * Renews at {@code renewFraction} of the TTL. When the lifetime cannot be extended any more (not
 * renewable, maximum TTL reached, renewal refused) it reacquires (when configured) or calls {@code
 * onExpire} once at expiry. Retryable failures are retried halfway to the expiry.
 */
final class RenewalLoop {
  /** Slack when comparing a granted TTL with the requested one. */
  static final Duration CAP_TOLERANCE = Duration.ofSeconds(1);

  private final RenewalOptions options;
  private final Scheduler scheduler;
  private final Function<Duration, CompletableFuture<RenewalEvent>> renew;
  private final Supplier<CompletableFuture<RenewalEvent>> reacquire;
  private final Runnable onExpire;
  private Runnable timer;
  private boolean stopped;
  private boolean expired;
  private Instant expiresAt;
  private Duration baseline = Duration.ZERO;

  RenewalLoop(
      RenewalOptions options,
      Function<Duration, CompletableFuture<RenewalEvent>> renew,
      Supplier<CompletableFuture<RenewalEvent>> reacquire,
      Runnable onExpire) {
    this.options = options;
    this.scheduler = options.scheduler();
    this.renew = renew;
    this.reacquire = reacquire;
    this.onExpire = onExpire;
  }

  synchronized boolean running() {
    return !stopped;
  }

  synchronized boolean expired() {
    return expired;
  }

  synchronized Instant expiresAt() {
    return expiresAt;
  }

  synchronized void start(Duration ttl, boolean renewable) {
    baseline = ttl;
    schedule(ttl, renewable, false);
  }

  synchronized void stop() {
    stopped = true;
    clear();
  }

  private void clear() {
    if (timer != null) {
      timer.run();
      timer = null;
    }
  }

  private void at(Duration delay, Runnable fn) {
    clear();
    if (stopped) {
      return;
    }
    Runnable[] self = new Runnable[1];
    self[0] =
        scheduler.schedule(
            () -> {
              synchronized (this) {
                if (timer == self[0]) {
                  timer = null;
                }
                if (stopped) {
                  return;
                }
              }
              fn.run();
            },
            delay);
    timer = self[0];
  }

  private void schedule(Duration ttl, boolean renewable, boolean fin) {
    if (stopped) {
      return;
    }
    if (ttl.isZero() || ttl.isNegative()) {
      expiresAt = null;
      clear();
      return;
    }
    expiresAt = scheduler.now().plus(ttl);
    Duration early = max(options.minDelay(), mul(ttl, options.renewFraction()));
    if (!fin && renewable) {
      at(early, this::doRenew);
    } else if (reacquire != null) {
      at(early.compareTo(ttl) < 0 ? early : ttl, this::doReacquire);
    } else {
      at(ttl, this::expire);
    }
  }

  private Duration remaining() {
    return expiresAt == null ? Duration.ZERO : Duration.between(scheduler.now(), expiresAt);
  }

  private static Duration mul(Duration d, double f) {
    return Duration.ofNanos((long) (d.toNanos() * f));
  }

  private static Duration max(Duration a, Duration b) {
    return a.compareTo(b) >= 0 ? a : b;
  }

  private static <T> CompletableFuture<T> start(Supplier<CompletableFuture<T>> s) {
    try {
      return s.get();
    } catch (RuntimeException e) {
      return CompletableFuture.failedFuture(e);
    }
  }

  private void doRenew() {
    Duration requested = options.increment().orElse(null);
    start(() -> renew.apply(requested))
        .whenComplete(
            (state, err) -> {
              synchronized (this) {
                if (stopped) {
                  return;
                }
                if (err == null) {
                  safe(options.onRenew(), state);
                  Duration wanted = requested != null ? requested : baseline;
                  boolean capped = state.ttl().plus(CAP_TOLERANCE).compareTo(wanted) < 0;
                  schedule(state.ttl(), state.renewable(), capped || !state.renewable());
                  return;
                }
                OpenBaoException e = HttpTransport.asSdkException(err, "renewal");
                safe(options.onError(), e);
                Duration left = remaining();
                if (e.retryable() && left.compareTo(options.minDelay().multipliedBy(2)) > 0) {
                  at(left.dividedBy(2), this::doRenew);
                } else {
                  schedule(max(left, Duration.ofMillis(1)), false, true);
                }
              }
            });
  }

  private void doReacquire() {
    start(reacquire)
        .whenComplete(
            (state, err) -> {
              synchronized (this) {
                if (stopped) {
                  return;
                }
                if (err == null) {
                  baseline = state.ttl();
                  safe(options.onRenew(), state);
                  schedule(state.ttl(), state.renewable(), false);
                  return;
                }
                safe(options.onError(), HttpTransport.asSdkException(err, "renewal"));
                Duration left = remaining();
                if (left.compareTo(options.minDelay().multipliedBy(2)) > 0) {
                  at(left.dividedBy(2), this::doReacquire);
                } else {
                  at(left.isNegative() ? Duration.ZERO : left, this::expire);
                }
              }
            });
  }

  private synchronized void expire() {
    if (expired) {
      return;
    }
    expired = true;
    stopped = true;
    clear();
    if (onExpire != null) {
      safeRun(onExpire);
    }
    if (options.onExpire() != null) {
      safeRun(options.onExpire());
    }
  }

  private static <T> void safe(Consumer<T> fn, T value) {
    if (fn == null) {
      return;
    }
    try {
      fn.accept(value);
    } catch (RuntimeException ignored) {
      // callbacks never break the renewal loop
    }
  }

  private static void safeRun(Runnable r) {
    try {
      r.run();
    } catch (RuntimeException ignored) {
      // callbacks never break the renewal loop
    }
  }
}
