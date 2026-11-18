package codes.grow.packages.openbao;

import java.time.Instant;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.function.Consumer;

/** Handle of a lease kept alive by {@link LeaseManager#manage(Lease, RenewalOptions)}. */
public final class ManagedLease implements AutoCloseable {
  private final String leaseId;
  private final RenewalLoop loop;
  private final boolean revokeOnStop;
  private final Consumer<ManagedLease> onStopped;
  private final LeaseManager manager;
  private final Consumer<Throwable> onError;
  private CompletableFuture<Void> stopped;

  ManagedLease(
      String leaseId,
      RenewalLoop loop,
      RenewalOptions options,
      LeaseManager manager,
      Consumer<ManagedLease> onStopped) {
    this.leaseId = leaseId;
    this.loop = loop;
    this.revokeOnStop = options.revokeOnStop();
    this.onError = options.onError();
    this.manager = manager;
    this.onStopped = onStopped;
  }

  /**
   * Returns the lease id.
   *
   * @return the id
   */
  public String leaseId() {
    return leaseId;
  }

  /**
   * Returns whether renewal is still active.
   *
   * @return true while running
   */
  public boolean running() {
    return loop.running();
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
   * Returns the expiry of the current lease.
   *
   * @return the expiry, or empty when it never expires
   */
  public Optional<Instant> expiresAt() {
    return Optional.ofNullable(loop.expiresAt());
  }

  /**
   * Stops renewing (and revokes the lease when {@code revokeOnStop}). Idempotent.
   *
   * @return a future completed when stopped (revocation errors go to {@code onError})
   */
  public synchronized CompletableFuture<Void> stopAsync() {
    if (stopped == null) {
      loop.stop();
      onStopped.accept(this);
      if (revokeOnStop && !loop.expired()) {
        stopped =
            manager
                .revokeAsync(leaseId)
                .exceptionally(
                    err -> {
                      if (onError != null) {
                        try {
                          onError.accept(err);
                        } catch (RuntimeException ignored) {
                          // callbacks never break stop
                        }
                      }
                      return null;
                    });
      } else {
        stopped = CompletableFuture.completedFuture(null);
      }
    }
    return stopped;
  }

  /** Stops renewing and waits for the optional revocation. Idempotent. */
  @Override
  public void close() {
    stopAsync().join();
  }

  @Override
  public String toString() {
    return "ManagedLease(" + leaseId + ")";
  }
}
