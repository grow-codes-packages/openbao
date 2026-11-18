package codes.grow.packages.openbao;

import codes.grow.packages.openbao.core.HttpTransport;
import codes.grow.packages.openbao.core.ValidationException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Lease operations and automatic renewal: {@code client.leases()}.
 *
 * <pre>{@code
 * Lease<DatabaseCredentials> creds = client.database().getCredentials("app");
 * ManagedLease handle = client.leases().manage(creds,
 *     RenewalOptions.builder().onExpire(() -> reconnect()).build());
 * }</pre>
 */
public final class LeaseManager {
  private final ClientContext ctx;
  private final Set<ManagedLease> managed = ConcurrentHashMap.newKeySet();

  LeaseManager(ClientContext ctx) {
    this.ctx = ctx;
  }

  /**
   * Renews a lease with its default increment.
   *
   * @param leaseId lease id
   * @return the renewal
   */
  public LeaseRenewal renew(String leaseId) {
    return renew(leaseId, null);
  }

  /**
   * Renews a lease: {@code PUT sys/leases/renew}. A TTL beyond the maximum is capped (see {@code
   * warnings}); unknown or revoked leases raise {@code ValidationException}.
   *
   * @param leaseId lease id
   * @param increment requested TTL, may be null
   * @return the renewal
   */
  public LeaseRenewal renew(String leaseId, Duration increment) {
    return HttpTransport.await(renewAsync(leaseId, increment), "leases.renew");
  }

  /**
   * Asynchronous {@link #renew(String, Duration)}.
   *
   * @param leaseId lease id
   * @param increment requested TTL, may be null
   * @return a future with the renewal
   */
  public CompletableFuture<LeaseRenewal> renewAsync(String leaseId, Duration increment) {
    return Wire.async(
        () ->
            ctx.http
                .call("PUT", "sys/leases/renew", "leases.renew")
                .json(
                    Wire.body()
                        .put("lease_id", Wire.requireText(leaseId, "leaseId", "leases.renew"))
                        .put("increment", Wire.optDuration(increment))
                        .build())
                .envelope()
                .thenApply(
                    env -> {
                      if (env == null) {
                        throw Wire.unexpected("leases.renew", "empty response body");
                      }
                      String id = Wire.str(env, "lease_id");
                      return new LeaseRenewal(
                          id.isEmpty() ? leaseId : id,
                          Wire.seconds(env.get("lease_duration")),
                          Wire.bool(env, "renewable"),
                          Wire.strings(env.get("warnings")));
                    }));
  }

  /**
   * Revokes a lease now: {@code PUT sys/leases/revoke}.
   *
   * @param leaseId lease id
   */
  public void revoke(String leaseId) {
    HttpTransport.await(revokeAsync(leaseId), "leases.revoke");
  }

  /**
   * Asynchronous {@link #revoke(String)}.
   *
   * @param leaseId lease id
   * @return a future completed when revoked
   */
  public CompletableFuture<Void> revokeAsync(String leaseId) {
    return Wire.async(
        () ->
            ctx.http
                .call("PUT", "sys/leases/revoke", "leases.revoke")
                .json(Map.of("lease_id", Wire.requireText(leaseId, "leaseId", "leases.revoke")))
                .run());
  }

  /**
   * Revokes every lease under a prefix: {@code PUT sys/leases/revoke-prefix/<prefix>} (needs sudo).
   *
   * @param prefix lease id prefix, e.g. {@code database/creds/app}
   */
  public void revokePrefix(String prefix) {
    HttpTransport.await(revokePrefixAsync(prefix), "leases.revokePrefix");
  }

  /**
   * Asynchronous {@link #revokePrefix(String)}.
   *
   * @param prefix prefix
   * @return a future completed when revoked
   */
  public CompletableFuture<Void> revokePrefixAsync(String prefix) {
    return Wire.async(
        () ->
            ctx.http
                .call(
                    "PUT",
                    Wire.encodePath(
                        "sys/leases/revoke-prefix",
                        Wire.requireText(prefix, "prefix", "leases.revokePrefix")),
                    "leases.revokePrefix")
                .run());
  }

  /**
   * Lease details: {@code PUT sys/leases/lookup}. Unknown leases raise {@code ValidationException}.
   *
   * @param leaseId lease id
   * @return the details
   */
  public LeaseInfo lookup(String leaseId) {
    return HttpTransport.await(lookupAsync(leaseId), "leases.lookup");
  }

  /**
   * Asynchronous {@link #lookup(String)}.
   *
   * @param leaseId lease id
   * @return a future with the details
   */
  public CompletableFuture<LeaseInfo> lookupAsync(String leaseId) {
    return Wire.async(
        () ->
            ctx.http
                .call("PUT", "sys/leases/lookup", "leases.lookup")
                .json(Map.of("lease_id", Wire.requireText(leaseId, "leaseId", "leases.lookup")))
                .data()
                .thenApply(
                    d -> {
                      String id = Wire.str(d, "id");
                      return new LeaseInfo(
                          id.isEmpty() ? leaseId : id,
                          Wire.str(d, "path"),
                          Wire.time(d.get("issue_time")),
                          Wire.time(d.get("expire_time")),
                          Wire.time(d.get("last_renewal")),
                          Wire.bool(d, "renewable"),
                          Wire.seconds(d.get("ttl")));
                    }));
  }

  /**
   * Keeps a lease alive: renews at 2/3 of its TTL until the maximum TTL is reached, then calls
   * {@code onExpire} once when it expires. Stopped by the handle, {@link #stopAll()} or {@code
   * client.close()}.
   *
   * @param lease the lease
   * @param options renewal options
   * @return the handle
   * @throws ValidationException when the lease has no id
   */
  public ManagedLease manage(Lease<?> lease, RenewalOptions options) {
    String leaseId = lease.leaseId();
    if (leaseId == null || leaseId.isEmpty()) {
      throw new ValidationException("leases.manage: the lease has no id");
    }
    ManagedLease[] handle = new ManagedLease[1];
    RenewalLoop loop =
        new RenewalLoop(
            options,
            increment ->
                renewAsync(leaseId, increment)
                    .thenApply(
                        r ->
                            new RenewalEvent(
                                r.leaseId(),
                                r.leaseDuration(),
                                r.renewable(),
                                false,
                                r.warnings())),
            null,
            () -> managed.remove(handle[0]));
    handle[0] = new ManagedLease(leaseId, loop, options, this, managed::remove);
    managed.add(handle[0]);
    loop.start(lease.leaseDuration(), lease.renewable());
    return handle[0];
  }

  /**
   * Returns the number of managed leases.
   *
   * @return the count
   */
  public int activeLeases() {
    return managed.size();
  }

  /**
   * Stops every managed lease (revoking those with {@code revokeOnStop}). Idempotent.
   *
   * @return a future completed when every lease is stopped
   */
  public CompletableFuture<Void> stopAllAsync() {
    List<CompletableFuture<Void>> all = new ArrayList<>();
    for (ManagedLease m : new ArrayList<>(managed)) {
      all.add(m.stopAsync());
    }
    return CompletableFuture.allOf(all.toArray(new CompletableFuture<?>[0]));
  }

  /** Stops every managed lease and waits for revocations. Idempotent. */
  public void stopAll() {
    stopAllAsync().join();
  }
}
