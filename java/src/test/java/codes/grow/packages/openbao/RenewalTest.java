package codes.grow.packages.openbao;

import static codes.grow.packages.openbao.Fixtures.enqueue;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import codes.grow.packages.openbao.core.MockServer;
import codes.grow.packages.openbao.core.UnavailableException;
import codes.grow.packages.openbao.core.ValidationException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;

class RenewalTest {
  private static RenewalEvent ev(long ttlSeconds, boolean renewable) {
    return new RenewalEvent("", Duration.ofSeconds(ttlSeconds), renewable, false, List.of());
  }

  @Test
  void optionsDefaultsAndBounds() {
    RenewalOptions d = RenewalOptions.defaults();
    assertThat(d.increment()).isEmpty();
    assertThat(d.renewFraction()).isEqualTo(2.0 / 3);
    assertThat(d.minDelay()).isEqualTo(Duration.ofMillis(500));
    assertThat(d.scheduler()).isSameAs(Scheduler.system());
    assertThat(d.revokeOnStop()).isFalse();
    RenewalOptions o =
        RenewalOptions.builder()
            .renewFraction(1.5)
            .minDelay(Duration.ofSeconds(-1))
            .increment(Duration.ofMinutes(1))
            .revokeOnStop(true)
            .build();
    assertThat(o.renewFraction()).isEqualTo(2.0 / 3);
    assertThat(o.minDelay()).isZero();
    assertThat(o.increment()).contains(Duration.ofMinutes(1));
    assertThat(RenewalOptions.builder().renewFraction(0).build().renewFraction())
        .isEqualTo(2.0 / 3);
    assertThat(RenewalOptions.builder().renewFraction(0.5).build().renewFraction()).isEqualTo(0.5);
  }

  @Test
  void renewsUntilCappedThenExpiresOnce() {
    Fixtures.FakeScheduler clock = new Fixtures.FakeScheduler();
    List<RenewalEvent> renewed = new ArrayList<>();
    AtomicInteger expired = new AtomicInteger();
    AtomicInteger internalExpired = new AtomicInteger();
    List<RenewalEvent> answers = new ArrayList<>(List.of(ev(60, true), ev(20, true)));
    RenewalOptions o =
        RenewalOptions.builder()
            .scheduler(clock)
            .onRenew(
                e -> {
                  renewed.add(e);
                  throw new IllegalStateException("ignored");
                })
            .onExpire(expired::incrementAndGet)
            .build();
    RenewalLoop loop =
        new RenewalLoop(
            o,
            inc -> CompletableFuture.completedFuture(answers.remove(0)),
            null,
            internalExpired::incrementAndGet);
    loop.start(Duration.ofSeconds(60), true);
    assertThat(loop.running()).isTrue();
    assertThat(loop.expiresAt()).isEqualTo(clock.now().plusSeconds(60));
    assertThat(clock.nextDelay()).isEqualTo(Duration.ofSeconds(40));
    clock.advance(Duration.ofSeconds(40));
    assertThat(renewed).hasSize(1);
    // second renewal grants less than the baseline: capped -> expire at the end
    clock.advance(Duration.ofSeconds(40));
    assertThat(renewed).hasSize(2);
    assertThat(clock.nextDelay()).isEqualTo(Duration.ofSeconds(20));
    clock.advance(Duration.ofSeconds(20));
    assertThat(expired).hasValue(1);
    assertThat(internalExpired).hasValue(1);
    assertThat(loop.expired()).isTrue();
    assertThat(loop.running()).isFalse();
    clock.advance(Duration.ofHours(1));
    assertThat(expired).hasValue(1);
  }

  @Test
  void neverExpiringTokenSchedulesNothing() {
    Fixtures.FakeScheduler clock = new Fixtures.FakeScheduler();
    RenewalLoop loop =
        new RenewalLoop(
            RenewalOptions.builder().scheduler(clock).build(),
            inc -> CompletableFuture.completedFuture(ev(1, true)),
            null,
            null);
    loop.start(Duration.ZERO, true);
    assertThat(clock.pending()).isZero();
    assertThat(loop.expiresAt()).isNull();
  }

  @Test
  void notRenewableExpiresAtTtl() {
    Fixtures.FakeScheduler clock = new Fixtures.FakeScheduler();
    AtomicInteger expired = new AtomicInteger();
    RenewalLoop loop =
        new RenewalLoop(
            RenewalOptions.builder()
                .scheduler(clock)
                .onExpire(
                    () -> {
                      expired.incrementAndGet();
                      throw new IllegalStateException("ignored");
                    })
                .build(),
            inc -> CompletableFuture.completedFuture(ev(1, true)),
            null,
            null);
    loop.start(Duration.ofSeconds(10), false);
    assertThat(clock.nextDelay()).isEqualTo(Duration.ofSeconds(10));
    clock.advance(Duration.ofSeconds(10));
    assertThat(expired).hasValue(1);
  }

  @Test
  void retryableFailureRetriesHalfway() {
    Fixtures.FakeScheduler clock = new Fixtures.FakeScheduler();
    List<Throwable> errors = new ArrayList<>();
    AtomicInteger calls = new AtomicInteger();
    RenewalLoop loop =
        new RenewalLoop(
            RenewalOptions.builder()
                .scheduler(clock)
                .increment(Duration.ofSeconds(60))
                .onError(
                    e -> {
                      errors.add(e);
                      throw new IllegalStateException("ignored");
                    })
                .build(),
            inc -> {
              if (calls.incrementAndGet() == 1) {
                return CompletableFuture.failedFuture(new UnavailableException("down"));
              }
              if (calls.get() == 2) {
                throw new IllegalStateException("sync failure");
              }
              return CompletableFuture.completedFuture(ev(60, true));
            },
            null,
            null);
    loop.start(Duration.ofSeconds(60), true);
    clock.advance(Duration.ofSeconds(40));
    assertThat(errors).hasSize(1);
    // 20 s left -> retry after 10 s
    assertThat(clock.nextDelay()).isEqualTo(Duration.ofSeconds(10));
    clock.advance(Duration.ofSeconds(10));
    // synchronous exception -> not retryable (UnavailableException is, IllegalState maps to
    // unavailable as well) -> retried again halfway
    assertThat(errors).hasSize(2);
    clock.runNext();
    assertThat(calls).hasValue(3);
    loop.stop();
    loop.stop();
    assertThat(clock.pending()).isZero();
  }

  @Test
  void nonRetryableFailureExpires() {
    Fixtures.FakeScheduler clock = new Fixtures.FakeScheduler();
    AtomicInteger expired = new AtomicInteger();
    RenewalLoop loop =
        new RenewalLoop(
            RenewalOptions.builder().scheduler(clock).onExpire(expired::incrementAndGet).build(),
            inc ->
                CompletableFuture.failedFuture(new ValidationException("lease is not renewable")),
            null,
            null);
    loop.start(Duration.ofSeconds(30), true);
    clock.advance(Duration.ofSeconds(20));
    assertThat(clock.nextDelay()).isEqualTo(Duration.ofSeconds(10));
    clock.advance(Duration.ofSeconds(10));
    assertThat(expired).hasValue(1);
  }

  @Test
  void reacquireWhenNotRenewable() {
    Fixtures.FakeScheduler clock = new Fixtures.FakeScheduler();
    AtomicInteger logins = new AtomicInteger();
    List<RenewalEvent> renewed = new ArrayList<>();
    AtomicInteger expired = new AtomicInteger();
    RenewalLoop loop =
        new RenewalLoop(
            RenewalOptions.builder()
                .scheduler(clock)
                .onRenew(renewed::add)
                .onExpire(expired::incrementAndGet)
                .build(),
            inc -> CompletableFuture.completedFuture(ev(1, false)),
            () -> {
              int n = logins.incrementAndGet();
              if (n == 2) {
                return CompletableFuture.failedFuture(new UnavailableException("down"));
              }
              if (n >= 3) {
                return CompletableFuture.failedFuture(new ValidationException("bad"));
              }
              return CompletableFuture.completedFuture(
                  new RenewalEvent("", Duration.ofSeconds(30), false, true, List.of()));
            },
            null);
    loop.start(Duration.ofSeconds(30), false);
    assertThat(clock.nextDelay()).isEqualTo(Duration.ofSeconds(20));
    clock.advance(Duration.ofSeconds(20));
    assertThat(logins).hasValue(1);
    assertThat(renewed.get(0).reauthenticated()).isTrue();
    clock.advance(Duration.ofSeconds(20));
    assertThat(logins).hasValue(2);
    // 10 s left, retry halfway (5 s)
    assertThat(clock.nextDelay()).isEqualTo(Duration.ofSeconds(5));
    clock.advance(Duration.ofSeconds(5));
    assertThat(logins).hasValue(3);
    clock.advance(Duration.ofSeconds(2));
    clock.runNext();
    clock.runNext();
    assertThat(expired.get()).isLessThanOrEqualTo(1);
    Fixtures.eventually(() -> loop.expired() || logins.get() > 3);
  }

  @Test
  void stopDuringRenewalIgnoresResult() {
    Fixtures.FakeScheduler clock = new Fixtures.FakeScheduler();
    CompletableFuture<RenewalEvent> pending = new CompletableFuture<>();
    List<RenewalEvent> renewed = new ArrayList<>();
    RenewalLoop loop =
        new RenewalLoop(
            RenewalOptions.builder().scheduler(clock).onRenew(renewed::add).build(),
            inc -> pending,
            () -> pending,
            null);
    loop.start(Duration.ofSeconds(3), true);
    clock.advance(Duration.ofSeconds(2));
    loop.stop();
    pending.complete(ev(60, true));
    assertThat(renewed).isEmpty();
    // a timer that fires after stop does nothing
    RenewalLoop loop2 =
        new RenewalLoop(
            RenewalOptions.builder().scheduler(clock).build(),
            inc -> CompletableFuture.completedFuture(ev(60, true)),
            null,
            null);
    loop2.start(Duration.ofSeconds(3), false);
    loop2.stop();
    clock.advance(Duration.ofSeconds(10));
    assertThat(loop2.expired()).isFalse();
  }

  @Test
  void systemSchedulerRunsAndCancels() throws Exception {
    Scheduler s = Scheduler.system();
    assertThat(s.now()).isNotNull();
    CompletableFuture<Boolean> ran = new CompletableFuture<>();
    s.schedule(() -> ran.complete(true), Duration.ofMillis(1));
    assertThat(ran.get()).isTrue();
    AtomicInteger never = new AtomicInteger();
    Runnable cancel = s.schedule(never::incrementAndGet, Duration.ofSeconds(30));
    cancel.run();
    assertThat(never).hasValue(0);
  }

  @Test
  void leaseManageRenewsAndRevokesOnStop() throws Exception {
    try (MockServer server = MockServer.start();
        OpenBaoClient client = Fixtures.client(server).build()) {
      Fixtures.FakeScheduler clock = new Fixtures.FakeScheduler();
      enqueue(server, "database.getCredentials.ok");
      Lease<DatabaseCredentials> lease = client.database().getCredentials("ro");
      List<RenewalEvent> renewed = new ArrayList<>();
      ManagedLease m =
          client
              .leases()
              .manage(
                  lease,
                  RenewalOptions.builder()
                      .scheduler(clock)
                      .onRenew(renewed::add)
                      .revokeOnStop(true)
                      .build());
      assertThat(m.leaseId()).isEqualTo(lease.leaseId());
      assertThat(m.running()).isTrue();
      assertThat(m.expired()).isFalse();
      assertThat(m.expiresAt()).isPresent();
      assertThat(m.toString()).contains(lease.leaseId());
      assertThat(client.leases().activeLeases()).isEqualTo(1);
      enqueue(server, "leases.renew.ok");
      clock.advance(Duration.ofSeconds(2400));
      Fixtures.eventually(() -> renewed.size() == 1);
      assertThat(renewed.get(0).leaseId()).isEqualTo(lease.leaseId());
      enqueue(server, "leases.revoke.ok");
      m.close();
      m.close();
      assertThat(m.running()).isFalse();
      assertThat(client.leases().activeLeases()).isZero();
      assertThat(server.requests().get(server.requests().size() - 1).uri())
          .isEqualTo("/v1/sys/leases/revoke");
    }
  }

  @Test
  void leaseManageExpiryAndRevokeErrors() throws Exception {
    try (MockServer server = MockServer.start();
        OpenBaoClient client = Fixtures.client(server).build()) {
      Fixtures.FakeScheduler clock = new Fixtures.FakeScheduler();
      AtomicInteger expired = new AtomicInteger();
      List<Throwable> errors = new ArrayList<>();
      Lease<String> lease =
          new Lease<>("db/creds/x/1", Duration.ofSeconds(10), false, "d", List.of());
      ManagedLease m =
          client
              .leases()
              .manage(
                  lease,
                  RenewalOptions.builder()
                      .scheduler(clock)
                      .onExpire(expired::incrementAndGet)
                      .revokeOnStop(true)
                      .build());
      clock.advance(Duration.ofSeconds(10));
      assertThat(expired).hasValue(1);
      assertThat(m.expired()).isTrue();
      assertThat(client.leases().activeLeases()).isZero();
      m.close(); // expired: no revoke request
      assertThat(server.requests()).isEmpty();

      ManagedLease m2 =
          client
              .leases()
              .manage(
                  lease,
                  RenewalOptions.builder()
                      .scheduler(clock)
                      .revokeOnStop(true)
                      .onError(
                          e -> {
                            errors.add(e);
                            throw new IllegalStateException("ignored");
                          })
                      .build());
      enqueue(server, "leases.renew.not-found");
      m2.stopAsync().join();
      assertThat(errors).hasSize(1);
      ManagedLease m3 =
          client
              .leases()
              .manage(lease, RenewalOptions.builder().scheduler(clock).revokeOnStop(true).build());
      enqueue(server, "leases.renew.not-found");
      client.leases().stopAll();
      assertThat(m3.running()).isFalse();
      assertThatThrownBy(
              () ->
                  client
                      .leases()
                      .manage(
                          new Lease<>("", Duration.ZERO, false, "", List.of()),
                          RenewalOptions.defaults()))
          .isInstanceOf(ValidationException.class);
    }
  }
}
