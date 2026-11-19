package codes.grow.packages.openbao;

import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

/**
 * Clock and timer used by {@link TokenRenewer} and {@link LeaseManager}. The default {@link
 * #system()} uses one shared daemon thread; tests inject a fake to control time.
 */
public interface Scheduler {
  /**
   * Returns the current time.
   *
   * @return now
   */
  Instant now();

  /**
   * Runs {@code task} once after {@code delay}.
   *
   * @param task task to run
   * @param delay delay (zero or positive)
   * @return a handle; running it cancels the task
   */
  Runnable schedule(Runnable task, Duration delay);

  /**
   * Returns the system scheduler (wall clock, shared daemon timer thread).
   *
   * @return the scheduler
   */
  static Scheduler system() {
    return SystemScheduler.INSTANCE;
  }

  /** Wall clock + one shared daemon thread. */
  final class SystemScheduler implements Scheduler {
    static final SystemScheduler INSTANCE = new SystemScheduler();
    private final ScheduledThreadPoolExecutor executor;

    private SystemScheduler() {
      executor =
          new ScheduledThreadPoolExecutor(
              1,
              r -> {
                Thread t = new Thread(r, "openbao-renewal");
                t.setDaemon(true);
                return t;
              });
      executor.setRemoveOnCancelPolicy(true);
    }

    @Override
    public Instant now() {
      return Instant.now();
    }

    @Override
    public Runnable schedule(Runnable task, Duration delay) {
      ScheduledFuture<?> f =
          executor.schedule(task, Math.max(0, delay.toNanos()), TimeUnit.NANOSECONDS);
      return () -> f.cancel(false);
    }
  }
}
