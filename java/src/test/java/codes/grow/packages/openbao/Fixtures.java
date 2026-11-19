package codes.grow.packages.openbao;

import codes.grow.packages.openbao.core.Json;
import codes.grow.packages.openbao.core.MockServer;
import codes.grow.packages.openbao.core.RetryPolicy;
import com.fasterxml.jackson.databind.JsonNode;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.function.BooleanSupplier;

/** Loads the recorded OpenBao responses from {@code src/test/resources/fixtures}. */
final class Fixtures {
  private Fixtures() {}

  /** One recorded exchange. */
  record Fixture(int status, List<String> headers, String body, JsonNode request) {}

  static Fixture load(String name) {
    try (InputStream in = Fixtures.class.getResourceAsStream("/fixtures/" + name + ".json")) {
      if (in == null) {
        throw new IllegalArgumentException("no fixture " + name);
      }
      JsonNode root = Json.tree(in.readAllBytes());
      JsonNode resp = root.get("response");
      List<String> headers = new ArrayList<>();
      for (JsonNode h : resp.path("headers")) {
        String line = h.asText();
        int colon = line.indexOf(':');
        headers.add(line.substring(0, colon).trim());
        headers.add(line.substring(colon + 1).trim());
      }
      JsonNode body = resp.get("body");
      String text;
      if (body == null || body.isNull()) {
        text = "";
      } else if (body.isTextual()) {
        text = body.asText();
      } else {
        text = Json.stringify(body);
      }
      return new Fixture(resp.get("status").asInt(), headers, text, root.get("request"));
    } catch (IOException e) {
      throw new UncheckedIOException(e);
    }
  }

  /** Queues a recorded response. */
  static void enqueue(MockServer server, String name) {
    Fixture f = load(name);
    enqueue(server, name, f.status());
  }

  /** Queues a recorded response with another status (e.g. health with *code=200 queries). */
  static void enqueue(MockServer server, String name, int status) {
    Fixture f = load(name);
    server.enqueue(status, f.body(), f.headers().toArray(new String[0]));
  }

  /** A client against the mock server with fast retries. */
  static OpenBaoClient.Builder client(MockServer server) {
    return OpenBaoClient.builder()
        .url(server.url())
        .token("root-token-1234")
        .retry(
            RetryPolicy.builder()
                .initialBackoff(Duration.ofMillis(1))
                .maxBackoff(Duration.ofMillis(2))
                .build());
  }

  /** Waits until the condition holds (max 5 s). */
  static void eventually(BooleanSupplier condition) {
    long deadline = System.nanoTime() + Duration.ofSeconds(5).toNanos();
    while (!condition.getAsBoolean()) {
      if (System.nanoTime() > deadline) {
        throw new AssertionError("condition not met within 5 s");
      }
      try {
        Thread.sleep(5);
      } catch (InterruptedException e) {
        Thread.currentThread().interrupt();
        throw new AssertionError(e);
      }
    }
  }

  /** Manual clock and timer for renewal tests. */
  static final class FakeScheduler implements Scheduler {
    private Instant now = Instant.parse("2026-01-01T00:00:00Z");
    private final List<Task> tasks = new ArrayList<>();

    private static final class Task {
      final Instant due;
      final Runnable run;
      boolean cancelled;

      Task(Instant due, Runnable run) {
        this.due = due;
        this.run = run;
      }
    }

    @Override
    public synchronized Instant now() {
      return now;
    }

    @Override
    public synchronized Runnable schedule(Runnable task, Duration delay) {
      Task t = new Task(now.plus(delay), task);
      tasks.add(t);
      return () -> {
        synchronized (this) {
          t.cancelled = true;
        }
      };
    }

    synchronized int pending() {
      return (int) tasks.stream().filter(t -> !t.cancelled).count();
    }

    synchronized Duration nextDelay() {
      return tasks.stream()
          .filter(t -> !t.cancelled)
          .map(t -> Duration.between(now, t.due))
          .min(Duration::compareTo)
          .orElse(null);
    }

    /** Moves the clock and runs every due task (outside the lock). */
    void advance(Duration d) {
      List<Runnable> due = new ArrayList<>();
      synchronized (this) {
        now = now.plus(d);
        for (Task t : new ArrayList<>(tasks)) {
          if (!t.cancelled && !t.due.isAfter(now)) {
            tasks.remove(t);
            due.add(t.run);
          }
        }
      }
      due.forEach(Runnable::run);
    }

    /** Runs the next pending task (moving the clock to it). */
    void runNext() {
      Duration d = nextDelay();
      if (d != null) {
        advance(d.isNegative() ? Duration.ZERO : d);
      }
    }
  }
}
