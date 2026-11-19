package codes.grow.packages.openbao.integration;

import static org.junit.jupiter.api.Assumptions.assumeTrue;

import codes.grow.packages.openbao.OpenBaoClient;
import codes.grow.packages.openbao.core.EnvReader;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.Map;
import java.util.function.BooleanSupplier;

/** Environment of the Docker suite: {@code /bootstrap/env} plus {@code GROW_OPENBAO_URL}. */
final class Env {
  private static final SecureRandom RANDOM = new SecureRandom();

  private Env() {}

  static Map<String, String> load() {
    try {
      Map<String, String> env = ConformanceTest.environment();
      String urlVariable = EnvReader.DEFAULT_PREFIX + "URL";
      assumeTrue(env.containsKey(urlVariable), urlVariable + " is not set; use docker/compose.yml");
      return env;
    } catch (IOException e) {
      throw new UncheckedIOException(e);
    }
  }

  static String get(Map<String, String> env, String name) {
    String v = env.get("GROW_OPENBAO_TEST_" + name);
    if (v == null) {
      throw new IllegalStateException("missing GROW_OPENBAO_TEST_" + name);
    }
    return v;
  }

  /** Root client from the bootstrap token. */
  static OpenBaoClient root(Map<String, String> env) {
    return OpenBaoClient.builder().fromEnv(EnvReader.of(env)).build();
  }

  /** A client of the same server without a token. */
  static OpenBaoClient anonymous(Map<String, String> env) {
    return OpenBaoClient.builder().url(env.get(EnvReader.DEFAULT_PREFIX + "URL")).build();
  }

  static String run() {
    StringBuilder sb = new StringBuilder();
    for (int i = 0; i < 8; i++) {
      sb.append((char) ('a' + RANDOM.nextInt(26)));
    }
    return sb.toString();
  }

  static void eventually(Duration timeout, BooleanSupplier condition) {
    long deadline = System.nanoTime() + timeout.toNanos();
    while (!condition.getAsBoolean()) {
      if (System.nanoTime() > deadline) {
        throw new AssertionError("condition not met within " + timeout);
      }
      try {
        Thread.sleep(100);
      } catch (InterruptedException e) {
        Thread.currentThread().interrupt();
        throw new AssertionError(e);
      }
    }
  }
}
