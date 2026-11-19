package codes.grow.packages.openbao.integration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import codes.grow.packages.openbao.HealthResponse;
import codes.grow.packages.openbao.OpenBaoClient;
import codes.grow.packages.openbao.SealStatus;
import codes.grow.packages.openbao.UnwrapResult;
import codes.grow.packages.openbao.WrapInfo;
import codes.grow.packages.openbao.WrappingLookup;
import codes.grow.packages.openbao.core.HealthStatus;
import codes.grow.packages.openbao.core.ValidationException;
import codes.grow.packages.openbao.testing.OpenBaoTesting;
import java.time.Duration;
import java.util.Map;
import org.junit.jupiter.api.Test;

class WrappingAndLifecycleTest {
  @Test
  void wrapping() {
    Map<String, String> env = Env.load();
    String secret = "wrapped-" + Env.run();
    try (OpenBaoClient c = Env.root(env)) {
      WrapInfo w = c.wrapping().wrap(Map.of("secret", secret, "n", 1), Duration.ofSeconds(60));
      assertEquals(Duration.ofSeconds(60), w.ttl());
      assertEquals("sys/wrapping/wrap", w.creationPath());
      try (OpenBaoClient anon = Env.anonymous(env)) {
        WrappingLookup l = anon.wrapping().lookupWrapping(w.token());
        assertEquals("sys/wrapping/wrap", l.creationPath());
        assertEquals(Duration.ofSeconds(60), l.creationTtl());
        UnwrapResult r = anon.wrapping().unwrap(w.token());
        assertEquals(secret, r.data().get().get("secret"));
        assertThrows(ValidationException.class, () -> anon.wrapping().unwrap(w.token()));
        assertThrows(ValidationException.class, () -> anon.wrapping().lookupWrapping(w.token()));
      }
    }
  }

  @Test
  void initUnsealSeal() {
    Map<String, String> env = Env.load();
    String url = Env.get(env, "SHAMIR_URL");
    try (OpenBaoClient c = OpenBaoClient.builder().url(url).build()) {
      HealthStatus before = c.health();
      assertFalse(before.healthy());
      assertEquals("uninitialized", before.status());
      assertFalse(OpenBaoTesting.initStatus(c));
      OpenBaoTesting.InitResult init = OpenBaoTesting.init(c, 1, 1);
      assertEquals(1, init.keys().size());
      assertTrue(OpenBaoTesting.initStatus(c));
      assertThrows(ValidationException.class, () -> OpenBaoTesting.init(c, 1, 1));
      SealStatus sealed = c.sys().sealStatus();
      assertTrue(sealed.sealed());
      assertEquals("shamir", sealed.type());
      assertEquals("sealed", c.health().status());
      assertThrows(
          ValidationException.class,
          () ->
              OpenBaoTesting.unseal(
                  c, codes.grow.packages.openbao.core.Secret.of("not-a-valid-key!")));
      SealStatus open = OpenBaoTesting.unseal(c, init.keys().get(0));
      assertFalse(open.sealed());
      HealthResponse h = OpenBaoTesting.waitForActive(c, Duration.ofSeconds(30));
      assertEquals("active", h.state());
      c.setToken(init.rootToken());
      assertTrue(c.ping().toNanos() > 0);
      OpenBaoTesting.seal(c);
      assertTrue(c.sys().sealStatus().sealed());
      OpenBaoTesting.resetUnseal(c);
      OpenBaoTesting.unseal(c, init.keysBase64().get(0));
      assertEquals("active", OpenBaoTesting.waitForActive(c, Duration.ofSeconds(30)).state());
    }
  }
}
