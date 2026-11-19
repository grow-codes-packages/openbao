package codes.grow.packages.openbao.integration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import codes.grow.packages.openbao.AppRoleAuth;
import codes.grow.packages.openbao.AuthInfo;
import codes.grow.packages.openbao.CreateTokenOptions;
import codes.grow.packages.openbao.JwtAuth;
import codes.grow.packages.openbao.KubernetesAuth;
import codes.grow.packages.openbao.LoginOptions;
import codes.grow.packages.openbao.OpenBaoClient;
import codes.grow.packages.openbao.RenewalEvent;
import codes.grow.packages.openbao.RenewalOptions;
import codes.grow.packages.openbao.TokenAuth;
import codes.grow.packages.openbao.TokenInfo;
import codes.grow.packages.openbao.TokenRenewer;
import codes.grow.packages.openbao.UserpassAuth;
import codes.grow.packages.openbao.core.AuthenticationException;
import codes.grow.packages.openbao.core.PermissionDeniedException;
import codes.grow.packages.openbao.core.Secret;
import codes.grow.packages.openbao.core.ValidationException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import org.junit.jupiter.api.Test;

class AuthIntegrationTest {
  private static final String ALLOWED = "sdk/allowed/hello";

  @Test
  void loginMethods() throws Exception {
    Map<String, String> env = Env.load();
    try (OpenBaoClient c = Env.anonymous(env)) {
      AuthInfo app =
          c.auth()
              .login(
                  new AppRoleAuth(
                      Env.get(env, "APPROLE_ROLE_ID"), Env.get(env, "APPROLE_SECRET_ID")));
      assertTrue(app.policies().contains("sdk-app"));
      assertEquals("sdk-app", app.metadata().get("role_name"));
      assertEquals("world", c.kv().read(ALLOWED).data().get("value"));
      assertEquals("world", c.kv("kv1").read(ALLOWED).data().get("value"));
      assertThrows(PermissionDeniedException.class, () -> c.kv().read("sdk/denied/hello"));
      assertThrows(
          AuthenticationException.class,
          () -> c.auth().login(new AppRoleAuth(Env.get(env, "APPROLE_ROLE_ID"), "wrong")));
    }
    try (OpenBaoClient c = Env.anonymous(env)) {
      AuthInfo up =
          c.auth()
              .login(
                  new UserpassAuth(
                      Env.get(env, "USERPASS_USER"), Env.get(env, "USERPASS_PASSWORD")));
      assertEquals(Env.get(env, "USERPASS_USER"), up.metadata().get("username"));
      assertEquals("world", c.kvV2("secret").read(ALLOWED).data().get("value"));
      assertThrows(
          AuthenticationException.class,
          () -> c.auth().login(new UserpassAuth(Env.get(env, "USERPASS_USER"), "nope")));
    }
    try (OpenBaoClient c = Env.anonymous(env)) {
      AuthInfo jwt =
          c.auth()
              .login(
                  new JwtAuth(Env.get(env, "JWT_ROLE"), Env.get(env, "JWT")),
                  LoginOptions.builder().setToken(true).build());
      assertEquals(Env.get(env, "JWT_ROLE"), jwt.metadata().get("role"));
      assertEquals("world", c.kvV2("secret").read(ALLOWED).data().get("value"));
      assertThrows(
          AuthenticationException.class,
          () ->
              c.auth().login(new JwtAuth(Env.get(env, "JWT_ROLE"), Env.get(env, "JWT_EXPIRED"))));
    }
    // Kubernetes: the fixture has no Kubernetes API, so the TokenReview fails (request shape only).
    Path sa = Files.createTempFile("sa", ".jwt");
    Files.writeString(sa, Env.get(env, "K8S_JWT"), StandardCharsets.UTF_8);
    try (OpenBaoClient c = Env.anonymous(env)) {
      assertThrows(
          AuthenticationException.class,
          () -> c.auth().login(new KubernetesAuth(Env.get(env, "K8S_ROLE"), sa.toString())));
      assertThrows(
          AuthenticationException.class,
          () ->
              c.auth()
                  .login(
                      KubernetesAuth.withJwt(
                          Env.get(env, "K8S_ROLE"),
                          Secret.of(Env.get(env, "K8S_JWT")),
                          Env.get(env, "K8S_MOUNT"))));
    } finally {
      Files.deleteIfExists(sa);
    }
  }

  @Test
  void tokenLifecycle() {
    Map<String, String> env = Env.load();
    try (OpenBaoClient root = Env.root(env)) {
      AuthInfo child =
          root.auth()
              .createToken(
                  CreateTokenOptions.builder()
                      .policies("sdk-app")
                      .ttl(Duration.ofHours(1))
                      .renewable(true)
                      .displayName("sdk-java")
                      .meta("run", Env.run())
                      .build());
      assertTrue(child.renewable());
      try (OpenBaoClient c = Env.anonymous(env)) {
        AuthInfo viaToken = c.auth().login(new TokenAuth(child.clientToken()));
        assertTrue(viaToken.policies().contains("sdk-app"));
        TokenInfo self = c.auth().lookupSelf();
        assertEquals("token-sdk-java", self.displayName());
        assertTrue(self.ttl().compareTo(Duration.ZERO) > 0);
        AuthInfo renewed = c.auth().renewSelf(Duration.ofMinutes(30));
        assertEquals(Duration.ofMinutes(30), renewed.leaseDuration());
        // a token without the root policy cannot create children
        assertThrows(
            PermissionDeniedException.class,
            () -> c.auth().createToken(CreateTokenOptions.builder().policies("root").build()));
        c.auth().revokeSelf();
        assertFalse(c.token().isPresent());
        c.setToken(child.clientToken().reveal());
        assertThrows(AuthenticationException.class, c::ping);
      }
      AuthInfo fixed =
          root.auth()
              .createToken(
                  CreateTokenOptions.builder().policies("sdk-app").renewable(false).build());
      try (OpenBaoClient c = Env.anonymous(env)) {
        c.setToken(fixed.clientToken());
        assertThrows(ValidationException.class, () -> c.auth().renewSelf(Duration.ofMinutes(5)));
      }
    }
  }

  @Test
  void tokenRenewerRenewsInBackground() {
    Map<String, String> env = Env.load();
    try (OpenBaoClient root = Env.root(env)) {
      AuthInfo shortToken =
          root.auth()
              .createToken(
                  CreateTokenOptions.builder()
                      .policies("sdk-app")
                      .ttl(Duration.ofSeconds(3))
                      .explicitMaxTtl(Duration.ofSeconds(30))
                      .renewable(true)
                      .build());
      OpenBaoClient sc = Env.anonymous(env);
      {
        sc.setToken(shortToken.clientToken());
        List<RenewalEvent> renewals = new CopyOnWriteArrayList<>();
        TokenRenewer r =
            sc.auth()
                .startRenewer(
                    RenewalOptions.builder()
                        .increment(Duration.ofSeconds(3))
                        .minDelay(Duration.ofMillis(200))
                        .onRenew(renewals::add)
                        .build());
        assertTrue(r.running());
        Env.eventually(Duration.ofSeconds(15), () -> renewals.size() >= 2);
        assertTrue(r.expiresAt().isPresent());
        assertTrue(sc.ping().toNanos() > 0);
        sc.close();
        assertFalse(r.running());
      }
      // login with automatic renewal
      try (OpenBaoClient c = Env.anonymous(env)) {
        AuthInfo info =
            c.auth()
                .login(
                    new UserpassAuth(
                        Env.get(env, "USERPASS_USER"), Env.get(env, "USERPASS_PASSWORD")),
                    LoginOptions.builder().autoRenew(RenewalOptions.defaults()).build());
        assertTrue(info.renewable());
        assertEquals(1, c.auth().activeRenewers());
      }
    }
  }
}
