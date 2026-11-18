package codes.grow.packages.openbao.integration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import codes.grow.packages.openbao.AppRoleAuth;
import codes.grow.packages.openbao.AppRoleOptions;
import codes.grow.packages.openbao.AuthInfo;
import codes.grow.packages.openbao.EnableOptions;
import codes.grow.packages.openbao.HealthResponse;
import codes.grow.packages.openbao.LeaderStatus;
import codes.grow.packages.openbao.MountInfo;
import codes.grow.packages.openbao.OpenBaoClient;
import codes.grow.packages.openbao.RawResponse;
import codes.grow.packages.openbao.SealStatus;
import codes.grow.packages.openbao.SecretIdInfo;
import codes.grow.packages.openbao.SecretIdOptions;
import codes.grow.packages.openbao.Sys;
import codes.grow.packages.openbao.core.AuthenticationException;
import codes.grow.packages.openbao.core.CancelledException;
import codes.grow.packages.openbao.core.HealthStatus;
import codes.grow.packages.openbao.core.NotFoundException;
import codes.grow.packages.openbao.core.PermissionDeniedException;
import codes.grow.packages.openbao.core.ValidationException;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class CoreAndSysTest {
  @Test
  void clientSurface() {
    Map<String, String> env = Env.load();
    OpenBaoClient c = Env.root(env);
    HealthStatus h = c.health();
    assertTrue(h.healthy());
    assertEquals("active", h.status());
    assertEquals(Env.get(env, "SERVER_VERSION"), h.details().get("version"));
    assertTrue(c.healthAsync().join().healthy());
    assertTrue(c.ping().toNanos() > 0);
    assertTrue(c.pingAsync().join().toNanos() > 0);
    assertEquals(Env.get(env, "SERVER_VERSION"), c.serverVersion());
    assertEquals(Env.get(env, "SERVER_VERSION"), c.serverVersionAsync().join());
    RawResponse raw = c.request("GET", "sys/mounts", null);
    assertEquals(200, raw.status());
    assertTrue(raw.data().get().has("secret/"));
    c.close();
    c.close();
    assertTrue(c.isClosed());
    assertThrows(CancelledException.class, c::ping);
    try (OpenBaoClient anon = Env.anonymous(env)) {
      assertThrows(AuthenticationException.class, anon::ping);
      assertTrue(anon.health().healthy());
    }
    try (OpenBaoClient bad =
        OpenBaoClient.builder().url(env.get("GROW_OPENBAO_URL")).token("not-a-real-token").build()) {
      assertThrows(AuthenticationException.class, bad::ping);
    }
  }

  @Test
  void sysStatus() {
    Map<String, String> env = Env.load();
    try (OpenBaoClient c = Env.root(env)) {
      Sys sys = c.sys();
      HealthResponse h = sys.health();
      assertEquals("active", h.state());
      assertTrue(h.initialized());
      SealStatus s = sys.sealStatus();
      assertFalse(s.sealed());
      assertEquals("raft", s.storageType());
      LeaderStatus l = sys.leader();
      assertTrue(l.isSelf());
      assertTrue(l.haEnabled());
      assertEquals(Env.get(env, "SERVER_VERSION"), sys.version());
    }
  }

  @Test
  void policies() {
    Map<String, String> env = Env.load();
    String name = "sdk-java-" + Env.run();
    String hcl = "path \"secret/data/" + name + "/*\" { capabilities = [\"read\"] }";
    try (OpenBaoClient c = Env.root(env)) {
      c.sys().writePolicy(name, hcl);
      assertEquals(hcl, c.sys().readPolicy(name).policy().trim());
      assertTrue(c.sys().listPolicies().contains(name));
      assertThrows(ValidationException.class, () -> c.sys().writePolicy(name, "not { hcl"));
      c.sys().deletePolicy(name);
      assertThrows(NotFoundException.class, () -> c.sys().readPolicy(name));
      assertFalse(c.sys().listPolicies().contains(name));
    }
  }

  @Test
  void mountsAndAppRoleAdmin() {
    Map<String, String> env = Env.load();
    String run = Env.run();
    String kvPath = "java-kv-" + run;
    String authPath = "java-ar-" + run;
    String policy = "java-pol-" + run;
    try (OpenBaoClient c = Env.root(env)) {
      Sys sys = c.sys();
      Map<String, MountInfo> mounts = sys.listMounts();
      assertEquals("kv", mounts.get("secret/").type());
      assertEquals("2", mounts.get("secret/").options().get("version"));
      sys.enableSecretsEngine(
          kvPath, "kv", EnableOptions.builder().option("version", "2").description("java").build());
      assertEquals("java", sys.listMounts().get(kvPath + "/").description());
      assertThrows(ValidationException.class, () -> sys.enableSecretsEngine(kvPath, "kv"));
      sys.disableSecretsEngine(kvPath);
      assertFalse(sys.listMounts().containsKey(kvPath + "/"));

      sys.enableAuthMethod(authPath, "approle");
      assertEquals("approle", sys.listAuthMethods().get(authPath + "/").type());
      sys.writePolicy(policy, "path \"secret/data/sdk/allowed/*\" { capabilities = [\"read\"] }");
      sys.createAppRole(
          "r1",
          AppRoleOptions.builder()
              .mount(authPath)
              .tokenPolicies(policy)
              .tokenTtl(Duration.ofMinutes(10))
              .secretIdNumUses(1)
              .build());
      assertEquals(List.of("r1"), sys.listAppRoles(authPath));
      String roleId = sys.readRoleId("r1", authPath);
      SecretIdInfo sid =
          sys.generateSecretId(
              "r1", SecretIdOptions.builder().mount(authPath).metadata("purpose", "sdk").build());
      assertEquals(1, sid.secretIdNumUses());
      try (OpenBaoClient app = Env.anonymous(env)) {
        AuthInfo info =
            app.auth().login(new AppRoleAuth(roleId, sid.secretId(), authPath));
        assertTrue(info.policies().contains(policy));
        assertEquals("sdk", info.metadata().get("purpose"));
        assertEquals("world", app.kvV2("secret").read("sdk/allowed/hello").data().get("value"));
        assertThrows(
            PermissionDeniedException.class, () -> app.kvV2("secret").read("sdk/denied/hello"));
        // single-use secret id
        assertThrows(
            AuthenticationException.class,
            () -> app.auth().login(new AppRoleAuth(roleId, sid.secretId(), authPath)));
      }
      assertThrows(NotFoundException.class, () -> sys.readRoleId("nope", authPath));
      sys.deleteAppRole("r1", authPath);
      assertTrue(sys.listAppRoles(authPath).isEmpty());
      sys.disableAuthMethod(authPath);
      assertFalse(sys.listAuthMethods().containsKey(authPath + "/"));
      sys.deletePolicy(policy);
    }
  }
}
