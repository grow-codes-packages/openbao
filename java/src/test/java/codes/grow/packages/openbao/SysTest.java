package codes.grow.packages.openbao;

import static codes.grow.packages.openbao.Fixtures.enqueue;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import codes.grow.packages.openbao.core.MockServer;
import codes.grow.packages.openbao.core.NotFoundException;
import codes.grow.packages.openbao.core.PermissionDeniedException;
import codes.grow.packages.openbao.core.UnavailableException;
import codes.grow.packages.openbao.core.UnsupportedException;
import codes.grow.packages.openbao.core.ValidationException;
import java.time.Duration;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class SysTest {
  private MockServer server;
  private OpenBaoClient client;
  private Sys sys;

  @BeforeEach
  void start() throws Exception {
    server = MockServer.start();
    client = Fixtures.client(server).build();
    sys = client.sys();
  }

  @AfterEach
  void stop() {
    client.close();
    server.close();
  }

  private String body(int i) {
    return server.requests().get(i).body();
  }

  private String uri(int i) {
    return server.requests().get(i).uri();
  }

  @Test
  void healthStates() {
    enqueue(server, "health.active");
    HealthResponse h = sys.health();
    assertThat(h.state()).isEqualTo("active");
    assertThat(h.version()).isEqualTo("2.7.2");
    assertThat(h.clusterName()).isNotEmpty();
    assertThat(h.clusterId()).isNotEmpty();
    assertThat(h.serverTime()).isPresent();
    assertThat(uri(0))
        .startsWith("/v1/sys/health?")
        .contains("uninitcode=200")
        .contains("sealedcode=200")
        .contains("standbycode=200")
        .contains("performancestandbycode=200");
    assertThat(server.requests().get(0).header("X-Vault-Token")).isNull();
    enqueue(server, "health.sealed", 200);
    assertThat(sys.health().state()).isEqualTo("sealed");
    enqueue(server, "health.uninitialized", 200);
    assertThat(sys.health().state()).isEqualTo("uninitialized");
    server.enqueue(200, "{\"initialized\":true,\"sealed\":false,\"standby\":true}");
    assertThat(sys.health().state()).isEqualTo("standby");
    server.enqueue(200, "{\"initialized\":true,\"standby\":true,\"performance_standby\":true}");
    HealthResponse perf = sys.health();
    assertThat(perf.state()).isEqualTo("perfstandby");
    assertThat(perf.performanceStandby()).isTrue();
    server.enqueue(200, "");
    assertThatThrownBy(sys::health).isInstanceOf(UnavailableException.class);
    server.enqueue(200, "[]");
    assertThatThrownBy(sys::health).isInstanceOf(UnavailableException.class);

    enqueue(server, "health.active");
    assertThat(sys.version()).isEqualTo("2.7.2");
    server.enqueue(200, "{\"initialized\":true}");
    assertThatThrownBy(sys::version).isInstanceOf(UnsupportedException.class);
  }

  @Test
  void sealStatusAndLeader() {
    enqueue(server, "sealStatus.sealed");
    SealStatus s = sys.sealStatus();
    assertThat(s.type()).isEqualTo("shamir");
    assertThat(s.sealed()).isTrue();
    assertThat(s.initialized()).isTrue();
    assertThat(s.threshold()).isEqualTo(1);
    assertThat(s.shares()).isEqualTo(1);
    assertThat(s.progress()).isZero();
    assertThat(s.nonce()).isEmpty();
    assertThat(s.recoverySeal()).isFalse();
    assertThat(s.version()).isEqualTo("2.7.2");
    assertThat(s.storageType()).isEqualTo("raft");
    enqueue(server, "sealStatus.unsealed");
    assertThat(sys.sealStatus().sealed()).isFalse();
    enqueue(server, "leader.active");
    LeaderStatus l = sys.leader();
    assertThat(l.haEnabled()).isTrue();
    assertThat(l.isSelf()).isTrue();
    assertThat(l.activeTime()).isPresent();
    assertThat(l.leaderAddress()).isEqualTo("http://openbao:8200");
    assertThat(l.leaderClusterAddress()).startsWith("https://");
  }

  @Test
  void policies() {
    enqueue(server, "admin.writePolicy.ok");
    sys.writePolicy("p1", "path \"x/*\" { capabilities = [\"read\"] }");
    assertThat(server.requests().get(0).method()).isEqualTo("PUT");
    assertThat(uri(0)).isEqualTo("/v1/sys/policies/acl/p1");
    assertThat(body(0)).startsWith("{\"policy\":\"path");
    assertThatThrownBy(() -> sys.writePolicy("p1", "")).isInstanceOf(ValidationException.class);
    enqueue(server, "admin.writePolicy.invalid");
    assertThatThrownBy(() -> sys.writePolicy("p1", "nonsense {"))
        .isInstanceOf(ValidationException.class);
    enqueue(server, "admin.readPolicy.ok");
    Policy p = sys.readPolicy("sdk-tmp");
    assertThat(p.name()).startsWith("sdk-tmp");
    assertThat(p.policy()).isNotEmpty();
    server.enqueue(200, "{\"data\":{\"policy\":\"x\"}}");
    assertThat(sys.readPolicy("given").name()).isEqualTo("given");
    enqueue(server, "admin.readPolicy.not-found");
    assertThatThrownBy(() -> sys.readPolicy("nope")).isInstanceOf(NotFoundException.class);
    enqueue(server, "admin.listPolicies.ok");
    assertThat(sys.listPolicies()).contains("default", "root");
    assertThat(uri(5)).isEqualTo("/v1/sys/policies/acl?list=true");
    enqueue(server, "admin.deletePolicy.ok");
    sys.deletePolicy("p1");
    assertThat(server.requests().get(6).method()).isEqualTo("DELETE");
  }

  @Test
  void mountsAndAuthMethods() {
    enqueue(server, "admin.listMounts.ok");
    Map<String, MountInfo> mounts = sys.listMounts();
    assertThat(mounts).containsKeys("sys/", "secret/");
    MountInfo secret = mounts.get("secret/");
    assertThat(secret.type()).isEqualTo("kv");
    assertThat(secret.options()).containsEntry("version", "2");
    assertThat(secret.config()).containsKey("default_lease_ttl");
    assertThat(secret.accessor()).isNotEmpty();
    assertThat(secret.description()).isNotNull();
    assertThat(secret.local()).isFalse();
    assertThat(mounts.get("sys/").sealWrap()).isTrue();
    enqueue(server, "admin.listMounts.permission-denied");
    assertThatThrownBy(sys::listMounts).isInstanceOf(PermissionDeniedException.class);

    enqueue(server, "admin.enableSecretsEngine.ok");
    sys.enableSecretsEngine(
        "/tmp-kv/",
        "kv",
        EnableOptions.builder()
            .description("d")
            .option("version", "2")
            .defaultLeaseTtl(Duration.ofHours(1))
            .maxLeaseTtl(Duration.ofHours(2))
            .local(false)
            .sealWrap(false)
            .build());
    assertThat(uri(2)).isEqualTo("/v1/sys/mounts/tmp-kv");
    assertThat(body(2))
        .isEqualTo(
            "{\"type\":\"kv\",\"description\":\"d\",\"options\":{\"version\":\"2\"},"
                + "\"config\":{\"default_lease_ttl\":\"3600s\",\"max_lease_ttl\":\"7200s\"},"
                + "\"local\":false,\"seal_wrap\":false}");
    enqueue(server, "admin.enableSecretsEngine.conflict");
    assertThatThrownBy(() -> sys.enableSecretsEngine("tmp", "kv"))
        .isInstanceOf(ValidationException.class);
    assertThat(body(3)).isEqualTo("{\"type\":\"kv\"}");
    assertThatThrownBy(() -> sys.enableSecretsEngine("/", "kv"))
        .isInstanceOf(ValidationException.class);
    assertThatThrownBy(() -> sys.enableSecretsEngine("x", ""))
        .isInstanceOf(ValidationException.class);
    enqueue(server, "admin.disableSecretsEngine.ok");
    sys.disableSecretsEngine("tmp-kv/");
    assertThat(server.requests().get(4).method()).isEqualTo("DELETE");
    assertThat(uri(4)).isEqualTo("/v1/sys/mounts/tmp-kv");

    enqueue(server, "admin.listAuthMethods.ok");
    Map<String, MountInfo> auths = sys.listAuthMethods();
    assertThat(auths).containsKey("token/");
    assertThat(auths.get("token/").config()).containsEntry("token_type", "default-service");
    enqueue(server, "admin.enableAuthMethod.ok");
    sys.enableAuthMethod("ar", "approle");
    assertThat(body(6)).isEqualTo("{\"type\":\"approle\"}");
    enqueue(server, "admin.enableAuthMethod.ok");
    sys.enableAuthMethod(
        "ar2",
        "approle",
        EnableOptions.builder().description("x").option("ignored", "1").sealWrap(true).build());
    assertThat(body(7)).isEqualTo("{\"type\":\"approle\",\"description\":\"x\"}");
    enqueue(server, "admin.disableAuthMethod.ok");
    sys.disableAuthMethod("ar");
    assertThat(uri(8)).isEqualTo("/v1/sys/auth/ar");
    assertThat(EnableOptions.none()).isNotNull();
  }

  @Test
  void appRoleAdmin() {
    enqueue(server, "admin.createAppRole.ok");
    sys.createAppRole(
        "r1",
        AppRoleOptions.builder()
            .mount("ar")
            .tokenPolicies("p")
            .tokenTtl(Duration.ofMinutes(10))
            .tokenMaxTtl(Duration.ofMinutes(20))
            .secretIdTtl(Duration.ofMinutes(5))
            .secretIdNumUses(1)
            .bindSecretId(true)
            .tokenType("service")
            .build());
    assertThat(uri(0)).isEqualTo("/v1/auth/ar/role/r1");
    assertThat(body(0))
        .contains("\"token_policies\":[\"p\"]")
        .contains("\"token_ttl\":\"600s\"")
        .contains("\"secret_id_num_uses\":1")
        .contains("\"token_type\":\"service\"");
    enqueue(server, "admin.createAppRole.ok");
    sys.createAppRole("r2", AppRoleOptions.none());
    assertThat(uri(1)).isEqualTo("/v1/auth/approle/role/r2");
    enqueue(server, "admin.listAppRoles.ok");
    assertThat(sys.listAppRoles("ar")).containsExactly("r1");
    assertThat(uri(2)).isEqualTo("/v1/auth/ar/role?list=true");
    server.enqueue(404, "{\"errors\":[]}");
    assertThat(sys.listAppRoles()).isEmpty();
    enqueue(server, "admin.readRoleId.ok");
    assertThat(sys.readRoleId("r1", "ar")).hasSize(36);
    assertThat(uri(4)).isEqualTo("/v1/auth/ar/role/r1/role-id");
    enqueue(server, "admin.readRoleId.not-found");
    assertThatThrownBy(() -> sys.readRoleId("nope")).isInstanceOf(NotFoundException.class);
    server.enqueue(200, "{\"data\":{}}");
    assertThatThrownBy(() -> sys.readRoleId("r")).isInstanceOf(UnavailableException.class);
    enqueue(server, "admin.generateSecretId.ok");
    SecretIdInfo sid =
        sys.generateSecretId(
            "r1",
            SecretIdOptions.builder()
                .mount("ar")
                .metadata("purpose", "sdk")
                .cidrList("10.0.0.0/8")
                .ttl(Duration.ofMinutes(5))
                .numUses(1)
                .build());
    assertThat(sid.secretIdNumUses()).isEqualTo(1);
    assertThat(sid.secretIdTtl()).isZero();
    assertThat(sid.toString()).doesNotContain("redacted>");
    assertThat(body(7))
        .contains("\"metadata\":\"{\\\"purpose\\\":\\\"sdk\\\"}\"")
        .contains("\"cidr_list\":[\"10.0.0.0/8\"]")
        .contains("\"ttl\":\"300s\"")
        .contains("\"num_uses\":1");
    enqueue(server, "admin.generateSecretId.ok");
    sys.generateSecretId("r1");
    assertThat(body(8)).isEqualTo("{}");
    server.enqueue(200, "{\"data\":{}}");
    assertThatThrownBy(() -> sys.generateSecretId("r1")).isInstanceOf(UnavailableException.class);
    server.enqueue(204, "");
    sys.deleteAppRole("r1");
    server.enqueue(204, "");
    sys.deleteAppRole("r1", "ar");
    assertThat(uri(11)).isEqualTo("/v1/auth/ar/role/r1");
    assertThatThrownBy(() -> sys.deleteAppRole("")).isInstanceOf(ValidationException.class);
  }
}
