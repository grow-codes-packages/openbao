package codes.grow.packages.openbao;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import codes.grow.packages.openbao.core.AuthenticationException;
import codes.grow.packages.openbao.core.CancelledException;
import codes.grow.packages.openbao.core.ConfigException;
import codes.grow.packages.openbao.core.EnvReader;
import codes.grow.packages.openbao.core.HealthStatus;
import codes.grow.packages.openbao.core.Hooks;
import codes.grow.packages.openbao.core.Logger;
import codes.grow.packages.openbao.core.MockServer;
import codes.grow.packages.openbao.core.RetryPolicy;
import codes.grow.packages.openbao.core.Secret;
import codes.grow.packages.openbao.core.TlsOptions;
import codes.grow.packages.openbao.core.UnsupportedException;
import java.net.ServerSocket;
import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class OpenBaoClientTest {
  private static final String P = EnvReader.DEFAULT_PREFIX;

  private MockServer server;

  @BeforeEach
  void start() throws Exception {
    server = MockServer.start();
  }

  @AfterEach
  void stop() {
    server.close();
  }

  private static OpenBaoConfig.Builder cfg() {
    return OpenBaoConfig.builder();
  }

  private OpenBaoClient client() {
    return OpenBaoClient.builder()
        .url(server.url())
        .token("tok-123456")
        .retry(RetryPolicy.builder().initialBackoff(Duration.ofMillis(1)).build())
        .build();
  }

  @Test
  void healthVariants() {
    Fixtures.enqueue(server, "health.active");
    Fixtures.enqueue(server, "health.sealed", 200);
    Fixtures.enqueue(server, "health.uninitialized", 200);
    server.enqueue(200, "{\"initialized\":true,\"standby\":true}");
    server.enqueue(500, "oops");
    try (var c = client()) {
      HealthStatus h = c.health();
      assertThat(h.healthy()).isTrue();
      assertThat(h.status()).isEqualTo("active");
      assertThat(h.details())
          .containsEntry("version", "2.7.2")
          .containsEntry("sealed", "false")
          .containsKey("clusterName");
      HealthStatus sealed = c.health();
      assertThat(sealed.healthy()).isFalse();
      assertThat(sealed.status()).isEqualTo("sealed");
      assertThat(sealed.details()).doesNotContainKey("clusterName");
      assertThat(c.health().status()).isEqualTo("uninitialized");
      assertThat(c.healthAsync().join().status()).isEqualTo("standby");
      HealthStatus broken = c.health();
      assertThat(broken.status()).isEqualTo("unreachable");
      assertThat(server.requests().get(0).uri()).startsWith("/v1/sys/health?");
    }
  }

  @Test
  void core_health_unreachable() throws Exception {
    int port;
    try (ServerSocket s = new ServerSocket(0)) {
      port = s.getLocalPort();
    }
    String url = "http://127.0.0.1:" + port;
    try (var c = OpenBaoClient.builder().url(url).build()) {
      HealthStatus h = c.health();
      assertThat(h.healthy()).isFalse();
      assertThat(h.status()).isEqualTo("unreachable");
      assertThat(c.healthAsync().join().status()).isEqualTo("unreachable");
    }
  }

  @Test
  void healthThrowsOnlyForCancel() {
    OpenBaoClient c = client();
    c.close();
    assertThatThrownBy(c::health).isInstanceOf(CancelledException.class);
    assertThatThrownBy(() -> c.healthAsync().join()).hasCauseInstanceOf(CancelledException.class);
  }

  @Test
  void pingSendsVaultToken() {
    Fixtures.enqueue(server, "ping.lookup-self");
    Fixtures.enqueue(server, "ping.invalid-token");
    server.enqueue(403, "{\"errors\":[\"1 error occurred: permission denied tok-123456\"]}");
    Fixtures.enqueue(server, "ping.lookup-self");
    try (var c = client()) {
      assertThat(c.ping()).isPositive();
      assertThat(server.requests().get(0).header("X-Vault-Token")).isEqualTo("tok-123456");
      assertThat(server.requests().get(0).uri()).isEqualTo("/v1/auth/token/lookup-self");
      assertThatThrownBy(c::ping).isInstanceOf(AuthenticationException.class);
      assertThatThrownBy(c::ping)
          .isInstanceOf(AuthenticationException.class)
          .message()
          .doesNotContain("tok-123456");
      assertThat(c.pingAsync().join()).isPositive();
    }
  }

  @Test
  void pingWithoutTokenAndNamespace() {
    server.enqueue(200, "{}");
    try (var c = OpenBaoClient.builder().url(server.url()).namespace("team-a").build()) {
      c.ping();
      assertThat(server.requests().get(0).header("X-Vault-Token")).isNull();
      assertThat(server.requests().get(0).header("X-Vault-Namespace")).isEqualTo("team-a");
      c.setToken("set-later-1");
      assertThat(c.token().get().reveal()).isEqualTo("set-later-1");
      c.setToken((String) null);
      assertThat(c.token()).isEmpty();
      c.setToken(Secret.of("cleared-x"));
      c.token().get().clear();
      server.enqueue(200, "{}");
      c.ping();
      assertThat(server.requests().get(1).header("X-Vault-Token")).isNull();
      assertThat(c.transport().config().knownSecrets()).isEmpty();
    }
  }

  @Test
  void serverVersion() {
    Fixtures.enqueue(server, "health.active");
    server.enqueue(200, "{\"initialized\":true}");
    Fixtures.enqueue(server, "health.active");
    try (var c = client()) {
      assertThat(c.serverVersion()).isEqualTo("2.7.2");
      assertThatThrownBy(c::serverVersion).isInstanceOf(UnsupportedException.class);
      assertThat(c.serverVersionAsync().join()).isEqualTo("2.7.2");
    }
  }

  @Test
  void modulesAreAvailable() {
    try (var c = client()) {
      assertThat(c.auth()).isSameAs(c.auth());
      assertThat(c.sys()).isNotNull();
      assertThat(c.wrapping()).isNotNull();
      assertThat(c.leases()).isNotNull();
      assertThat(c.kv().mount()).isEqualTo("secret");
      assertThat(c.kvV1("kv1").mount()).isEqualTo("kv1");
      assertThat(c.kvV2("secret").mount()).isEqualTo("secret");
      assertThat(c.transit().mount()).isEqualTo("transit");
      assertThat(c.database().mount()).isEqualTo("database");
      assertThat(c.pki().mount()).isEqualTo("pki");
      assertThat(c.pki("pki-int").mount()).isEqualTo("pki-int");
      assertThat(c.secrets().kv()).isSameAs(c.kv());
      assertThat(c.secrets(SecretsOptions.builder().mount("kv1").build()).kv().mount())
          .isEqualTo("kv1");
    }
  }

  @Test
  void closeStopsLeasesAndProviders() {
    OpenBaoClient c = client();
    OpenBaoSecretsProvider p = c.secrets();
    Fixtures.FakeScheduler clock = new Fixtures.FakeScheduler();
    ManagedLease m =
        c.leases()
            .manage(
                new Lease<>("db/creds/x/1", Duration.ofSeconds(60), true, "d", java.util.List.of()),
                RenewalOptions.builder().scheduler(clock).revokeOnStop(true).build());
    server.enqueue(204, "");
    c.close();
    assertThat(m.running()).isFalse();
    assertThat(server.requests()).hasSize(1);
    assertThat(server.requests().get(0).uri()).isEqualTo("/v1/sys/leases/revoke");
    p.close();
  }

  @Test
  void closeIsInterruptSafe() {
    OpenBaoClient c = client();
    Fixtures.FakeScheduler clock = new Fixtures.FakeScheduler();
    c.leases()
        .manage(
            new Lease<>("db/creds/x/1", Duration.ofSeconds(60), true, "d", java.util.List.of()),
            RenewalOptions.builder().scheduler(clock).revokeOnStop(true).build());
    server.enqueue(
        ex -> {
          Thread.sleep(2000);
          MockServer.send(ex, 204, "");
        });
    Thread.currentThread().interrupt();
    c.close();
    assertThat(Thread.interrupted()).isTrue();
    assertThat(c.isClosed()).isTrue();
  }

  @Test
  void closeTimesOutOnSlowRevoke() {
    OpenBaoClient c =
        OpenBaoClient.builder()
            .url(server.url())
            .token("t-1234")
            .requestTimeout(Duration.ofMillis(100))
            .build();
    Fixtures.FakeScheduler clock = new Fixtures.FakeScheduler();
    c.leases()
        .manage(
            new Lease<>("db/creds/x/1", Duration.ofSeconds(60), true, "d", java.util.List.of()),
            RenewalOptions.builder().scheduler(clock).revokeOnStop(true).build());
    server.fallback(
        ex -> {
          Thread.sleep(1000);
          MockServer.send(ex, 204, "");
        });
    c.close();
    assertThat(c.isClosed()).isTrue();
  }

  @Test
  void core_close_idempotent() throws Exception {
    AtomicInteger closed = new AtomicInteger();
    OpenBaoClient c = client();
    c.register(closed::incrementAndGet);
    c.register(
        () -> {
          throw new IllegalStateException("ignored");
        });
    c.close();
    c.close();
    assertThat(c.isClosed()).isTrue();
    assertThat(closed).hasValue(1);
    assertThat(c.transport().isClosed()).isTrue();
    assertThatThrownBy(c::ping).isInstanceOf(CancelledException.class);
  }

  @Test
  void builderSetsEveryField() {
    Hooks hooks = new Hooks() {};
    Logger logger = new Logger() {};
    try (var c =
        OpenBaoClient.builder()
            .url(server.url())
            .token(Secret.of("s3cr3t-value"))
            .connectTimeout(Duration.ofSeconds(1))
            .requestTimeout(Duration.ofSeconds(2))
            .totalTimeout(Duration.ofSeconds(3))
            .retry(RetryPolicy.none())
            .tls(TlsOptions.defaults())
            .proxy("http://proxy.invalid:3128")
            .header("X-A", "1")
            .userAgentSuffix("app/1")
            .hooks(hooks)
            .logger(logger)
            .build()) {
      OpenBaoConfig cfg = c.config();
      assertThat(cfg.url()).isEqualTo(server.url());
      assertThat(cfg.token()).isPresent();
      assertThat(cfg.connectTimeout()).isEqualTo(Duration.ofSeconds(1));
      assertThat(cfg.requestTimeout()).isEqualTo(Duration.ofSeconds(2));
      assertThat(cfg.totalTimeout()).isEqualTo(Duration.ofSeconds(3));
      assertThat(cfg.retry().maxRetries()).isZero();
      assertThat(cfg.tls().isCustom()).isFalse();
      assertThat(cfg.proxy()).contains("http://proxy.invalid:3128");
      assertThat(cfg.headers()).containsEntry("X-A", "1");
      assertThat(cfg.userAgentSuffix()).contains("app/1");
      assertThat(cfg.hooks()).isSameAs(hooks);
      assertThat(cfg.logger()).isSameAs(logger);
      assertThat(c.toString()).doesNotContain("s3cr3t-value");
      assertThat(c.transport().config().knownSecrets()).containsExactly("s3cr3t-value");
      assertThat(cfg.namespace()).isEmpty();
      assertThat(cfg.kvMount()).isEqualTo("secret");
      assertThat(cfg.kvVersion()).isEmpty();
      cfg.token().get().clear();
      assertThat(c.transport().config().knownSecrets()).isEmpty();
    }
  }

  @Test
  void core_redaction_config() {
    OpenBaoConfig cfg =
        cfg()
            .url("http://user:pw@h:1")
            .token("tok-very-secret")
            .header("Authorization", "Bearer tok-very-secret")
            .proxy("http://u:proxypass@p:3128")
            .build();
    assertThat(cfg.toString())
        .doesNotContain("tok-very-secret")
        .doesNotContain("proxypass")
        .doesNotContain(":pw@")
        .contains("token=[REDACTED]");
    assertThat(cfg().build().toString()).contains("token=null").contains("proxy=null");
  }

  @Test
  void core_config_env_precedence() {
    Map<String, String> env = new HashMap<>();
    env.put(P + "URL", "http://from-env:1");
    env.put(P + "TOKEN", "env-token");
    env.put(P + "CONNECT_TIMEOUT", "1500");
    env.put(P + "REQUEST_TIMEOUT", "2s");
    env.put(P + "TOTAL_TIMEOUT", "1m");
    env.put(P + "MAX_RETRIES", "5");
    env.put(P + "CA_CERT", "/tmp/ca.pem");
    env.put(P + "CLIENT_CERT", "/tmp/c.pem");
    env.put(P + "CLIENT_KEY", "/tmp/k.pem");
    env.put(P + "INSECURE_SKIP_VERIFY", "on");
    env.put(P + "PROXY", "http://proxy:1");
    OpenBaoConfig fromEnv = OpenBaoConfig.fromEnv(env);
    assertThat(fromEnv.url()).isEqualTo("http://from-env:1");
    assertThat(fromEnv.token().map(Secret::reveal)).contains("env-token");
    assertThat(fromEnv.connectTimeout()).isEqualTo(Duration.ofMillis(1500));
    assertThat(fromEnv.requestTimeout()).isEqualTo(Duration.ofSeconds(2));
    assertThat(fromEnv.totalTimeout()).isEqualTo(Duration.ofMinutes(1));
    assertThat(fromEnv.retry().maxRetries()).isEqualTo(5);
    assertThat(fromEnv.tls().insecureSkipVerify()).isTrue();
    assertThat(fromEnv.tls().caCertPath()).isPresent();
    assertThat(fromEnv.proxy()).contains("http://proxy:1");
    // explicit values win over the environment
    OpenBaoConfig explicit =
        cfg()
            .url("http://explicit:2")
            .token("explicit-token")
            .connectTimeout(Duration.ofSeconds(9))
            .requestTimeout(Duration.ofSeconds(9))
            .totalTimeout(Duration.ofSeconds(9))
            .retry(RetryPolicy.none())
            .tls(TlsOptions.defaults())
            .proxy("http://p2:1")
            .fromEnv(EnvReader.of(env))
            .build();
    assertThat(explicit.url()).isEqualTo("http://explicit:2");
    assertThat(explicit.token().map(Secret::reveal)).contains("explicit-token");
    assertThat(explicit.retry().maxRetries()).isZero();
    assertThat(explicit.tls().insecureSkipVerify()).isFalse();
    assertThat(explicit.proxy()).contains("http://p2:1");
    // defaults when nothing is set
    OpenBaoConfig defaults = OpenBaoConfig.fromEnv(Map.of());
    assertThat(defaults.url()).isEqualTo(OpenBaoConfig.DEFAULT_URL);
    assertThat(defaults.token()).isEmpty();
    assertThat(defaults.connectTimeout()).isEqualTo(Duration.ofSeconds(10));
    assertThat(defaults.requestTimeout()).isEqualTo(Duration.ofSeconds(30));
    assertThat(defaults.totalTimeout()).isEqualTo(Duration.ofSeconds(120));
    assertThat(defaults.retry().maxRetries()).isEqualTo(3);
    // invalid values name the variable, never the value
    Map<String, String> badTimeout = Map.of(P + "TOTAL_TIMEOUT", "forever");
    assertThatThrownBy(() -> OpenBaoConfig.fromEnv(badTimeout))
        .isInstanceOf(ConfigException.class)
        .hasMessageContaining(P + "TOTAL_TIMEOUT")
        .message()
        .doesNotContain("forever");
    Map<String, String> badRetries = Map.of(P + "MAX_RETRIES", "-1");
    assertThatThrownBy(() -> OpenBaoConfig.fromEnv(badRetries))
        .isInstanceOf(ConfigException.class)
        .hasMessageContaining(P + "MAX_RETRIES");
    assertThat(OpenBaoConfig.fromEnv()).isNotNull();
  }

  @Test
  void kvSettingsFromEnv() {
    OpenBaoConfig c =
        OpenBaoConfig.fromEnv(
            Map.of(P + "KV_MOUNT", "kv1", P + "KV_VERSION", "1", P + "SECRETS_PATH", "/apps/web/"));
    assertThat(c.kvMount()).isEqualTo("kv1");
    assertThat(c.kvVersion()).hasValue(1);
    assertThat(c.secretsPath()).isEqualTo("apps/web");
    assertThat(c.valueField()).isEqualTo("value");
    assertThat(c.toString()).contains("secretsPath=apps/web");
    assertThat(OpenBaoConfig.fromEnv(Map.of(P + "KV_VERSION", "0")).kvVersion()).isEmpty();
    assertThat(
            OpenBaoConfig.builder()
                .kvMount("x")
                .fromEnv(EnvReader.of(Map.of(P + "KV_MOUNT", "y")))
                .build()
                .kvMount())
        .isEqualTo("x");
    Map<String, String> bad = Map.of(P + "KV_VERSION", "3");
    assertThatThrownBy(() -> OpenBaoConfig.fromEnv(bad))
        .isInstanceOf(ConfigException.class)
        .hasMessageContaining(P + "KV_VERSION");
    assertThatThrownBy(() -> OpenBaoConfig.builder().valueField(" ").build())
        .isInstanceOf(ConfigException.class);
    try (OpenBaoClient client =
        OpenBaoClient.create(
            OpenBaoConfig.builder()
                .url("http://127.0.0.1:1")
                .secretsPath("base")
                .valueField("v")
                .build())) {
      assertThat(client.secrets().fullPath("a", null)).isEqualTo("base/a");
      assertThat(client.secrets(SecretsOptions.builder().path("other").build()).fullPath("a", null))
          .isEqualTo("other/a");
    }
  }

  @Test
  void vendorVariables() {
    Map<String, String> env = new HashMap<>();
    env.put("BAO_ADDR", "http://bao:8200");
    env.put("VAULT_ADDR", "http://vault:8200");
    env.put("VAULT_TOKEN", "vault-token-1");
    env.put("VAULT_NAMESPACE", "ns-v");
    env.put("BAO_CACERT", "/tmp/bao-ca.pem");
    env.put("VAULT_CLIENT_CERT", "/tmp/c.pem");
    env.put("VAULT_CLIENT_KEY", "/tmp/k.pem");
    env.put("VAULT_SKIP_VERIFY", "true");
    OpenBaoConfig c = OpenBaoConfig.fromEnv(env);
    assertThat(c.url()).isEqualTo("http://bao:8200");
    assertThat(c.token().get().reveal()).isEqualTo("vault-token-1");
    assertThat(c.namespace()).contains("ns-v");
    assertThat(c.tls().caCertPath().get().toString()).isEqualTo("/tmp/bao-ca.pem");
    assertThat(c.tls().clientCertPath()).isPresent();
    assertThat(c.tls().clientKeyPath()).isPresent();
    assertThat(c.tls().insecureSkipVerify()).isTrue();
    env.put("BAO_TOKEN", "bao-token-1");
    env.put("BAO_NAMESPACE", "ns-b");
    env.put(P + "NAMESPACE", "ns-grow");
    env.put(P + "TOKEN", "grow-token-1");
    OpenBaoConfig c2 = OpenBaoConfig.fromEnv(env);
    assertThat(c2.token().get().reveal()).isEqualTo("grow-token-1");
    assertThat(c2.namespace()).contains("ns-grow");
    OpenBaoConfig explicit =
        cfg().namespace("explicit").kvMount("kv1").kvVersion(1).fromEnv(EnvReader.of(env)).build();
    assertThat(explicit.namespace()).contains("explicit");
    assertThat(explicit.kvMount()).isEqualTo("kv1");
    assertThat(explicit.kvVersion()).hasValue(1);
    assertThat(explicit.toString()).contains("namespace=explicit").contains("kvMount=kv1");
    assertThat(cfg().namespace("").build().namespace()).isEmpty();
  }

  @Test
  void serviceValidation() {
    assertThatThrownBy(() -> cfg().token("  ").build()).isInstanceOf(ConfigException.class);
    assertThatThrownBy(() -> cfg().kvMount("/").build()).isInstanceOf(ConfigException.class);
    assertThatThrownBy(() -> cfg().kvVersion(3).build()).isInstanceOf(ConfigException.class);
    assertThatThrownBy(() -> cfg().retry(RetryPolicy.builder().maxRetries(-1).build()).build())
        .isInstanceOf(ConfigException.class);
    Secret cleared = Secret.of("x-token");
    cleared.clear();
    assertThat(cfg().token(cleared).build().token()).isPresent();
    assertThat(cfg().kvVersion(2).build().kvVersion()).hasValue(2);
  }

  @Test
  void validation() {
    assertThatThrownBy(() -> cfg().url("ftp://x").build()).isInstanceOf(ConfigException.class);
    assertThatThrownBy(() -> cfg().url("http://[").build()).isInstanceOf(ConfigException.class);
    assertThatThrownBy(() -> cfg().url("mailto:x").build()).isInstanceOf(ConfigException.class);
    assertThatThrownBy(() -> cfg().connectTimeout(Duration.ZERO).build())
        .isInstanceOf(ConfigException.class);
    assertThatThrownBy(() -> cfg().requestTimeout(Duration.ofSeconds(-1)).build())
        .isInstanceOf(ConfigException.class);
    assertThatThrownBy(() -> cfg().totalTimeout(Duration.ZERO).build())
        .isInstanceOf(ConfigException.class);
    assertThatThrownBy(() -> cfg().tls(TlsOptions.builder().clientCertPem("x").build()).build())
        .isInstanceOf(ConfigException.class);
    assertThatThrownBy(() -> cfg().proxy("relative").build()).isInstanceOf(ConfigException.class);
    assertThatThrownBy(() -> cfg().proxy("http://[").build()).isInstanceOf(ConfigException.class);
    assertThat(cfg().token((String) null).build().token()).isEmpty();
  }

  @Test
  void createAndFromEnv() {
    try (var c = OpenBaoClient.create(cfg().url(server.url()).build())) {
      assertThat(c.isClosed()).isFalse();
    }
    try (var c = OpenBaoClient.fromEnv()) {
      assertThat(c.config()).isNotNull();
    }
    EnvReader env = EnvReader.of(Map.of(P + "URL", server.url()));
    try (var c = OpenBaoClient.builder().fromEnv(env).build()) {
      assertThat(c.config().url()).isEqualTo(server.url());
    }
  }
}
