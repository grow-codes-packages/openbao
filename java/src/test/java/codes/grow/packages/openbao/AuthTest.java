package codes.grow.packages.openbao;

import static codes.grow.packages.openbao.Fixtures.enqueue;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import codes.grow.packages.openbao.core.AuthenticationException;
import codes.grow.packages.openbao.core.ConfigException;
import codes.grow.packages.openbao.core.MockServer;
import codes.grow.packages.openbao.core.PermissionDeniedException;
import codes.grow.packages.openbao.core.Secret;
import codes.grow.packages.openbao.core.UnavailableException;
import codes.grow.packages.openbao.core.ValidationException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.concurrent.CompletableFuture;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class AuthTest {
  private static final String LOGIN_BODY =
      "{\"auth\":{\"client_token\":\"new-token-5678\",\"accessor\":\"acc-1\",\"policies\":[\"default\"],"
          + "\"token_policies\":[\"default\"],\"metadata\":{\"username\":\"u\"},\"lease_duration\":60,"
          + "\"renewable\":true,\"entity_id\":\"e\",\"token_type\":\"service\",\"orphan\":true,\"num_uses\":0}}";

  private MockServer server;
  private OpenBaoClient client;

  @BeforeEach
  void start() throws Exception {
    server = MockServer.start();
    client = Fixtures.client(server).build();
  }

  @AfterEach
  void stop() {
    client.close();
    server.close();
  }

  @Test
  void appRoleLoginSetsToken() {
    server.enqueue(200, LOGIN_BODY);
    AuthInfo info = client.auth().login(new AppRoleAuth("role-1", "secret-id-9999"));
    assertThat(info.clientToken().reveal()).isEqualTo("new-token-5678");
    assertThat(info.accessor()).isPresent();
    assertThat(info.policies()).containsExactly("default");
    assertThat(info.tokenPolicies()).containsExactly("default");
    assertThat(info.metadata()).containsEntry("username", "u");
    assertThat(info.leaseDuration()).isEqualTo(Duration.ofSeconds(60));
    assertThat(info.renewable()).isTrue();
    assertThat(info.entityId()).isEqualTo("e");
    assertThat(info.tokenType()).isEqualTo("service");
    assertThat(info.orphan()).isTrue();
    assertThat(info.numUses()).isZero();
    assertThat(info.toString()).doesNotContain("new-token-5678");
    MockServer.Recorded r = server.requests().get(0);
    assertThat(r.uri()).isEqualTo("/v1/auth/approle/login");
    assertThat(r.header("X-Vault-Token")).isNull();
    assertThat(r.body()).isEqualTo("{\"role_id\":\"role-1\",\"secret_id\":\"secret-id-9999\"}");
    assertThat(client.token().get().reveal()).isEqualTo("new-token-5678");
    // later calls use the new token
    enqueue(server, "lookupSelf.ok");
    client.auth().lookupSelf();
    assertThat(server.requests().get(1).header("X-Vault-Token")).isEqualTo("new-token-5678");
  }

  @Test
  void loginFailuresAreAuthentication() {
    enqueue(server, "appRoleLogin.invalid-secret");
    assertThatThrownBy(() -> client.auth().login(new AppRoleAuth("r", "bad-secret-id")))
        .isInstanceOf(AuthenticationException.class)
        .message()
        .doesNotContain("bad-secret-id");
    enqueue(server, "userpassLogin.invalid-password");
    assertThatThrownBy(() -> client.auth().login(new UserpassAuth("sdk-user", "wrong-pass")))
        .isInstanceOf(AuthenticationException.class);
    enqueue(server, "jwtLogin.expired");
    assertThatThrownBy(() -> client.auth().login(new JwtAuth("sdk-jwt", "a.b.c")))
        .isInstanceOf(AuthenticationException.class);
    enqueue(server, "kubernetesLogin.no-kubernetes-api");
    assertThatThrownBy(
            () ->
                client
                    .auth()
                    .login(KubernetesAuth.withJwt("sdk-k8s", Secret.of("k.j.w"), "kubernetes")))
        .isInstanceOf(AuthenticationException.class);
    server.enqueue(200, "{\"auth\":null}");
    assertThatThrownBy(() -> client.auth().login(new AppRoleAuth("r", "s")))
        .isInstanceOf(UnavailableException.class);
    // the client token is unchanged after failures
    assertThat(client.token().get().reveal()).isEqualTo("root-token-1234");
  }

  @Test
  void loginMethodsBuildRequests(@TempDir Path dir) throws Exception {
    server.enqueue(200, LOGIN_BODY);
    client
        .auth()
        .login(
            new UserpassAuth("sdk user", Secret.of("pw"), "/up/"),
            LoginOptions.builder().setToken(false).build());
    assertThat(server.requests().get(0).uri()).isEqualTo("/v1/auth/up/login/sdk%20user");
    assertThat(server.requests().get(0).body()).isEqualTo("{\"password\":\"pw\"}");
    assertThat(client.token().get().reveal()).isEqualTo("root-token-1234");

    server.enqueue(200, LOGIN_BODY);
    client.auth().loginAsync(new JwtAuth("role", Secret.of("j.w.t"), null)).join();
    assertThat(server.requests().get(1).uri()).isEqualTo("/v1/auth/jwt/login");
    assertThat(server.requests().get(1).body())
        .contains("\"role\":\"role\"")
        .contains("\"jwt\":\"j.w.t\"");

    Path jwt = dir.resolve("token");
    Files.writeString(jwt, " sa.jwt.value \n", StandardCharsets.UTF_8);
    server.enqueue(200, LOGIN_BODY);
    KubernetesAuth k8s = new KubernetesAuth("sdk-k8s", jwt.toString());
    assertThat(k8s.jwtPath()).isEqualTo(jwt);
    assertThat(k8s.method()).isEqualTo("kubernetes");
    client.auth().login(k8s);
    assertThat(server.requests().get(2).uri()).isEqualTo("/v1/auth/kubernetes/login");
    assertThat(server.requests().get(2).body()).contains("\"jwt\":\"sa.jwt.value\"");

    server.enqueue(200, LOGIN_BODY);
    client.auth().login(new AppRoleAuth("role-only", null, "approle2"));
    assertThat(server.requests().get(3).body()).isEqualTo("{\"role_id\":\"role-only\"}");
    assertThat(server.requests().get(3).uri()).isEqualTo("/v1/auth/approle2/login");

    // unreadable / empty token files fail before any request
    assertThatThrownBy(() -> client.auth().login(new KubernetesAuth("r", dir.resolve("nope"), "k")))
        .isInstanceOf(ConfigException.class)
        .hasMessageContaining("cannot read");
    Path empty = dir.resolve("empty");
    Files.writeString(empty, "  ");
    assertThatThrownBy(() -> client.auth().login(new KubernetesAuth("r", empty, null)))
        .isInstanceOf(ConfigException.class)
        .hasMessageContaining("is empty");
    assertThat(new KubernetesAuth("r").jwtPath().toString())
        .isEqualTo(KubernetesAuth.DEFAULT_JWT_PATH);
    assertThat(server.requests()).hasSize(4);
  }

  @Test
  void methodValidationAndToString() {
    assertThatThrownBy(() -> new TokenAuth((String) null)).isInstanceOf(ConfigException.class);
    assertThatThrownBy(() -> new TokenAuth("")).isInstanceOf(ConfigException.class);
    assertThatThrownBy(() -> new UserpassAuth("u", (String) null))
        .isInstanceOf(ConfigException.class);
    assertThatThrownBy(() -> new UserpassAuth("u", "")).isInstanceOf(ConfigException.class);
    assertThatThrownBy(() -> new UserpassAuth("", "p")).isInstanceOf(ValidationException.class);
    assertThatThrownBy(() -> new JwtAuth("r", (String) null)).isInstanceOf(ConfigException.class);
    assertThatThrownBy(() -> new JwtAuth("r", "")).isInstanceOf(ConfigException.class);
    assertThatThrownBy(() -> new AppRoleAuth(" ", "s")).isInstanceOf(ValidationException.class);
    assertThatThrownBy(() -> KubernetesAuth.withJwt("r", null, null))
        .isInstanceOf(ConfigException.class);
    assertThatThrownBy(() -> KubernetesAuth.withJwt("r", Secret.of(""), null))
        .isInstanceOf(ConfigException.class);
    assertThat(new TokenAuth("t-1234").toString()).isEqualTo("TokenAuth([REDACTED])");
    assertThat(new TokenAuth("t-1234").method()).isEqualTo("token");
    assertThat(new AppRoleAuth("r", "sec-1234").toString()).doesNotContain("sec-1234");
    assertThat(new AppRoleAuth("r", "s").method()).isEqualTo("approle");
    assertThat(new AppRoleAuth("r", "s").mount()).isEqualTo("approle");
    assertThat(new UserpassAuth("u", "pw-1234").toString()).doesNotContain("pw-1234");
    assertThat(new UserpassAuth("u", "p").method()).isEqualTo("userpass");
    assertThat(new JwtAuth("r", "jwt-1234").toString()).doesNotContain("jwt-1234");
    assertThat(new JwtAuth("r", "j").method()).isEqualTo("jwt");
    assertThat(new KubernetesAuth("r").toString()).isEqualTo("KubernetesAuth(kubernetes, role=r)");
  }

  @Test
  void tokenAuthLooksUpTheToken() {
    enqueue(server, "lookupSelf.ok");
    AuthInfo info = client.auth().login(new TokenAuth("other-token-42"));
    assertThat(info.clientToken().reveal()).isEqualTo("other-token-42");
    assertThat(info.leaseDuration()).isPositive();
    assertThat(server.requests().get(0).header("X-Vault-Token")).isEqualTo("other-token-42");
    assertThat(client.token().get().reveal()).isEqualTo("other-token-42");
    enqueue(server, "lookupSelf.revoked");
    assertThatThrownBy(() -> client.auth().login(new TokenAuth("revoked-token")))
        .isInstanceOf(AuthenticationException.class);
    // a method throwing synchronously fails the future
    AuthMethod broken =
        new AuthMethod() {
          @Override
          public String method() {
            return "broken";
          }

          @Override
          public CompletableFuture<AuthInfo> login(LoginContext context) {
            throw new IllegalStateException("boom");
          }
        };
    assertThatThrownBy(() -> client.auth().login(broken)).isInstanceOf(UnavailableException.class);
  }

  @Test
  void tokenSelfService() {
    enqueue(server, "lookupSelf.ok");
    TokenInfo t = client.auth().lookupSelf();
    assertThat(t.displayName()).isEqualTo("token-sdk-test");
    assertThat(t.creationTtl()).isEqualTo(Duration.ofHours(1));
    assertThat(t.creationTime()).isPresent();
    assertThat(t.expireTime()).isPresent();
    assertThat(t.issueTime()).isPresent();
    assertThat(t.meta()).containsEntry("run", "f43633d7");
    assertThat(t.path()).isEqualTo("auth/token/create");
    assertThat(t.toString()).doesNotContain("redacted>");

    enqueue(server, "renewSelf.ok");
    AuthInfo r = client.auth().renewSelf(Duration.ofMinutes(30));
    assertThat(r.leaseDuration()).isEqualTo(Duration.ofMinutes(30));
    assertThat(server.requests().get(1).body()).isEqualTo("{\"increment\":\"1800s\"}");
    enqueue(server, "renewSelf.ok");
    client.auth().renewSelf();
    assertThat(server.requests().get(2).body()).isEqualTo("{}");
    enqueue(server, "renewSelf.not-renewable");
    assertThatThrownBy(() -> client.auth().renewSelf(Duration.ofMinutes(30)))
        .isInstanceOf(ValidationException.class);
    assertThatThrownBy(() -> client.auth().renewSelf(Duration.ofSeconds(-1)))
        .isInstanceOf(ValidationException.class);

    enqueue(server, "createToken.ok");
    AuthInfo created =
        client
            .auth()
            .createToken(
                CreateTokenOptions.builder()
                    .policies("sdk-app")
                    .ttl(Duration.ofHours(1))
                    .explicitMaxTtl(Duration.ofHours(2))
                    .renewable(true)
                    .displayName("sdk-test")
                    .meta("run", "x")
                    .numUses(0)
                    .noParent(false)
                    .noDefaultPolicy(false)
                    .period(Duration.ofMinutes(5))
                    .build());
    assertThat(created.policies()).contains("sdk-app");
    String body = server.requests().get(4).body();
    assertThat(body)
        .contains("\"policies\":[\"sdk-app\"]")
        .contains("\"ttl\":\"3600s\"")
        .contains("\"explicit_max_ttl\":\"7200s\"")
        .contains("\"display_name\":\"sdk-test\"")
        .contains("\"meta\":{\"run\":\"x\"}")
        .contains("\"period\":\"300s\"");
    assertThat(client.token().get().reveal()).isEqualTo("root-token-1234");
    enqueue(server, "createToken.ok");
    client.auth().createToken(CreateTokenOptions.builder().role("my role").build());
    assertThat(server.requests().get(5).uri()).isEqualTo("/v1/auth/token/create/my%20role");
    enqueue(server, "createToken.ok");
    client.auth().createToken(CreateTokenOptions.defaults());
    assertThat(server.requests().get(6).body()).isEqualTo("{}");
    assertThatThrownBy(
            () -> client.auth().createToken(CreateTokenOptions.builder().numUses(-1).build()))
        .isInstanceOf(ValidationException.class);
    enqueue(server, "createToken.permission-denied");
    assertThatThrownBy(() -> client.auth().createToken(CreateTokenOptions.defaults()))
        .isInstanceOf(PermissionDeniedException.class);

    enqueue(server, "revokeSelf.ok");
    client.auth().revokeSelf();
    assertThat(client.token()).isEmpty();
    enqueue(server, "ping.invalid-token");
    assertThatThrownBy(client::ping).isInstanceOf(AuthenticationException.class);
    assertThat(server.requests().get(9).header("X-Vault-Token")).isNull();
  }

  @Test
  void loginWithAutoRenewStartsRenewer() {
    Fixtures.FakeScheduler clock = new Fixtures.FakeScheduler();
    server.enqueue(200, LOGIN_BODY);
    RenewalOptions opts = RenewalOptions.builder().scheduler(clock).build();
    AuthInfo info =
        client
            .auth()
            .login(new AppRoleAuth("r", "s"), LoginOptions.builder().autoRenew(opts).build());
    assertThat(info.renewable()).isTrue();
    assertThat(client.auth().activeRenewers()).isEqualTo(1);
    assertThat(clock.nextDelay()).isEqualTo(Duration.ofSeconds(40));
    TokenRenewer r = client.auth().renewers().get(0);
    assertThat(r.running()).isTrue();
    assertThat(r.expired()).isFalse();
    assertThat(r.expiresAt()).isPresent();
    // renewal at 2/3 of the TTL
    server.enqueue(200, LOGIN_BODY);
    clock.advance(Duration.ofSeconds(40));
    Fixtures.eventually(() -> server.requests().size() == 2);
    assertThat(server.requests().get(1).uri()).isEqualTo("/v1/auth/token/renew-self");
    client.auth().stopRenewers();
    assertThat(client.auth().activeRenewers()).isZero();
    assertThat(r.running()).isFalse();
  }

  @Test
  void startRenewerReadsTtlAndCloses() {
    Fixtures.FakeScheduler clock = new Fixtures.FakeScheduler();
    enqueue(server, "lookupSelf.ok");
    TokenRenewer r = client.auth().startRenewer(RenewalOptions.builder().scheduler(clock).build());
    assertThat(r.running()).isTrue();
    assertThat(clock.pending()).isEqualTo(1);
    // starting twice is a no-op
    assertThat(r.start(null).join()).isSameAs(r);
    r.close();
    r.close();
    assertThat(clock.pending()).isZero();
    // a failing lookup stops and forgets the renewer
    enqueue(server, "lookupSelf.revoked");
    assertThatThrownBy(
            () -> client.auth().startRenewer(RenewalOptions.builder().scheduler(clock).build()))
        .isInstanceOf(AuthenticationException.class);
    assertThat(client.auth().activeRenewers()).isZero();
    // close() of the client stops renewers
    enqueue(server, "lookupSelf.ok");
    client.auth().startRenewerAsync(RenewalOptions.builder().scheduler(clock).build()).join();
    assertThat(client.auth().activeRenewers()).isEqualTo(1);
    client.close();
    assertThat(client.auth().activeRenewers()).isZero();
  }
}
