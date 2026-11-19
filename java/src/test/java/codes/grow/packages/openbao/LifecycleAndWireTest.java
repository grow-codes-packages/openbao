package codes.grow.packages.openbao;

import static codes.grow.packages.openbao.Fixtures.enqueue;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import codes.grow.packages.openbao.core.AuthenticationException;
import codes.grow.packages.openbao.core.ConflictException;
import codes.grow.packages.openbao.core.ErrorCode;
import codes.grow.packages.openbao.core.Json;
import codes.grow.packages.openbao.core.MockServer;
import codes.grow.packages.openbao.core.NotFoundException;
import codes.grow.packages.openbao.core.OpenBaoException;
import codes.grow.packages.openbao.core.PermissionDeniedException;
import codes.grow.packages.openbao.core.RateLimitException;
import codes.grow.packages.openbao.core.Secret;
import codes.grow.packages.openbao.core.TimeoutException;
import codes.grow.packages.openbao.core.UnavailableException;
import codes.grow.packages.openbao.core.UnsupportedException;
import codes.grow.packages.openbao.core.ValidationException;
import codes.grow.packages.openbao.testing.OpenBaoTesting;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import org.junit.jupiter.api.Test;

class LifecycleAndWireTest {
  @Test
  void initUnsealSeal() throws Exception {
    try (MockServer server = MockServer.start();
        OpenBaoClient client = Fixtures.client(server).namespace("ns").build()) {
      enqueue(server, "init.status");
      assertThat(OpenBaoTesting.initStatus(client)).isFalse();
      server.enqueue(
          200,
          "{\"keys\":[\"k-hex-1\",\"\"],\"keys_base64\":[\"k-b64\"],\"root_token\":\"root-1\"}");
      OpenBaoTesting.InitResult init = OpenBaoTesting.init(client, 1, 1);
      assertThat(init.keys()).hasSize(1);
      assertThat(init.keysBase64()).hasSize(1);
      assertThat(init.recoveryKeys()).isEmpty();
      assertThat(init.recoveryKeysBase64()).isEmpty();
      assertThat(init.rootToken().reveal()).isEqualTo("root-1");
      assertThat(init.toString()).doesNotContain("root-1").doesNotContain("k-hex-1");
      assertThat(server.requests().get(1).body())
          .contains("\"secret_shares\":1")
          .contains("\"secret_threshold\":1");
      assertThat(server.requests().get(1).header("X-Vault-Token")).isNull();
      assertThat(server.requests().get(1).header("X-Vault-Namespace")).isEqualTo("ns");
      server.enqueue(
          200,
          "{\"recovery_keys\":[\"r1\"],\"recovery_keys_base64\":[\"r2\"],\"root_token\":\"root-2\"}");
      assertThat(OpenBaoTesting.initRecovery(client, 1, 1).recoveryKeys()).hasSize(1);
      assertThat(server.requests().get(2).body()).contains("recovery_shares");
      enqueue(server, "init.already-initialized");
      assertThatThrownBy(() -> OpenBaoTesting.init(client, 1, 1))
          .isInstanceOf(ValidationException.class);
      server.enqueue(200, "{\"keys\":[]}");
      assertThatThrownBy(() -> OpenBaoTesting.init(client, 1, 1))
          .isInstanceOf(UnavailableException.class);

      enqueue(server, "unseal.ok");
      SealStatus s = OpenBaoTesting.unseal(client, Secret.of("k-hex-1"));
      assertThat(s.sealed()).isFalse();
      assertThat(server.requests().get(5).body()).isEqualTo("{\"key\":\"k-hex-1\"}");
      enqueue(server, "unseal.invalid-key");
      assertThatThrownBy(() -> OpenBaoTesting.unseal(client, Secret.of("zz")))
          .isInstanceOf(ValidationException.class);
      assertThatThrownBy(() -> OpenBaoTesting.unseal(client, Secret.of(" ")))
          .isInstanceOf(ValidationException.class);
      assertThatThrownBy(() -> OpenBaoTesting.unseal(client, null))
          .isInstanceOf(ValidationException.class);
      enqueue(server, "sealStatus.sealed");
      assertThat(OpenBaoTesting.resetUnseal(client).sealed()).isTrue();
      assertThat(server.requests().get(7).body()).isEqualTo("{\"reset\":true}");
      server.enqueue(200, "");
      assertThatThrownBy(() -> OpenBaoTesting.resetUnseal(client))
          .isInstanceOf(UnavailableException.class);

      enqueue(server, "seal.testing");
      OpenBaoTesting.seal(client);
      assertThat(server.requests().get(9).header("X-Vault-Token")).isEqualTo("root-token-1234");

      enqueue(server, "health.sealed", 200);
      enqueue(server, "health.active");
      HealthResponse h = OpenBaoTesting.waitForActive(client, Duration.ofSeconds(5));
      assertThat(h.state()).isEqualTo("active");
      server.fallback(ex -> MockServer.send(ex, 200, "{\"initialized\":false}"));
      assertThatThrownBy(() -> OpenBaoTesting.waitForActive(client, Duration.ofMillis(300)))
          .isInstanceOf(TimeoutException.class);
    }
    try (MockServer server = MockServer.start();
        OpenBaoClient client = OpenBaoClient.builder().url(server.url()).build()) {
      server.enqueue(204, "");
      OpenBaoTesting.seal(client);
      assertThat(server.requests().get(0).header("X-Vault-Token")).isNull();
    }
  }

  @Test
  void errorMapping() {
    OpenBaoException plain = new ValidationException("x");
    assertThat(VaultHttp.map(plain, true)).isSameAs(plain);
    // plain "permission denied" body (missing/invalid/revoked token) -> AUTHENTICATION
    OpenBaoException plain403 =
        OpenBaoException.of(
            ErrorCode.PERMISSION_DENIED,
            "op: permission denied (HTTP 403)",
            403,
            "rid",
            null,
            null);
    assertThat(VaultHttp.map(plain403, false)).isInstanceOf(AuthenticationException.class);
    assertThat(VaultHttp.map(plain403, false).requestId()).contains("rid");
    // policy denial (wrapped multierror) stays PERMISSION_DENIED except on login endpoints
    OpenBaoException e403 =
        OpenBaoException.of(
            ErrorCode.PERMISSION_DENIED,
            "op: permission denied: 1 error occurred: * permission denied (HTTP 403)",
            403,
            "rid",
            null,
            null);
    assertThat(VaultHttp.map(e403, false)).isSameAs(e403);
    assertThat(VaultHttp.map(e403, true)).isInstanceOf(AuthenticationException.class);
    assertThat(VaultHttp.map(e403, true).requestId()).contains("rid");
    OpenBaoException invalid =
        OpenBaoException.of(
            ErrorCode.PERMISSION_DENIED,
            "op: missing client token (HTTP 403)",
            403,
            null,
            null,
            null);
    assertThat(VaultHttp.map(invalid, false)).isInstanceOf(AuthenticationException.class);
    OpenBaoException e400 =
        OpenBaoException.of(
            ErrorCode.VALIDATION, "op: bad request (HTTP 400)", 400, null, null, null);
    assertThat(VaultHttp.map(e400, false)).isSameAs(e400);
    assertThat(VaultHttp.map(e400, true)).isInstanceOf(AuthenticationException.class);
    OpenBaoException e401 =
        OpenBaoException.of(ErrorCode.AUTHENTICATION, "op (HTTP 401)", 401, null, null, null);
    assertThat(VaultHttp.map(e401, true)).isSameAs(e401);
    OpenBaoException cas =
        OpenBaoException.of(
            ErrorCode.VALIDATION,
            "op: check-and-set parameter did not match the current version (HTTP 400)",
            400,
            null,
            null,
            null);
    assertThat(VaultHttp.map(cas, false)).isInstanceOf(ConflictException.class);
    OpenBaoException e405 =
        OpenBaoException.of(ErrorCode.VALIDATION, "op (HTTP 405)", 405, null, null, null);
    assertThat(VaultHttp.map(e405, false)).isInstanceOf(UnsupportedException.class);
    OpenBaoException e501 =
        OpenBaoException.of(ErrorCode.UNSUPPORTED, "op (HTTP 501)", 501, null, null, null);
    assertThat(VaultHttp.map(e501, false)).isInstanceOf(UnavailableException.class);
    OpenBaoException e404 =
        OpenBaoException.of(ErrorCode.NOT_FOUND, "op (HTTP 404)", 404, null, null, null);
    assertThat(VaultHttp.map(e404, false)).isSameAs(e404);
    assertThat(VaultHttp.map(e403, false)).isInstanceOf(PermissionDeniedException.class);
  }

  @Test
  void rateLimitAndNotFoundFromServer() throws Exception {
    try (MockServer server = MockServer.start();
        OpenBaoClient client =
            Fixtures.client(server)
                .retry(codes.grow.packages.openbao.core.RetryPolicy.none())
                .build()) {
      enqueue(server, "errors.rate-limited");
      assertThatThrownBy(() -> client.kvV1("kv1").read("sdk/allowed/hello"))
          .isInstanceOf(RateLimitException.class)
          .satisfies(
              e ->
                  assertThat(((OpenBaoException) e).retryAfter()).contains(Duration.ofSeconds(29)));
      enqueue(server, "errors.unsupported-path");
      assertThatThrownBy(() -> client.request("GET", "nope/x", null))
          .isInstanceOfAny(
              NotFoundException.class, UnsupportedException.class, ValidationException.class);
      server.enqueue(200, "not json");
      assertThatThrownBy(() -> client.sys().leader()).isInstanceOf(ValidationException.class);
    }
  }

  @Test
  void wireHelpers() {
    assertThat(Wire.trimSlashes("//a/b//")).isEqualTo("a/b");
    assertThat(Wire.encodePath("kv1", "sdk/with space", "", "ü+x"))
        .isEqualTo("kv1/sdk/with%20space/%C3%BC%2Bx");
    assertThat(Wire.join("", "n")).isEqualTo("n");
    assertThat(Wire.join("b", "")).isEqualTo("b");
    assertThat(Wire.join("/b/", "/n")).isEqualTo("b/n");
    assertThat(Wire.duration(Duration.ofMillis(1500))).isEqualTo("2s");
    assertThat(Wire.duration(Duration.ofSeconds(3))).isEqualTo("3s");
    assertThat(Wire.optDuration(null)).isNull();
    assertThatThrownBy(() -> Wire.duration(Duration.ofSeconds(-1)))
        .isInstanceOf(ValidationException.class);
    assertThat(Wire.seconds(null)).isZero();
    assertThat(Wire.seconds(Json.tree("\"x\"".getBytes()))).isZero();
    assertThat(Wire.vaultDuration(null)).isZero();
    assertThat(Wire.vaultDuration(Json.tree("null".getBytes()))).isZero();
    assertThat(Wire.vaultDuration(Json.tree("5".getBytes()))).isEqualTo(Duration.ofSeconds(5));
    assertThat(Wire.vaultDuration(Json.tree("\"7\"".getBytes()))).isEqualTo(Duration.ofSeconds(7));
    assertThat(Wire.vaultDuration(Json.tree("\"1h30m\"".getBytes())))
        .isEqualTo(Duration.ofMinutes(90));
    assertThat(Wire.vaultDuration(Json.tree("\"\"".getBytes()))).isZero();
    assertThat(Wire.vaultDuration(Json.tree("\"bad\"".getBytes()))).isZero();
    assertThat(Wire.time(null)).isEmpty();
    assertThat(Wire.time(Json.tree("null".getBytes()))).isEmpty();
    assertThat(Wire.time(Json.tree("0".getBytes()))).isEmpty();
    assertThat(Wire.time(Json.tree("10".getBytes()))).contains(Instant.ofEpochSecond(10));
    assertThat(Wire.time(Json.tree("\"\"".getBytes()))).isEmpty();
    assertThat(Wire.time(Json.tree("\"nope\"".getBytes()))).isEmpty();
    assertThat(Wire.time(Json.tree("\"2026-01-01T00:00:00Z\"".getBytes()))).isPresent();
    assertThat(Wire.str(null, "a")).isEmpty();
    assertThat(Wire.num(null, "a")).isZero();
    assertThat(Wire.bool(null, "a")).isFalse();
    assertThat(Wire.strings(null)).isEmpty();
    assertThat(Wire.strings(Json.tree("[\"a\",1]".getBytes()))).containsExactly("a");
    assertThat(Wire.stringMap(null)).isEmpty();
    assertThat(Wire.stringMap(Json.tree("{\"a\":\"x\",\"b\":1,\"c\":null}".getBytes())))
        .containsEntry("a", "x")
        .containsEntry("b", "1")
        .doesNotContainKey("c");
    assertThat(Wire.optB64(null)).isNull();
    assertThat(Wire.unb64("AQ==", "op")).isEqualTo(new byte[] {1});
    assertThatThrownBy(() -> Wire.unb64("***", "op")).isInstanceOf(UnavailableException.class);
    assertThat(Wire.optSecret(Json.tree("{\"a\":\"\"}".getBytes()), "a")).isEmpty();
    assertThatThrownBy(() -> Wire.requireText(null, "x", "op"))
        .isInstanceOf(ValidationException.class);
    CompletableFuture<String> failed =
        Wire.orElseOnNotFound(CompletableFuture.failedFuture(new ValidationException("v")), "fb");
    assertThatThrownBy(failed::join).hasCauseInstanceOf(ValidationException.class);
    assertThat(
            Wire.orElseOnNotFound(CompletableFuture.failedFuture(new NotFoundException("n")), "fb")
                .join())
        .isEqualTo("fb");
    assertThat(
            Wire.<String>async(
                    () -> {
                      throw new IllegalStateException("x");
                    })
                .isCompletedExceptionally())
        .isTrue();
  }

  @Test
  void recordsCopyAndRedact() {
    KvMetadata m =
        new KvMetadata(
            false,
            java.util.Optional.empty(),
            java.util.Optional.empty(),
            2,
            0,
            0,
            Duration.ZERO,
            Map.of(),
            Map.of());
    assertThat(m.currentDeleted()).isTrue();
    KvVersionMetadata destroyed =
        new KvVersionMetadata(
            1, java.util.Optional.empty(), java.util.Optional.empty(), true, Map.of());
    assertThat(destroyed.deleted()).isTrue();
    RenewalEvent e = new RenewalEvent("l", Duration.ZERO, false, false, Arrays.asList("w"));
    assertThat(e.warnings()).containsExactly("w");
    assertThat(new Ciphertext("c", 1).ciphertext()).isEqualTo("c");
    assertThat(new LeaseRenewal("l", Duration.ZERO, false, List.of()).warnings()).isEmpty();
    assertThat(new DatabaseCredentials("u", Secret.of("p-1234")).toString())
        .doesNotContain("p-1234");
  }
}
