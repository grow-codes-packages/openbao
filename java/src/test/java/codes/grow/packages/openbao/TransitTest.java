package codes.grow.packages.openbao;

import static codes.grow.packages.openbao.Fixtures.enqueue;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import codes.grow.packages.openbao.core.MockServer;
import codes.grow.packages.openbao.core.NotFoundException;
import codes.grow.packages.openbao.core.UnavailableException;
import codes.grow.packages.openbao.core.ValidationException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class TransitTest {
  private MockServer server;
  private OpenBaoClient client;
  private Transit transit;

  @BeforeEach
  void start() throws Exception {
    server = MockServer.start();
    client = Fixtures.client(server).build();
    transit = client.transit();
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
  void keys() {
    assertThat(transit.mount()).isEqualTo("transit");
    assertThat(transit.toString()).isEqualTo("Transit(transit)");
    enqueue(server, "transit.createKey.ok");
    TransitKey k = transit.createKey("k1");
    assertThat(k.type()).isEqualTo("aes256-gcm96");
    assertThat(k.latestVersion()).isEqualTo(1);
    assertThat(k.keys()).containsKey("1");
    assertThat(k.supportsEncryption()).isTrue();
    assertThat(k.autoRotatePeriod()).isZero();
    assertThat(body(0)).isEqualTo("{\"type\":\"aes256-gcm96\"}");
    // empty body (204) -> read back
    server.enqueue(204, "");
    enqueue(server, "transit.readKey.ok");
    assertThat(transit.createKey("k2", "ed25519").name()).startsWith("sdk-");
    assertThat(body(1)).isEqualTo("{\"type\":\"ed25519\"}");
    server.enqueue(200, "{\"data\":null}");
    enqueue(server, "transit.readKey.ok");
    transit.createKey(
        "k3",
        CreateKeyOptions.builder()
            .type("rsa-2048")
            .exportable(true)
            .derived(false)
            .autoRotatePeriod(Duration.ofHours(24))
            .allowPlaintextBackup(false)
            .keySize(32)
            .build());
    assertThat(body(3))
        .contains("\"exportable\":true")
        .contains("\"auto_rotate_period\":\"86400s\"")
        .contains("\"key_size\":32");
    enqueue(server, "transit.readKey.not-found");
    assertThatThrownBy(() -> transit.readKey("nope")).isInstanceOf(NotFoundException.class);
    assertThatThrownBy(() -> transit.readKey("")).isInstanceOf(ValidationException.class);

    enqueue(server, "transit.listKeys.ok");
    assertThat(transit.listKeys()).isNotEmpty();
    assertThat(uri(6)).isEqualTo("/v1/transit/keys/?list=true");
    enqueue(server, "transit.listKeys.paginated");
    transit.listKeys("a", 1);
    assertThat(uri(7)).contains("limit=1").contains("after=a");
    server.enqueue(404, "{\"errors\":[]}");
    assertThat(transit.listKeys()).isEmpty();

    enqueue(server, "transit.rotateKey.ok");
    assertThat(transit.rotateKey("k1").latestVersion()).isEqualTo(2);
    assertThat(uri(9)).isEqualTo("/v1/transit/keys/k1/rotate");
    enqueue(server, "transit.updateKeyConfig.ok");
    transit.updateKeyConfig(
        "k1",
        KeyConfig.builder()
            .deletionAllowed(true)
            .minDecryptionVersion(1)
            .minEncryptionVersion(0)
            .exportable(false)
            .allowPlaintextBackup(false)
            .autoRotatePeriod(Duration.ZERO)
            .build());
    assertThat(body(10))
        .contains("\"deletion_allowed\":true")
        .contains("\"auto_rotate_period\":\"0s\"");
    enqueue(server, "transit.deleteKey.not-allowed");
    assertThatThrownBy(() -> transit.deleteKey("k1")).isInstanceOf(ValidationException.class);
    enqueue(server, "transit.deleteKey.ok");
    transit.deleteKey("k1");
    assertThat(server.requests().get(12).method()).isEqualTo("DELETE");
  }

  @Test
  void encryptDecryptRewrap() {
    enqueue(server, "transit.encrypt.ok");
    Ciphertext ct = transit.encrypt("k", "hello");
    assertThat(ct.ciphertext()).startsWith("vault:v");
    assertThat(ct.keyVersion()).isPositive();
    assertThat(body(0)).isEqualTo("{\"plaintext\":\"aGVsbG8=\"}");
    enqueue(server, "transit.encrypt.ok");
    transit.encrypt(
        "k",
        new byte[] {1},
        TransitOptions.builder()
            .context("ctx".getBytes(StandardCharsets.UTF_8))
            .keyVersion(1)
            .associatedData(new byte[] {2})
            .build());
    assertThat(body(1))
        .contains("\"context\":\"Y3R4\"")
        .contains("\"key_version\":1")
        .contains("\"associated_data\":\"Ag==\"");
    server.enqueue(200, "{\"data\":{}}");
    assertThatThrownBy(() -> transit.encrypt("k", "x")).isInstanceOf(UnavailableException.class);
    enqueue(server, "transit.encrypt.not-base64");
    assertThatThrownBy(() -> transit.encrypt("k", "x")).isInstanceOf(ValidationException.class);

    enqueue(server, "transit.decrypt.ok");
    assertThat(transit.decrypt("k", ct.ciphertext())).isNotEmpty();
    enqueue(server, "transit.decrypt.ok");
    transit.decrypt("k", "vault:v1:x", TransitOptions.builder().context(new byte[] {1}).build());
    assertThat(body(5)).contains("\"context\":\"AQ==\"");
    server.enqueue(200, "{\"data\":{\"plaintext\":\"***\"}}");
    assertThatThrownBy(() -> transit.decrypt("k", "vault:v1:x"))
        .isInstanceOf(UnavailableException.class);
    enqueue(server, "transit.decrypt.invalid");
    assertThatThrownBy(() -> transit.decrypt("k", "vault:v1:AAAA"))
        .isInstanceOf(ValidationException.class);
    enqueue(server, "transit.decrypt.below-min-version");
    assertThatThrownBy(() -> transit.decrypt("k", "vault:v1:AAAA"))
        .isInstanceOf(ValidationException.class);
    assertThatThrownBy(() -> transit.decrypt("k", "")).isInstanceOf(ValidationException.class);

    enqueue(server, "transit.rewrap.ok");
    assertThat(transit.rewrap("k", ct.ciphertext()).ciphertext()).startsWith("vault:v");
    enqueue(server, "transit.rewrap.ok");
    transit.rewrap("k", "vault:v1:x", TransitOptions.builder().keyVersion(2).build());
    assertThat(body(10)).contains("\"key_version\":2");
  }

  @Test
  void batches() {
    enqueue(server, "transit.encryptBatch.ok");
    List<EncryptBatchResult> enc =
        transit.encryptBatch(
            "k",
            List.of(
                EncryptBatchItem.of("one"),
                new EncryptBatchItem(
                    "two".getBytes(StandardCharsets.UTF_8), new byte[] {1}, "r2")));
    assertThat(enc).hasSize(2);
    assertThat(enc.get(0).ciphertext()).isPresent();
    assertThat(enc.get(0).keyVersion()).hasValue(2);
    assertThat(enc.get(0).reference()).isEmpty();
    assertThat(enc.get(1).reference()).contains("r2");
    assertThat(body(0))
        .contains("\"partial_failure_response_code\":207")
        .contains("{\"plaintext\":\"b25l\"}")
        .contains("\"reference\":\"r2\"");
    assertThat(EncryptBatchItem.of("secret").toString()).doesNotContain("secret\"");

    enqueue(server, "transit.decryptBatch.partial-207");
    List<DecryptBatchResult> dec =
        transit.decryptBatch(
            "k",
            List.of(
                DecryptBatchItem.of("vault:v2:x"),
                new DecryptBatchItem("vault:v1:AAAA", new byte[] {1}, "r")));
    assertThat(new String(dec.get(0).plaintext().get(), StandardCharsets.UTF_8)).isEqualTo("one");
    assertThat(dec.get(1).error()).contains("invalid ciphertext length");
    assertThat(dec.get(1).plaintext()).isEmpty();
    assertThat(dec.get(0).toString()).contains("[REDACTED]");
    assertThat(dec.get(1).toString()).contains("plaintext=none");
    assertThat(DecryptBatchItem.of("c").toString()).contains("ciphertext=c");
    server.enqueue(
        200, "{\"data\":{\"batch_results\":[{\"error\":\"bad\"},{\"key_version\":\"x\"}]}}");
    List<EncryptBatchResult> failed =
        transit.encryptBatch("k", List.of(EncryptBatchItem.of("a"), EncryptBatchItem.of("b")));
    assertThat(failed.get(0).error()).contains("bad");
    assertThat(failed.get(1).keyVersion()).isEmpty();
    server.enqueue(200, "{\"data\":{\"other\":1}}");
    assertThatThrownBy(() -> transit.encryptBatch("k", List.of(EncryptBatchItem.of("a"))))
        .isInstanceOf(UnavailableException.class);
    assertThat(transit.encryptBatch("k", List.of())).isEmpty();
    assertThat(transit.decryptBatch("k", List.of())).isEmpty();
    assertThat(server.requests()).hasSize(4);
  }

  @Test
  void dataKeysAndUtilities() {
    enqueue(server, "transit.generateDataKey.plaintext");
    DataKey dk = transit.generateDataKey("k");
    assertThat(dk.plaintext().get()).hasSize(32);
    assertThat(dk.keyVersion()).isEqualTo(1);
    assertThat(dk.toString()).contains("[REDACTED]");
    assertThat(uri(0)).isEqualTo("/v1/transit/datakey/plaintext/k");
    enqueue(server, "transit.generateDataKey.wrapped");
    DataKey wrapped = transit.generateDataKey("k", false, 128);
    assertThat(wrapped.plaintext()).isEmpty();
    assertThat(wrapped.toString()).contains("plaintext=none");
    assertThat(uri(1)).isEqualTo("/v1/transit/datakey/wrapped/k");
    assertThat(body(1)).isEqualTo("{\"bits\":128}");

    enqueue(server, "transit.hmac.ok");
    String hmac = transit.hmac("k", "in".getBytes(StandardCharsets.UTF_8));
    assertThat(hmac).startsWith("vault:v");
    enqueue(server, "transit.hmac.ok");
    transit.hmac(
        "k",
        new byte[] {1},
        TransitOptions.builder().hashAlgorithm("sha2-512").keyVersion(1).build());
    assertThat(uri(3)).isEqualTo("/v1/transit/hmac/k/sha2-512");
    server.enqueue(200, "{\"data\":{}}");
    assertThatThrownBy(() -> transit.hmac("k", new byte[] {1}))
        .isInstanceOf(UnavailableException.class);

    enqueue(server, "transit.sign.ed25519");
    Signature sig = transit.sign("sdk-sign", "sign-me".getBytes(StandardCharsets.UTF_8));
    assertThat(sig.signature()).startsWith("vault:v1:");
    assertThat(sig.keyVersion()).isEqualTo(1);
    enqueue(server, "transit.sign.rsa-pkcs1v15");
    transit.sign(
        "sdk-rsa",
        new byte[] {1},
        TransitOptions.builder()
            .hashAlgorithm("sha2-256")
            .signatureAlgorithm("pkcs1v15")
            .prehashed(false)
            .build());
    assertThat(uri(6)).isEqualTo("/v1/transit/sign/sdk-rsa/sha2-256");
    assertThat(body(6)).contains("\"signature_algorithm\":\"pkcs1v15\"");
    enqueue(server, "transit.sign.unsupported-key-type");
    assertThatThrownBy(() -> transit.sign("k", new byte[] {1}))
        .isInstanceOf(ValidationException.class);
    server.enqueue(200, "{\"data\":{}}");
    assertThatThrownBy(() -> transit.sign("k", new byte[] {1}))
        .isInstanceOf(UnavailableException.class);

    enqueue(server, "transit.verify.valid");
    assertThat(transit.verify("k", new byte[] {1}, sig.signature())).isTrue();
    enqueue(server, "transit.verify.invalid");
    assertThat(
            transit.verify(
                "k",
                new byte[] {1},
                "vault:v1:bad",
                TransitOptions.builder().hashAlgorithm("sha2-256").build()))
        .isFalse();
    assertThat(uri(10)).isEqualTo("/v1/transit/verify/k/sha2-256");
    enqueue(server, "transit.verify.hmac-valid");
    assertThat(transit.verifyHmac("k", new byte[] {1}, hmac)).isTrue();
    assertThat(body(11)).contains("\"hmac\":");
    assertThatThrownBy(
            () ->
                transit.verifyAsync("k", new byte[] {1}, null, null, TransitOptions.none()).join())
        .hasCauseInstanceOf(ValidationException.class);
    assertThatThrownBy(
            () -> transit.verifyAsync("k", new byte[] {1}, "a", "b", TransitOptions.none()).join())
        .hasCauseInstanceOf(ValidationException.class);

    enqueue(server, "transit.hash.default-hex");
    assertThat(transit.hash("in".getBytes(StandardCharsets.UTF_8))).isNotEmpty();
    assertThat(uri(12)).isEqualTo("/v1/transit/hash");
    enqueue(server, "transit.hash.base64");
    transit.hash(new byte[] {1}, "sha2-256", "base64");
    assertThat(uri(13)).isEqualTo("/v1/transit/hash/sha2-256");
    assertThat(body(13)).contains("\"format\":\"base64\"");
    server.enqueue(200, "{\"data\":{}}");
    assertThatThrownBy(() -> transit.hash(new byte[] {1})).isInstanceOf(UnavailableException.class);

    enqueue(server, "transit.randomBytes.base64");
    assertThat(transit.randomBytes(16)).isNotEmpty();
    assertThat(body(15)).contains("\"bytes\":16").contains("\"format\":\"base64\"");
    enqueue(server, "transit.randomBytes.hex");
    assertThat(transit.randomBytes(8, "hex")).matches("[0-9a-f]+");
    enqueue(server, "transit.randomBytes.hex");
    transit.randomBytesAsync(8, null).join();
    server.enqueue(200, "{\"data\":{}}");
    assertThatThrownBy(() -> transit.randomBytes(8)).isInstanceOf(UnavailableException.class);
    assertThatThrownBy(() -> transit.randomBytes(0)).isInstanceOf(ValidationException.class);
  }

  @Test
  void customMount() {
    Transit t = client.transit("/enc/");
    enqueue(server, "transit.encrypt.ok");
    t.encrypt("k", "x");
    assertThat(uri(0)).isEqualTo("/v1/enc/encrypt/k");
  }
}
