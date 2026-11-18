package codes.grow.packages.openbao;

import static codes.grow.packages.openbao.Fixtures.enqueue;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import codes.grow.packages.openbao.core.MockServer;
import codes.grow.packages.openbao.core.NotFoundException;
import codes.grow.packages.openbao.core.TimeoutException;
import codes.grow.packages.openbao.core.UnavailableException;
import codes.grow.packages.openbao.core.ValidationException;
import java.time.Duration;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class PkiTest {
  private MockServer server;
  private OpenBaoClient client;
  private Pki pki;

  @BeforeEach
  void start() throws Exception {
    server = MockServer.start();
    client = Fixtures.client(server).build();
    pki = client.pki();
  }

  @AfterEach
  void stop() {
    client.close();
    server.close();
  }

  @Test
  void issueSignRevoke() {
    assertThat(pki.mount()).isEqualTo("pki");
    assertThat(pki.toString()).isEqualTo("Pki(pki)");
    enqueue(server, "pki.issueCertificate.ok");
    IssuedCertificate cert =
        pki.issueCertificate(
            "sdk-test",
            "svc.example.test",
            IssueOptions.builder()
                .altNames("alt.example.test", "b.example.test")
                .ipSans("127.0.0.1")
                .uriSans("spiffe://x")
                .ttl(Duration.ofHours(1))
                .format("pem")
                .privateKeyFormat("pkcs8")
                .excludeCnFromSans(false)
                .build());
    assertThat(cert.certificate()).startsWith("-----BEGIN CERTIFICATE-----");
    assertThat(cert.caChain()).isNotEmpty();
    assertThat(cert.issuingCa()).isNotEmpty();
    assertThat(cert.serialNumber()).contains(":");
    assertThat(cert.expiration()).isPresent();
    assertThat(cert.privateKeyType()).isEqualTo("ec");
    assertThat(cert.toString()).doesNotContain("PRIVATE KEY");
    assertThat(server.requests().get(0).body())
        .contains("\"alt_names\":\"alt.example.test,b.example.test\"")
        .contains("\"ip_sans\":\"127.0.0.1\"")
        .contains("\"uri_sans\":\"spiffe://x\"")
        .contains("\"ttl\":\"3600s\"")
        .contains("\"private_key_format\":\"pkcs8\"");
    enqueue(server, "pki.issueCertificate.ok");
    pki.issueCertificate("sdk-test", "a.example.test");
    assertThat(server.requests().get(1).body()).isEqualTo("{\"common_name\":\"a.example.test\"}");
    enqueue(server, "pki.issueCertificate.not-allowed");
    assertThatThrownBy(() -> pki.issueCertificate("sdk-test", "evil.example.com"))
        .isInstanceOf(ValidationException.class);
    server.enqueue(200, "{\"data\":{}}");
    assertThatThrownBy(() -> pki.issueCertificate("r", "c"))
        .isInstanceOf(UnavailableException.class);
    assertThatThrownBy(() -> pki.issueCertificate("r", "")).isInstanceOf(ValidationException.class);

    enqueue(server, "pki.signCsr.ok");
    SignedCertificate signed =
        pki.signCsr(
            "sdk-test",
            "-----BEGIN CERTIFICATE REQUEST-----",
            IssueOptions.builder().commonName("c.example.test").build());
    assertThat(signed.certificate()).startsWith("-----BEGIN");
    assertThat(server.requests().get(4).body()).contains("\"common_name\":\"c.example.test\"");
    enqueue(server, "pki.signCsr.invalid");
    assertThatThrownBy(() -> pki.signCsr("sdk-test", "garbage"))
        .isInstanceOf(ValidationException.class);

    enqueue(server, "pki.revokeCertificate.ok");
    RevocationInfo rev = pki.revokeCertificate("1b:51");
    assertThat(rev.state()).isEqualTo("revoked");
    assertThat(rev.revocationTime()).isPresent();
    server.enqueue(200, "{\"data\":{\"revocation_time\":1795033751}}");
    RevocationInfo rev2 = pki.revokeCertificate("1b:52");
    assertThat(rev2.state()).isEqualTo("revoked");
    assertThat(rev2.revocationTime()).isPresent();
    enqueue(server, "pki.revokeCertificate.not-found");
    assertThatThrownBy(() -> pki.revokeCertificate("ff:ff"))
        .isInstanceOf(ValidationException.class);
  }

  @Test
  void readAndList() {
    enqueue(server, "pki.readCaChain.pem");
    assertThat(pki.readCaChain()).startsWith("-----BEGIN CERTIFICATE-----");
    enqueue(server, "pki.readCertificate.ok");
    CertificateInfo c = pki.readCertificate("1b:51");
    assertThat(c.certificate()).startsWith("-----BEGIN");
    assertThat(c.revocationTime()).isEmpty();
    enqueue(server, "pki.readCertificate.revoked");
    assertThat(pki.readCertificate("1b:51").revocationTime()).isPresent();
    enqueue(server, "pki.readCertificate.not-found");
    assertThatThrownBy(() -> pki.readCertificate("ff")).isInstanceOf(NotFoundException.class);
    server.enqueue(200, "{\"data\":{\"certificate\":\"\"}}");
    assertThatThrownBy(() -> pki.readCertificate("ff")).isInstanceOf(UnavailableException.class);
    enqueue(server, "pki.listCertificates.ok");
    assertThat(pki.listCertificates()).isNotEmpty();
    assertThat(server.requests().get(5).uri()).isEqualTo("/v1/pki/certs/?list=true");
    server.enqueue(404, "{\"errors\":[]}");
    assertThat(pki.listCertificates()).isEmpty();
  }

  @Test
  void tidy() {
    enqueue(server, "pki.tidy.accepted");
    server.enqueue(200, "{\"data\":{\"state\":\"Running\",\"error\":null}}");
    enqueue(server, "pki.tidyStatus.finished");
    TidyStatus s =
        pki.tidy(
            TidyOptions.builder()
                .safetyBuffer(Duration.ofSeconds(1))
                .interval(Duration.ofMillis(5))
                .timeout(Duration.ofSeconds(5))
                .build());
    assertThat(s.state()).isEqualTo("Finished");
    assertThat(s.error()).isEmpty();
    assertThat(s.timeStarted()).isPresent();
    assertThat(server.requests().get(0).body())
        .isEqualTo(
            "{\"tidy_cert_store\":true,\"tidy_revoked_certs\":true,\"safety_buffer\":\"1s\"}");
    // no wait
    enqueue(server, "pki.tidy.accepted");
    server.enqueue(200, "{\"data\":{\"state\":\"Running\",\"error\":\"boom\"}}");
    TidyStatus running =
        pki.tidy(
            TidyOptions.builder()
                .await(false)
                .tidyCertStore(false)
                .tidyRevokedCerts(false)
                .build());
    assertThat(running.state()).isEqualTo("Running");
    assertThat(running.error()).contains("boom");
    // timeout while still running
    enqueue(server, "pki.tidy.accepted");
    server.fallback(ex -> MockServer.send(ex, 200, "{\"data\":{\"state\":\"Running\"}}"));
    assertThatThrownBy(
            () ->
                pki.tidy(
                    TidyOptions.builder()
                        .interval(Duration.ofMillis(5))
                        .timeout(Duration.ofMillis(50))
                        .build()))
        .isInstanceOf(TimeoutException.class);
    assertThat(TidyOptions.defaults()).isNotNull();
    assertThat(pki.tidyStatus().state()).isEqualTo("Running");
    enqueue(server, "pki.tidy.accepted");
    server.fallback(ex -> MockServer.send(ex, 200, "{\"data\":{\"state\":\"Finished\"}}"));
    assertThat(pki.tidy().state()).isEqualTo("Finished");
  }
}
