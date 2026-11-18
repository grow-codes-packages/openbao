package codes.grow.packages.openbao;

import codes.grow.packages.openbao.core.HttpTransport;
import codes.grow.packages.openbao.core.Poll;
import codes.grow.packages.openbao.core.Secret;
import com.fasterxml.jackson.databind.JsonNode;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.CompletableFuture;

/**
 * PKI engine on one mount: {@code client.pki()} (mount {@code pki}).
 *
 * <pre>{@code
 * IssuedCertificate cert = client.pki().issueCertificate("web", "app.example.test");
 * }</pre>
 */
public final class Pki {
  private static final Set<String> TIDY_DONE = Set.of("Finished", "Error", "Cancelled");

  private final ClientContext ctx;
  private final String mount;

  Pki(ClientContext ctx, String mount) {
    this.ctx = ctx;
    this.mount = Wire.trimSlashes(mount);
  }

  /**
   * Returns the mount.
   *
   * @return the mount path
   */
  public String mount() {
    return mount;
  }

  private static SignedCertificate signed(JsonNode d, String op) {
    if (!d.path("certificate").isTextual()) {
      throw Wire.unexpected(op, "no certificate");
    }
    return new SignedCertificate(
        d.get("certificate").asText(),
        Wire.str(d, "issuing_ca"),
        Wire.strings(d.get("ca_chain")),
        Wire.str(d, "serial_number"),
        Wire.time(d.get("expiration")));
  }

  private static Optional<java.time.Instant> revocation(JsonNode d) {
    Optional<java.time.Instant> t = Wire.time(d.get("revocation_time_rfc3339"));
    return t.isPresent() ? t : Wire.time(d.get("revocation_time"));
  }

  /**
   * Issues a certificate and private key for a role.
   *
   * @param role role name
   * @param commonName common name
   * @return the certificate and key
   */
  public IssuedCertificate issueCertificate(String role, String commonName) {
    return issueCertificate(role, commonName, IssueOptions.none());
  }

  /**
   * Issues a certificate and private key: {@code POST <mount>/issue/<role>}. A name the role does
   * not allow raises {@code ValidationException}.
   *
   * @param role role name
   * @param commonName common name
   * @param options SANs, TTL, format
   * @return the certificate and key
   */
  public IssuedCertificate issueCertificate(String role, String commonName, IssueOptions options) {
    return HttpTransport.await(
        issueCertificateAsync(role, commonName, options), "pki.issueCertificate");
  }

  /**
   * Asynchronous {@link #issueCertificate(String, String, IssueOptions)}.
   *
   * @param role role name
   * @param commonName common name
   * @param o options
   * @return a future with the certificate and key
   */
  public CompletableFuture<IssuedCertificate> issueCertificateAsync(
      String role, String commonName, IssueOptions o) {
    String op = "pki.issueCertificate " + role;
    return Wire.async(
        () ->
            ctx.http
                .call(
                    "POST", Wire.encodePath(mount, "issue", Wire.requireText(role, "role", op)), op)
                .json(
                    Wire.body()
                        .put("common_name", Wire.requireText(commonName, "commonName", op))
                        .put("alt_names", o.altNamesCsv())
                        .put("ip_sans", o.ipSansCsv())
                        .put("uri_sans", o.uriSansCsv())
                        .put("ttl", Wire.optDuration(o.ttl))
                        .put("format", o.format)
                        .put("private_key_format", o.privateKeyFormat)
                        .put("exclude_cn_from_sans", o.excludeCnFromSans)
                        .build())
                .data()
                .thenApply(
                    d -> {
                      SignedCertificate s = signed(d, op);
                      return new IssuedCertificate(
                          s.certificate(),
                          s.issuingCa(),
                          s.caChain(),
                          s.serialNumber(),
                          s.expiration(),
                          Secret.of(Wire.str(d, "private_key")),
                          Wire.str(d, "private_key_type"));
                    }));
  }

  /**
   * Signs a PEM CSR for a role.
   *
   * @param role role name
   * @param csr PEM certificate signing request
   * @return the certificate
   */
  public SignedCertificate signCsr(String role, String csr) {
    return signCsr(role, csr, IssueOptions.none());
  }

  /**
   * Signs a PEM CSR: {@code POST <mount>/sign/<role>}. Invalid CSRs raise {@code
   * ValidationException}.
   *
   * @param role role name
   * @param csr PEM CSR
   * @param options common name, SANs, TTL, format
   * @return the certificate
   */
  public SignedCertificate signCsr(String role, String csr, IssueOptions options) {
    return HttpTransport.await(signCsrAsync(role, csr, options), "pki.signCsr");
  }

  /**
   * Asynchronous {@link #signCsr(String, String, IssueOptions)}.
   *
   * @param role role name
   * @param csr PEM CSR
   * @param o options
   * @return a future with the certificate
   */
  public CompletableFuture<SignedCertificate> signCsrAsync(
      String role, String csr, IssueOptions o) {
    String op = "pki.signCsr " + role;
    return Wire.async(
        () ->
            ctx.http
                .call(
                    "POST", Wire.encodePath(mount, "sign", Wire.requireText(role, "role", op)), op)
                .json(
                    Wire.body()
                        .put("csr", Wire.requireText(csr, "csr", op))
                        .put("common_name", o.commonName)
                        .put("alt_names", o.altNamesCsv())
                        .put("ip_sans", o.ipSansCsv())
                        .put("uri_sans", o.uriSansCsv())
                        .put("ttl", Wire.optDuration(o.ttl))
                        .put("format", o.format)
                        .put("exclude_cn_from_sans", o.excludeCnFromSans)
                        .build())
                .data()
                .thenApply(d -> signed(d, op)));
  }

  /**
   * Revokes a certificate by serial ({@code aa:bb:...}); unknown serials raise {@code
   * ValidationException}.
   *
   * @param serial serial number
   * @return the revocation info
   */
  public RevocationInfo revokeCertificate(String serial) {
    return HttpTransport.await(revokeCertificateAsync(serial), "pki.revokeCertificate");
  }

  /**
   * Asynchronous {@link #revokeCertificate(String)}.
   *
   * @param serial serial number
   * @return a future with the revocation info
   */
  public CompletableFuture<RevocationInfo> revokeCertificateAsync(String serial) {
    String op = "pki.revokeCertificate " + serial;
    return Wire.async(
        () ->
            ctx.http
                .call("POST", Wire.encodePath(mount, "revoke"), op)
                .json(Map.of("serial_number", Wire.requireText(serial, "serial", op)))
                .idempotent(true)
                .data()
                .thenApply(
                    d -> {
                      String state = Wire.str(d, "state");
                      return new RevocationInfo(revocation(d), state.isEmpty() ? "revoked" : state);
                    }));
  }

  /**
   * The CA chain as PEM text ({@code GET <mount>/ca_chain}, raw PEM).
   *
   * @return PEM text
   */
  public String readCaChain() {
    return HttpTransport.await(readCaChainAsync(), "pki.readCaChain");
  }

  /**
   * Asynchronous {@link #readCaChain()}.
   *
   * @return a future with the PEM text
   */
  public CompletableFuture<String> readCaChainAsync() {
    return ctx.http
        .call("GET", Wire.encodePath(mount, "ca_chain"), "pki.readCaChain")
        .header("Accept", "application/x-pem-file, */*")
        .send()
        .thenApply(r -> r.text());
  }

  /**
   * A certificate by serial; {@code NotFoundException} when unknown.
   *
   * @param serial serial number
   * @return the certificate
   */
  public CertificateInfo readCertificate(String serial) {
    return HttpTransport.await(readCertificateAsync(serial), "pki.readCertificate");
  }

  /**
   * Asynchronous {@link #readCertificate(String)}.
   *
   * @param serial serial number
   * @return a future with the certificate
   */
  public CompletableFuture<CertificateInfo> readCertificateAsync(String serial) {
    String op = "pki.readCertificate " + serial;
    return Wire.async(
        () ->
            ctx.http
                .call(
                    "GET",
                    Wire.encodePath(mount, "cert", Wire.requireText(serial, "serial", op)),
                    op)
                .data()
                .thenApply(
                    d -> {
                      String cert = Wire.str(d, "certificate");
                      if (cert.isEmpty()) {
                        throw Wire.unexpected(op, "no certificate");
                      }
                      return new CertificateInfo(cert, revocation(d));
                    }));
  }

  /**
   * Serials of all stored certificates; empty when there is none.
   *
   * @return the serials
   */
  public List<String> listCertificates() {
    return HttpTransport.await(listCertificatesAsync(), "pki.listCertificates");
  }

  /**
   * Asynchronous {@link #listCertificates()}.
   *
   * @return a future with the serials
   */
  public CompletableFuture<List<String>> listCertificatesAsync() {
    return Wire.orElseOnNotFound(
        ctx.http
            .call("GET", Wire.encodePath(mount, "certs") + "/", "pki.listCertificates")
            .list()
            .data()
            .thenApply(d -> Wire.strings(d.get("keys"))),
        List.of());
  }

  /**
   * Current tidy progress: {@code GET <mount>/tidy-status}.
   *
   * @return the status
   */
  public TidyStatus tidyStatus() {
    return HttpTransport.await(tidyStatusAsync(), "pki.tidyStatus");
  }

  /**
   * Asynchronous {@link #tidyStatus()}.
   *
   * @return a future with the status
   */
  public CompletableFuture<TidyStatus> tidyStatusAsync() {
    return ctx.http
        .call("GET", Wire.encodePath(mount, "tidy-status"), "pki.tidyStatus")
        .data()
        .thenApply(
            d -> {
              String err = Wire.str(d, "error");
              return new TidyStatus(
                  Wire.str(d, "state"),
                  err.isEmpty() ? Optional.empty() : Optional.of(err),
                  Wire.num(d, "cert_store_deleted_count"),
                  Wire.num(d, "revoked_cert_deleted_count"),
                  Wire.time(d.get("time_started")),
                  Wire.time(d.get("time_finished")));
            });
  }

  /**
   * Starts a tidy run and waits until it is done (defaults).
   *
   * @return the last status
   */
  public TidyStatus tidy() {
    return tidy(TidyOptions.defaults());
  }

  /**
   * Starts a tidy run ({@code POST <mount>/tidy}, 202) and, unless {@code await(false)}, polls
   * {@code tidy-status} until it is {@code Finished}, {@code Error} or {@code Cancelled}.
   *
   * @param options options
   * @return the last status
   */
  public TidyStatus tidy(TidyOptions options) {
    return HttpTransport.await(tidyAsync(options), "pki.tidy");
  }

  /**
   * Asynchronous {@link #tidy(TidyOptions)}.
   *
   * @param o options
   * @return a future with the last status
   */
  public CompletableFuture<TidyStatus> tidyAsync(TidyOptions o) {
    return Wire.async(
        () ->
            ctx.http
                .call("POST", Wire.encodePath(mount, "tidy"), "pki.tidy")
                .json(
                    Wire.body()
                        .put("tidy_cert_store", o.tidyCertStore)
                        .put("tidy_revoked_certs", o.tidyRevokedCerts)
                        .put("safety_buffer", Wire.optDuration(o.safetyBuffer))
                        .build())
                .run()
                .thenCompose(
                    v ->
                        o.await
                            ? Poll.untilAsync(
                                "pki.tidy",
                                o.timeout,
                                o.interval,
                                () ->
                                    tidyStatusAsync()
                                        .thenApply(
                                            s ->
                                                TIDY_DONE.contains(s.state())
                                                    ? Optional.of(s)
                                                    : Optional.<TidyStatus>empty()))
                            : tidyStatusAsync()));
  }

  @Override
  public String toString() {
    return "Pki(" + mount + ")";
  }
}
