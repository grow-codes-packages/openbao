package codes.grow.packages.openbao;

import codes.grow.packages.openbao.core.Secret;
import java.time.Instant;
import java.util.List;
import java.util.Optional;

/**
 * A certificate and private key issued by the PKI engine ({@link Pki#issueCertificate}).
 *
 * @param certificate PEM certificate
 * @param issuingCa PEM of the issuing CA
 * @param caChain PEM chain
 * @param serialNumber serial, colon hex
 * @param expiration expiry
 * @param privateKey PEM private key (redacted)
 * @param privateKeyType key type, e.g. {@code ec}, {@code rsa}
 */
public record IssuedCertificate(
    String certificate,
    String issuingCa,
    List<String> caChain,
    String serialNumber,
    Optional<Instant> expiration,
    Secret privateKey,
    String privateKeyType) {
  /**
   * Creates the record; the chain is copied.
   *
   * @param certificate certificate
   * @param issuingCa issuing CA
   * @param caChain chain
   * @param serialNumber serial
   * @param expiration expiry
   * @param privateKey private key
   * @param privateKeyType key type
   */
  public IssuedCertificate {
    caChain = List.copyOf(caChain);
  }
}
