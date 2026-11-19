package codes.grow.packages.openbao;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

/**
 * A certificate signed by the PKI engine ({@link Pki#signCsr}).
 *
 * @param certificate PEM certificate
 * @param issuingCa PEM of the issuing CA
 * @param caChain PEM chain
 * @param serialNumber serial, colon hex ({@code 56:f1:...})
 * @param expiration expiry
 */
public record SignedCertificate(
    String certificate,
    String issuingCa,
    List<String> caChain,
    String serialNumber,
    Optional<Instant> expiration) {
  /**
   * Creates the record; the chain is copied.
   *
   * @param certificate certificate
   * @param issuingCa issuing CA
   * @param caChain chain
   * @param serialNumber serial
   * @param expiration expiry
   */
  public SignedCertificate {
    caChain = List.copyOf(caChain);
  }
}
