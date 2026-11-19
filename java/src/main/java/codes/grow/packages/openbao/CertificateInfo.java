package codes.grow.packages.openbao;

import java.time.Instant;
import java.util.Optional;

/**
 * A stored certificate ({@link Pki#readCertificate(String)}).
 *
 * @param certificate PEM certificate
 * @param revocationTime revocation time (empty when not revoked)
 */
public record CertificateInfo(String certificate, Optional<Instant> revocationTime) {}
