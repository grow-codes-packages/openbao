package codes.grow.packages.openbao;

import java.time.Instant;
import java.util.Optional;

/**
 * Result of {@link Pki#revokeCertificate(String)}.
 *
 * @param revocationTime revocation time
 * @param state state, e.g. {@code revoked}
 */
public record RevocationInfo(Optional<Instant> revocationTime, String state) {}
