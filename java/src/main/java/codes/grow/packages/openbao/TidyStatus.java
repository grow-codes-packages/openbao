package codes.grow.packages.openbao;

import java.time.Instant;
import java.util.Optional;

/**
 * Progress of a PKI tidy run ({@code GET <mount>/tidy-status}).
 *
 * @param state {@code Inactive}, {@code Running}, {@code Finished}, {@code Error} or {@code
 *     Cancelled}
 * @param error error text
 * @param certStoreDeletedCount certificates removed
 * @param revokedCertDeletedCount revoked entries removed
 * @param timeStarted start time
 * @param timeFinished end time
 */
public record TidyStatus(
    String state,
    Optional<String> error,
    int certStoreDeletedCount,
    int revokedCertDeletedCount,
    Optional<Instant> timeStarted,
    Optional<Instant> timeFinished) {}
