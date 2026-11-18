package codes.grow.packages.openbao;

import java.time.Duration;
import java.time.Instant;
import java.util.Optional;

/**
 * Properties of a wrapping token ({@link Wrapping#lookupWrapping}); the token stays usable.
 *
 * @param creationPath path that created the wrapped response
 * @param creationTime creation time
 * @param creationTtl validity at creation
 */
public record WrappingLookup(
    String creationPath, Optional<Instant> creationTime, Duration creationTtl) {}
