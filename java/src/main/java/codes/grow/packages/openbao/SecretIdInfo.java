package codes.grow.packages.openbao;

import codes.grow.packages.openbao.core.Secret;
import java.time.Duration;

/**
 * A generated AppRole secret id.
 *
 * @param secretId the secret id (redacted)
 * @param secretIdAccessor its accessor (redacted)
 * @param secretIdNumUses allowed uses (0 = unlimited)
 * @param secretIdTtl TTL (zero = never expires)
 */
public record SecretIdInfo(
    Secret secretId, Secret secretIdAccessor, int secretIdNumUses, Duration secretIdTtl) {}
