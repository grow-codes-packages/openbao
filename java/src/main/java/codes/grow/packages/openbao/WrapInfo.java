package codes.grow.packages.openbao;

import codes.grow.packages.openbao.core.Secret;
import com.fasterxml.jackson.databind.JsonNode;
import java.time.Duration;
import java.time.Instant;
import java.util.Optional;

/**
 * A response-wrapping token ({@code wrap_info}).
 *
 * @param token single-use wrapping token (redacted)
 * @param accessor its accessor
 * @param ttl validity
 * @param creationTime creation time
 * @param creationPath path that created the wrapped response
 */
public record WrapInfo(
    Secret token,
    Optional<Secret> accessor,
    Duration ttl,
    Optional<Instant> creationTime,
    String creationPath) {

  static WrapInfo from(JsonNode w) {
    return new WrapInfo(
        Secret.of(w.get("token").asText()),
        Wire.optSecret(w, "accessor"),
        Wire.seconds(w.get("ttl")),
        Wire.time(w.get("creation_time")),
        Wire.str(w, "creation_path"));
  }
}
