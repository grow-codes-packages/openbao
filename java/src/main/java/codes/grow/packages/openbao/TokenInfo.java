package codes.grow.packages.openbao;

import codes.grow.packages.openbao.core.Secret;
import com.fasterxml.jackson.databind.JsonNode;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Properties of a token ({@code auth/token/lookup-self}).
 *
 * @param id the token itself (redacted)
 * @param accessor token accessor
 * @param policies policies
 * @param ttl remaining TTL (zero = never expires)
 * @param creationTtl TTL at creation
 * @param creationTime creation time
 * @param expireTime expiry time
 * @param issueTime issue time
 * @param renewable whether the token can be renewed
 * @param displayName display name ({@code token-<name>})
 * @param meta token metadata
 * @param numUses remaining uses (0 = unlimited)
 * @param orphan whether the token has no parent
 * @param path creation path, e.g. {@code auth/approle/login}
 * @param type {@code service} or {@code batch}
 * @param explicitMaxTtl explicit maximum TTL
 * @param entityId identity entity id
 */
public record TokenInfo(
    Secret id,
    Optional<Secret> accessor,
    List<String> policies,
    Duration ttl,
    Duration creationTtl,
    Optional<Instant> creationTime,
    Optional<Instant> expireTime,
    Optional<Instant> issueTime,
    boolean renewable,
    String displayName,
    Map<String, String> meta,
    int numUses,
    boolean orphan,
    String path,
    String type,
    Duration explicitMaxTtl,
    String entityId) {
  /**
   * Creates the record; collections are copied.
   *
   * @param id token
   * @param accessor accessor
   * @param policies policies
   * @param ttl TTL
   * @param creationTtl creation TTL
   * @param creationTime creation time
   * @param expireTime expiry time
   * @param issueTime issue time
   * @param renewable renewable flag
   * @param displayName display name
   * @param meta metadata
   * @param numUses remaining uses
   * @param orphan orphan flag
   * @param path creation path
   * @param type token type
   * @param explicitMaxTtl explicit max TTL
   * @param entityId entity id
   */
  public TokenInfo {
    policies = List.copyOf(policies);
    meta = Map.copyOf(meta);
  }

  static TokenInfo fromData(JsonNode d) {
    return new TokenInfo(
        Secret.of(Wire.str(d, "id")),
        Wire.optSecret(d, "accessor"),
        Wire.strings(d.get("policies")),
        Wire.seconds(d.get("ttl")),
        Wire.seconds(d.get("creation_ttl")),
        Wire.time(d.get("creation_time")),
        Wire.time(d.get("expire_time")),
        Wire.time(d.get("issue_time")),
        Wire.bool(d, "renewable"),
        Wire.str(d, "display_name"),
        Wire.stringMap(d.get("meta")),
        Wire.num(d, "num_uses"),
        Wire.bool(d, "orphan"),
        Wire.str(d, "path"),
        Wire.str(d, "type"),
        Wire.seconds(d.get("explicit_max_ttl")),
        Wire.str(d, "entity_id"));
  }
}
