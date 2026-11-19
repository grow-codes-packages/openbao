package codes.grow.packages.openbao;

import codes.grow.packages.openbao.core.Secret;
import com.fasterxml.jackson.databind.JsonNode;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * The {@code auth} block of a login, token creation or renewal. Tokens are {@link Secret}s and
 * never printed.
 *
 * @param clientToken the client token
 * @param accessor token accessor, when returned
 * @param policies all policies of the token
 * @param tokenPolicies policies attached to the token itself
 * @param metadata auth metadata (e.g. {@code role_name}, {@code username})
 * @param leaseDuration token TTL (zero = never expires)
 * @param renewable whether the token can be renewed
 * @param entityId identity entity id
 * @param tokenType {@code service} or {@code batch}
 * @param orphan whether the token has no parent
 * @param numUses remaining uses (0 = unlimited)
 */
public record AuthInfo(
    Secret clientToken,
    Optional<Secret> accessor,
    List<String> policies,
    List<String> tokenPolicies,
    Map<String, String> metadata,
    Duration leaseDuration,
    boolean renewable,
    String entityId,
    String tokenType,
    boolean orphan,
    int numUses) {
  /**
   * Creates the record; collections are copied.
   *
   * @param clientToken token
   * @param accessor accessor
   * @param policies policies
   * @param tokenPolicies token policies
   * @param metadata metadata
   * @param leaseDuration TTL
   * @param renewable renewable flag
   * @param entityId entity id
   * @param tokenType token type
   * @param orphan orphan flag
   * @param numUses remaining uses
   */
  public AuthInfo {
    policies = List.copyOf(policies);
    tokenPolicies = List.copyOf(tokenPolicies);
    metadata = Map.copyOf(metadata);
  }

  /**
   * Converts the {@code auth} block of an envelope.
   *
   * @param env envelope, may be null
   * @param operation operation name for errors
   * @return the auth info
   */
  static AuthInfo fromEnvelope(JsonNode env, String operation) {
    JsonNode a = env == null ? null : env.get("auth");
    if (a == null || !a.isObject() || !a.path("client_token").isTextual()) {
      throw Wire.unexpected(operation, "response has no auth block");
    }
    return new AuthInfo(
        Secret.of(a.get("client_token").asText()),
        Wire.optSecret(a, "accessor"),
        Wire.strings(a.get("policies")),
        Wire.strings(a.get("token_policies")),
        Wire.stringMap(a.get("metadata")),
        Wire.seconds(a.get("lease_duration")),
        Wire.bool(a, "renewable"),
        Wire.str(a, "entity_id"),
        Wire.str(a, "token_type"),
        Wire.bool(a, "orphan"),
        Wire.num(a, "num_uses"));
  }
}
