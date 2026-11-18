package codes.grow.packages.openbao;

import com.fasterxml.jackson.databind.JsonNode;
import java.time.Duration;
import java.util.List;
import java.util.Optional;

/**
 * Result of {@link OpenBaoClient#request}: the decoded OpenBao envelope.
 *
 * @param status HTTP status (204 = no content)
 * @param data {@code data} of the envelope
 * @param leaseId lease id
 * @param leaseDuration lease TTL
 * @param renewable whether the lease is renewable
 * @param warnings server warnings
 * @param wrapInfo set when the response was wrapped
 * @param auth set for login-like responses
 */
public record RawResponse(
    int status,
    Optional<JsonNode> data,
    String leaseId,
    Duration leaseDuration,
    boolean renewable,
    List<String> warnings,
    Optional<WrapInfo> wrapInfo,
    Optional<AuthInfo> auth) {
  /**
   * Creates the record; warnings are copied.
   *
   * @param status status
   * @param data data
   * @param leaseId lease id
   * @param leaseDuration TTL
   * @param renewable renewable flag
   * @param warnings warnings
   * @param wrapInfo wrap info
   * @param auth auth block
   */
  public RawResponse {
    warnings = List.copyOf(warnings);
  }

  @Override
  public String toString() {
    return "RawResponse{status="
        + status
        + ", data="
        + (data.isPresent() ? "[REDACTED]" : "none")
        + "}";
  }

  static RawResponse from(int status, JsonNode env) {
    if (env == null || !env.isObject()) {
      return new RawResponse(
          status,
          Optional.empty(),
          "",
          Duration.ZERO,
          false,
          List.of(),
          Optional.empty(),
          Optional.empty());
    }
    JsonNode d = env.get("data");
    JsonNode w = env.get("wrap_info");
    JsonNode a = env.get("auth");
    return new RawResponse(
        status,
        d == null || d.isNull() ? Optional.empty() : Optional.of(d),
        Wire.str(env, "lease_id"),
        Wire.seconds(env.get("lease_duration")),
        Wire.bool(env, "renewable"),
        Wire.strings(env.get("warnings")),
        w != null && w.path("token").isTextual() ? Optional.of(WrapInfo.from(w)) : Optional.empty(),
        a != null && a.path("client_token").isTextual()
            ? Optional.of(AuthInfo.fromEnvelope(env, "request"))
            : Optional.empty());
  }
}
