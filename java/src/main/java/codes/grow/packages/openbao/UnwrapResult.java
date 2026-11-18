package codes.grow.packages.openbao;

import java.time.Duration;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * The unwrapped response. Data values are never printed.
 *
 * @param data wrapped data (for wrapped API responses the original {@code data})
 * @param auth auth block when a login response was wrapped
 * @param leaseId lease id of the original response
 * @param leaseDuration lease TTL of the original response
 * @param renewable whether that lease is renewable
 * @param warnings server warnings
 */
public record UnwrapResult(
    Optional<Map<String, Object>> data,
    Optional<AuthInfo> auth,
    String leaseId,
    Duration leaseDuration,
    boolean renewable,
    List<String> warnings) {
  /**
   * Creates the record; collections are copied.
   *
   * @param data data
   * @param auth auth
   * @param leaseId lease id
   * @param leaseDuration TTL
   * @param renewable renewable flag
   * @param warnings warnings
   */
  public UnwrapResult {
    data = data.map(d -> Collections.unmodifiableMap(new LinkedHashMap<>(d)));
    warnings = List.copyOf(warnings);
  }

  @Override
  public String toString() {
    return "UnwrapResult{data="
        + (data.isPresent() ? "[REDACTED]" : "none")
        + ", auth="
        + auth
        + ", leaseId="
        + leaseId
        + "}";
  }
}
