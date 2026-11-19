package codes.grow.packages.openbao;

import com.fasterxml.jackson.databind.JsonNode;
import java.time.Duration;
import java.util.List;

/**
 * A secret with a lease (for example dynamic database credentials). Keep it alive with {@link
 * LeaseManager#manage(Lease, RenewalOptions)}.
 *
 * @param <T> type of the data
 * @param leaseId lease id, e.g. {@code database/creds/app/abc}
 * @param leaseDuration TTL of the lease
 * @param renewable whether the lease can be renewed
 * @param data the secret data
 * @param warnings server warnings
 */
public record Lease<T>(
    String leaseId, Duration leaseDuration, boolean renewable, T data, List<String> warnings) {
  /**
   * Creates the record; the warnings are copied.
   *
   * @param leaseId lease id
   * @param leaseDuration TTL
   * @param renewable renewable flag
   * @param data data
   * @param warnings warnings
   */
  public Lease {
    warnings = List.copyOf(warnings);
  }

  static <T> Lease<T> from(JsonNode env, T data) {
    return new Lease<>(
        Wire.str(env, "lease_id"),
        Wire.seconds(env.get("lease_duration")),
        Wire.bool(env, "renewable"),
        data,
        Wire.strings(env.get("warnings")));
  }
}
