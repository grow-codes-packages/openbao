package codes.grow.packages.openbao;

import java.time.Duration;
import java.util.List;

/**
 * Outcome of one successful renewal (or re-login) reported to {@link
 * RenewalOptions.Builder#onRenew}.
 *
 * @param leaseId lease id ({@code ""} for a token)
 * @param ttl granted time to live
 * @param renewable whether it can be renewed again
 * @param reauthenticated true when a token renewer logged in again instead of renewing
 * @param warnings server warnings (for example "TTL ... is capped")
 */
public record RenewalEvent(
    String leaseId,
    Duration ttl,
    boolean renewable,
    boolean reauthenticated,
    List<String> warnings) {
  /**
   * Creates an event; the warnings are copied.
   *
   * @param leaseId lease id
   * @param ttl granted TTL
   * @param renewable renewable flag
   * @param reauthenticated re-login flag
   * @param warnings warnings
   */
  public RenewalEvent {
    warnings = List.copyOf(warnings);
  }
}
