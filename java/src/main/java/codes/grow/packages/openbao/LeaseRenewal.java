package codes.grow.packages.openbao;

import java.time.Duration;
import java.util.List;

/**
 * Result of {@link LeaseManager#renew(String, Duration)}.
 *
 * @param leaseId lease id
 * @param leaseDuration granted TTL (capped by the maximum TTL; see {@code warnings})
 * @param renewable whether it can be renewed again
 * @param warnings server warnings
 */
public record LeaseRenewal(
    String leaseId, Duration leaseDuration, boolean renewable, List<String> warnings) {
  /**
   * Creates the record; the warnings are copied.
   *
   * @param leaseId lease id
   * @param leaseDuration TTL
   * @param renewable renewable flag
   * @param warnings warnings
   */
  public LeaseRenewal {
    warnings = List.copyOf(warnings);
  }
}
