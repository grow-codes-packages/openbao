package codes.grow.packages.openbao;

import java.time.Duration;
import java.util.List;

/**
 * A database role.
 *
 * @param dbName connection name
 * @param creationStatements SQL run to create a user
 * @param revocationStatements SQL run to drop a user
 * @param renewStatements SQL run on renewal
 * @param rollbackStatements SQL run on failure
 * @param defaultTtl default lease TTL
 * @param maxTtl maximum lease TTL
 * @param credentialType credential type, e.g. {@code password}
 */
public record RoleInfo(
    String dbName,
    List<String> creationStatements,
    List<String> revocationStatements,
    List<String> renewStatements,
    List<String> rollbackStatements,
    Duration defaultTtl,
    Duration maxTtl,
    String credentialType) {
  /**
   * Creates the record; lists are copied.
   *
   * @param dbName connection name
   * @param creationStatements creation SQL
   * @param revocationStatements revocation SQL
   * @param renewStatements renew SQL
   * @param rollbackStatements rollback SQL
   * @param defaultTtl default TTL
   * @param maxTtl max TTL
   * @param credentialType credential type
   */
  public RoleInfo {
    creationStatements = List.copyOf(creationStatements);
    revocationStatements = List.copyOf(revocationStatements);
    renewStatements = List.copyOf(renewStatements);
    rollbackStatements = List.copyOf(rollbackStatements);
  }
}
