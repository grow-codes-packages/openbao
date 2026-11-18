package codes.grow.packages.openbao;

import java.util.List;
import java.util.Map;

/**
 * A database connection (without its password).
 *
 * @param pluginName plugin, e.g. {@code postgresql-database-plugin}
 * @param allowedRoles roles allowed to use the connection
 * @param connectionDetails connection details (URL template, user name, ...)
 */
public record ConnectionInfo(
    String pluginName, List<String> allowedRoles, Map<String, String> connectionDetails) {
  /**
   * Creates the record; collections are copied.
   *
   * @param pluginName plugin
   * @param allowedRoles roles
   * @param connectionDetails details
   */
  public ConnectionInfo {
    allowedRoles = List.copyOf(allowedRoles);
    connectionDetails = Map.copyOf(connectionDetails);
  }
}
