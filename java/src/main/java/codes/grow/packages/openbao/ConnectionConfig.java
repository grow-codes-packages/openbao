package codes.grow.packages.openbao;

import codes.grow.packages.openbao.core.Secret;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Settings of {@link Database#configureConnection(String, ConnectionConfig)}. */
public final class ConnectionConfig {
  final String pluginName;
  final String connectionUrl;
  final String username;
  final Secret password;
  final List<String> allowedRoles;
  final Boolean verifyConnection;
  final Map<String, Object> extra;

  private ConnectionConfig(Builder b) {
    this.pluginName = b.pluginName;
    this.connectionUrl = b.connectionUrl;
    this.username = b.username;
    this.password = b.password;
    this.allowedRoles = b.allowedRoles;
    this.verifyConnection = b.verifyConnection;
    this.extra = Map.copyOf(b.extra);
  }

  /**
   * Starts a builder.
   *
   * @param pluginName plugin, e.g. {@code postgresql-database-plugin}
   * @param connectionUrl URL template, e.g. {@code
   *     postgresql://{{username}}:{{password}}@db:5432/app}
   * @return a new builder
   */
  public static Builder builder(String pluginName, String connectionUrl) {
    return new Builder(pluginName, connectionUrl);
  }

  @Override
  public String toString() {
    return "ConnectionConfig{pluginName=" + pluginName + ", password=[REDACTED]}";
  }

  /** Builder of {@link ConnectionConfig}. */
  public static final class Builder {
    private final String pluginName;
    private final String connectionUrl;
    private String username;
    private Secret password;
    private List<String> allowedRoles;
    private Boolean verifyConnection;
    private final Map<String, Object> extra = new LinkedHashMap<>();

    private Builder(String pluginName, String connectionUrl) {
      this.pluginName = pluginName;
      this.connectionUrl = connectionUrl;
    }

    /**
     * Sets the privileged user name.
     *
     * @param username user
     * @return this builder
     */
    public Builder username(String username) {
      this.username = username;
      return this;
    }

    /**
     * Sets the privileged password.
     *
     * @param password password
     * @return this builder
     */
    public Builder password(String password) {
      this.password = password == null ? null : Secret.of(password);
      return this;
    }

    /**
     * Sets the privileged password.
     *
     * @param password password
     * @return this builder
     */
    public Builder password(Secret password) {
      this.password = password;
      return this;
    }

    /**
     * Sets the roles allowed to use the connection.
     *
     * @param roles role names ({@code *} for all)
     * @return this builder
     */
    public Builder allowedRoles(String... roles) {
      this.allowedRoles = List.of(roles);
      return this;
    }

    /**
     * Verifies the connection when it is written (server default true).
     *
     * @param verify flag
     * @return this builder
     */
    public Builder verifyConnection(boolean verify) {
      this.verifyConnection = verify;
      return this;
    }

    /**
     * Adds a plugin-specific field (e.g. {@code max_open_connections}).
     *
     * @param key wire field name
     * @param value value
     * @return this builder
     */
    public Builder extra(String key, Object value) {
      this.extra.put(key, value);
      return this;
    }

    /**
     * Builds the settings.
     *
     * @return the settings
     */
    public ConnectionConfig build() {
      return new ConnectionConfig(this);
    }
  }
}
