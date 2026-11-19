package codes.grow.packages.openbao;

import java.time.Duration;
import java.util.List;

/** Settings of {@link Database#createRole(String, RoleConfig)}. */
public final class RoleConfig {
  final String dbName;
  final List<String> creationStatements;
  final List<String> revocationStatements;
  final List<String> renewStatements;
  final List<String> rollbackStatements;
  final Duration defaultTtl;
  final Duration maxTtl;

  private RoleConfig(Builder b) {
    this.dbName = b.dbName;
    this.creationStatements = b.creationStatements;
    this.revocationStatements = b.revocationStatements;
    this.renewStatements = b.renewStatements;
    this.rollbackStatements = b.rollbackStatements;
    this.defaultTtl = b.defaultTtl;
    this.maxTtl = b.maxTtl;
  }

  /**
   * Starts a builder.
   *
   * @param dbName connection name
   * @param creationStatements SQL that creates the user ({@code {{name}}}, {@code {{password}}},
   *     {@code {{expiration}}} templates)
   * @return a new builder
   */
  public static Builder builder(String dbName, String... creationStatements) {
    return new Builder(dbName, List.of(creationStatements));
  }

  /** Builder of {@link RoleConfig}. */
  public static final class Builder {
    private final String dbName;
    private final List<String> creationStatements;
    private List<String> revocationStatements;
    private List<String> renewStatements;
    private List<String> rollbackStatements;
    private Duration defaultTtl;
    private Duration maxTtl;

    private Builder(String dbName, List<String> creationStatements) {
      this.dbName = dbName;
      this.creationStatements = creationStatements;
    }

    /**
     * Sets the revocation SQL.
     *
     * @param statements statements
     * @return this builder
     */
    public Builder revocationStatements(String... statements) {
      this.revocationStatements = List.of(statements);
      return this;
    }

    /**
     * Sets the renewal SQL.
     *
     * @param statements statements
     * @return this builder
     */
    public Builder renewStatements(String... statements) {
      this.renewStatements = List.of(statements);
      return this;
    }

    /**
     * Sets the rollback SQL.
     *
     * @param statements statements
     * @return this builder
     */
    public Builder rollbackStatements(String... statements) {
      this.rollbackStatements = List.of(statements);
      return this;
    }

    /**
     * Sets the default lease TTL.
     *
     * @param ttl TTL
     * @return this builder
     */
    public Builder defaultTtl(Duration ttl) {
      this.defaultTtl = ttl;
      return this;
    }

    /**
     * Sets the maximum lease TTL.
     *
     * @param ttl TTL
     * @return this builder
     */
    public Builder maxTtl(Duration ttl) {
      this.maxTtl = ttl;
      return this;
    }

    /**
     * Builds the settings.
     *
     * @return the settings
     */
    public RoleConfig build() {
      return new RoleConfig(this);
    }
  }
}
