package codes.grow.packages.openbao;

import codes.grow.packages.openbao.core.HttpTransport;
import codes.grow.packages.openbao.core.Secret;
import java.util.concurrent.CompletableFuture;

/**
 * Database secrets engine on one mount: {@code client.database()} (mount {@code database}).
 *
 * <pre>{@code
 * Lease<DatabaseCredentials> lease = client.database().getCredentials("readonly");
 * String user = lease.data().username();
 * }</pre>
 */
public final class Database {
  private final ClientContext ctx;
  private final String mount;

  Database(ClientContext ctx, String mount) {
    this.ctx = ctx;
    this.mount = Wire.trimSlashes(mount);
  }

  /**
   * Returns the mount.
   *
   * @return the mount path
   */
  public String mount() {
    return mount;
  }

  private String path(String kind, String name, String what, String op) {
    return Wire.encodePath(mount, kind, Wire.requireText(name, what, op));
  }

  /**
   * Generates credentials for a role: {@code GET <mount>/creds/<role>}. Unknown roles raise {@code
   * ValidationException}. Never retried blindly (each call creates a user).
   *
   * @param role role name
   * @return the lease with the credentials
   */
  public Lease<DatabaseCredentials> getCredentials(String role) {
    return HttpTransport.await(getCredentialsAsync(role), "database.getCredentials");
  }

  /**
   * Asynchronous {@link #getCredentials(String)}.
   *
   * @param role role name
   * @return a future with the lease
   */
  public CompletableFuture<Lease<DatabaseCredentials>> getCredentialsAsync(String role) {
    String op = "database.getCredentials " + role;
    return Wire.async(
        () ->
            ctx.http
                .call("GET", path("creds", role, "role", op), op)
                .idempotent(false)
                .envelope()
                .thenApply(
                    env -> {
                      if (env == null || !env.path("data").path("username").isTextual()) {
                        throw Wire.unexpected(op, "no credentials in response");
                      }
                      var d = env.get("data");
                      return Lease.from(
                          env,
                          new DatabaseCredentials(
                              d.get("username").asText(), Secret.of(Wire.str(d, "password"))));
                    }));
  }

  /**
   * Creates or replaces a connection: {@code POST <mount>/config/<name>} (verified by default; bad
   * credentials raise {@code ValidationException}).
   *
   * @param name connection name
   * @param config settings
   */
  public void configureConnection(String name, ConnectionConfig config) {
    HttpTransport.await(configureConnectionAsync(name, config), "database.configureConnection");
  }

  /**
   * Asynchronous {@link #configureConnection(String, ConnectionConfig)}.
   *
   * @param name connection name
   * @param c settings
   * @return a future completed when done
   */
  public CompletableFuture<Void> configureConnectionAsync(String name, ConnectionConfig c) {
    String op = "database.configureConnection " + name;
    return Wire.async(
        () -> {
          Wire.Body body = Wire.body();
          c.extra.forEach(body::put);
          body.put("plugin_name", c.pluginName)
              .put("connection_url", c.connectionUrl)
              .put("username", c.username)
              .put("password", c.password == null ? null : c.password.reveal())
              .put("allowed_roles", c.allowedRoles)
              .put("verify_connection", c.verifyConnection);
          return ctx.http
              .call("POST", path("config", name, "name", op), op)
              .json(body.build())
              .run();
        });
  }

  /**
   * Reads a connection (without its password); {@code NotFoundException} when missing.
   *
   * @param name connection name
   * @return the connection
   */
  public ConnectionInfo readConnection(String name) {
    return HttpTransport.await(readConnectionAsync(name), "database.readConnection");
  }

  /**
   * Asynchronous {@link #readConnection(String)}.
   *
   * @param name connection name
   * @return a future with the connection
   */
  public CompletableFuture<ConnectionInfo> readConnectionAsync(String name) {
    String op = "database.readConnection " + name;
    return Wire.async(
        () ->
            ctx.http
                .call("GET", path("config", name, "name", op), op)
                .data()
                .thenApply(
                    d ->
                        new ConnectionInfo(
                            Wire.str(d, "plugin_name"),
                            Wire.strings(d.get("allowed_roles")),
                            Wire.stringMap(d.get("connection_details")))));
  }

  /**
   * Deletes a connection.
   *
   * @param name connection name
   */
  public void deleteConnection(String name) {
    HttpTransport.await(deleteConnectionAsync(name), "database.deleteConnection");
  }

  /**
   * Asynchronous {@link #deleteConnection(String)}.
   *
   * @param name connection name
   * @return a future completed when done
   */
  public CompletableFuture<Void> deleteConnectionAsync(String name) {
    String op = "database.deleteConnection " + name;
    return Wire.async(() -> ctx.http.call("DELETE", path("config", name, "name", op), op).run());
  }

  /**
   * Creates or replaces a dynamic role: {@code POST <mount>/roles/<name>}.
   *
   * @param name role name
   * @param config settings
   */
  public void createRole(String name, RoleConfig config) {
    HttpTransport.await(createRoleAsync(name, config), "database.createRole");
  }

  /**
   * Asynchronous {@link #createRole(String, RoleConfig)}.
   *
   * @param name role name
   * @param c settings
   * @return a future completed when done
   */
  public CompletableFuture<Void> createRoleAsync(String name, RoleConfig c) {
    String op = "database.createRole " + name;
    return Wire.async(
        () ->
            ctx.http
                .call("POST", path("roles", name, "name", op), op)
                .json(
                    Wire.body()
                        .put("db_name", c.dbName)
                        .put("creation_statements", c.creationStatements)
                        .put("revocation_statements", c.revocationStatements)
                        .put("renew_statements", c.renewStatements)
                        .put("rollback_statements", c.rollbackStatements)
                        .put("default_ttl", Wire.optDuration(c.defaultTtl))
                        .put("max_ttl", Wire.optDuration(c.maxTtl))
                        .build())
                .run());
  }

  /**
   * Reads a role; {@code NotFoundException} when missing.
   *
   * @param name role name
   * @return the role
   */
  public RoleInfo readRole(String name) {
    return HttpTransport.await(readRoleAsync(name), "database.readRole");
  }

  /**
   * Asynchronous {@link #readRole(String)}.
   *
   * @param name role name
   * @return a future with the role
   */
  public CompletableFuture<RoleInfo> readRoleAsync(String name) {
    String op = "database.readRole " + name;
    return Wire.async(
        () ->
            ctx.http
                .call("GET", path("roles", name, "name", op), op)
                .data()
                .thenApply(
                    d ->
                        new RoleInfo(
                            Wire.str(d, "db_name"),
                            Wire.strings(d.get("creation_statements")),
                            Wire.strings(d.get("revocation_statements")),
                            Wire.strings(d.get("renew_statements")),
                            Wire.strings(d.get("rollback_statements")),
                            Wire.seconds(d.get("default_ttl")),
                            Wire.seconds(d.get("max_ttl")),
                            Wire.str(d, "credential_type"))));
  }

  /**
   * Deletes a role.
   *
   * @param name role name
   */
  public void deleteRole(String name) {
    HttpTransport.await(deleteRoleAsync(name), "database.deleteRole");
  }

  /**
   * Asynchronous {@link #deleteRole(String)}.
   *
   * @param name role name
   * @return a future completed when done
   */
  public CompletableFuture<Void> deleteRoleAsync(String name) {
    String op = "database.deleteRole " + name;
    return Wire.async(() -> ctx.http.call("DELETE", path("roles", name, "name", op), op).run());
  }

  @Override
  public String toString() {
    return "Database(" + mount + ")";
  }
}
