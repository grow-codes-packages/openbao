package codes.grow.packages.openbao;

import codes.grow.packages.openbao.core.HttpTransport;
import codes.grow.packages.openbao.core.Json;
import codes.grow.packages.openbao.core.UnsupportedException;
import com.fasterxml.jackson.databind.JsonNode;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

/**
 * System backend: {@code client.sys()} (health, seal status, leader, policies, mounts, auth
 * methods, AppRole admin). Most write calls need a privileged (root or sudo) token.
 */
public final class Sys {
  private final ClientContext ctx;

  Sys(ClientContext ctx) {
    this.ctx = ctx;
  }

  private static <T> T await(CompletableFuture<T> f, String op) {
    return HttpTransport.await(f, op);
  }

  private CompletableFuture<JsonNode> raw(String path, String op, boolean health) {
    return raw(path, op, health, false);
  }

  private CompletableFuture<JsonNode> raw(String path, String op, boolean health, boolean probe) {
    VaultHttp.Call c = ctx.http.call("GET", path, op).noToken();
    if (probe) {
      c.maxRetries(0);
    }
    if (health) {
      c.query("uninitcode", 200)
          .query("sealedcode", 200)
          .query("standbycode", 200)
          .query("performancestandbycode", 200);
    }
    return c.envelope()
        .thenApply(
            b -> {
              if (b == null || !b.isObject()) {
                throw Wire.unexpected(op, "empty response body");
              }
              return b;
            });
  }

  /**
   * {@code GET sys/health} (unauthenticated). Sealed, standby and uninitialised nodes are no error.
   *
   * @return the health
   */
  public HealthResponse health() {
    return await(healthAsync(), "sys.health");
  }

  /**
   * Asynchronous {@link #health()}.
   *
   * @return a future with the health
   */
  public CompletableFuture<HealthResponse> healthAsync() {
    return raw("sys/health", "sys.health", true).thenApply(HealthResponse::from);
  }

  /** One health probe without retries (used by {@code client.health()}). */
  CompletableFuture<HealthResponse> probeAsync() {
    return raw("sys/health", "health", true, true).thenApply(HealthResponse::from);
  }

  /**
   * {@code GET sys/seal-status} (unauthenticated).
   *
   * @return the seal status
   */
  public SealStatus sealStatus() {
    return await(sealStatusAsync(), "sys.sealStatus");
  }

  /**
   * Asynchronous {@link #sealStatus()}.
   *
   * @return a future with the seal status
   */
  public CompletableFuture<SealStatus> sealStatusAsync() {
    return raw("sys/seal-status", "sys.sealStatus", false).thenApply(SealStatus::from);
  }

  /**
   * {@code GET sys/leader} (unauthenticated).
   *
   * @return the leader status
   */
  public LeaderStatus leader() {
    return await(leaderAsync(), "sys.leader");
  }

  /**
   * Asynchronous {@link #leader()}.
   *
   * @return a future with the leader status
   */
  public CompletableFuture<LeaderStatus> leaderAsync() {
    return raw("sys/leader", "sys.leader", false)
        .thenApply(
            d ->
                new LeaderStatus(
                    Wire.bool(d, "ha_enabled"),
                    Wire.bool(d, "is_self"),
                    Wire.time(d.get("active_time")),
                    Wire.str(d, "leader_address"),
                    Wire.str(d, "leader_cluster_address")));
  }

  /**
   * Server version from {@code sys/health}; {@code UnsupportedException} when none is reported.
   *
   * @return the version, e.g. {@code 2.7.2}
   */
  public String version() {
    return await(versionAsync(), "sys.version");
  }

  /**
   * Asynchronous {@link #version()}.
   *
   * @return a future with the version
   */
  public CompletableFuture<String> versionAsync() {
    return healthAsync()
        .thenApply(
            h -> {
              if (h.version().isEmpty()) {
                throw new UnsupportedException("sys.version: the server reports no version");
              }
              return h.version();
            });
  }

  // ---- policies ----

  private static String policyPath(String name, String op) {
    return Wire.encodePath("sys/policies/acl", Wire.requireText(name, "name", op));
  }

  /**
   * Creates or replaces an ACL policy: {@code PUT sys/policies/acl/<name>}. Invalid HCL raises
   * {@code ValidationException}.
   *
   * @param name policy name
   * @param policy HCL text
   */
  public void writePolicy(String name, String policy) {
    await(writePolicyAsync(name, policy), "sys.writePolicy");
  }

  /**
   * Asynchronous {@link #writePolicy(String, String)}.
   *
   * @param name policy name
   * @param policy HCL text
   * @return a future completed when done
   */
  public CompletableFuture<Void> writePolicyAsync(String name, String policy) {
    String op = "sys.writePolicy " + name;
    return Wire.async(
        () ->
            ctx.http
                .call("PUT", policyPath(name, op), op)
                .json(Map.of("policy", Wire.requireText(policy, "policy", op)))
                .run());
  }

  /**
   * Reads an ACL policy; {@code NotFoundException} when missing.
   *
   * @param name policy name
   * @return the policy
   */
  public Policy readPolicy(String name) {
    return await(readPolicyAsync(name), "sys.readPolicy");
  }

  /**
   * Asynchronous {@link #readPolicy(String)}.
   *
   * @param name policy name
   * @return a future with the policy
   */
  public CompletableFuture<Policy> readPolicyAsync(String name) {
    String op = "sys.readPolicy " + name;
    return Wire.async(
        () ->
            ctx.http
                .call("GET", policyPath(name, op), op)
                .data()
                .thenApply(
                    d -> {
                      String n = Wire.str(d, "name");
                      return new Policy(n.isEmpty() ? name : n, Wire.str(d, "policy"));
                    }));
  }

  /**
   * ACL policy names (includes {@code default} and {@code root}).
   *
   * @return the names
   */
  public List<String> listPolicies() {
    return await(listPoliciesAsync(), "sys.listPolicies");
  }

  /**
   * Asynchronous {@link #listPolicies()}.
   *
   * @return a future with the names
   */
  public CompletableFuture<List<String>> listPoliciesAsync() {
    return ctx.http
        .call("GET", "sys/policies/acl", "sys.listPolicies")
        .list()
        .data()
        .thenApply(d -> Wire.strings(d.get("keys")));
  }

  /**
   * Deletes an ACL policy.
   *
   * @param name policy name
   */
  public void deletePolicy(String name) {
    await(deletePolicyAsync(name), "sys.deletePolicy");
  }

  /**
   * Asynchronous {@link #deletePolicy(String)}.
   *
   * @param name policy name
   * @return a future completed when done
   */
  public CompletableFuture<Void> deletePolicyAsync(String name) {
    String op = "sys.deletePolicy " + name;
    return Wire.async(() -> ctx.http.call("DELETE", policyPath(name, op), op).run());
  }

  // ---- mounts ----

  private static Map<String, MountInfo> mounts(JsonNode d) {
    Map<String, MountInfo> out = new LinkedHashMap<>();
    for (Map.Entry<String, JsonNode> e : d.properties()) {
      if (e.getValue().isObject() && e.getValue().has("type")) {
        out.put(e.getKey(), MountInfo.from(e.getValue()));
      }
    }
    return Collections.unmodifiableMap(out);
  }

  /**
   * Secrets engines by path ({@code "secret/"} to info).
   *
   * @return the mounts
   */
  public Map<String, MountInfo> listMounts() {
    return await(listMountsAsync(), "sys.listMounts");
  }

  /**
   * Asynchronous {@link #listMounts()}.
   *
   * @return a future with the mounts
   */
  public CompletableFuture<Map<String, MountInfo>> listMountsAsync() {
    return ctx.http.call("GET", "sys/mounts", "sys.listMounts").data().thenApply(Sys::mounts);
  }

  private CompletableFuture<Void> enable(
      String base, String kind, String path, String type, EnableOptions o, boolean engine) {
    String op = "sys." + kind + " " + path;
    return Wire.async(
        () ->
            ctx.http
                .call(
                    "POST",
                    Wire.encodePath(base, Wire.requireText(Wire.trimSlashes(path), "path", op)),
                    op)
                .json(
                    Wire.body()
                        .put("type", Wire.requireText(type, "type", op))
                        .put("description", o.description)
                        .put("options", engine ? o.options : null)
                        .put("config", o.config())
                        .put("local", o.local)
                        .put("seal_wrap", engine ? o.sealWrap : null)
                        .build())
                .run());
  }

  private CompletableFuture<Void> disable(String base, String kind, String path) {
    String op = "sys." + kind + " " + path;
    return Wire.async(
        () ->
            ctx.http
                .call(
                    "DELETE",
                    Wire.encodePath(base, Wire.requireText(Wire.trimSlashes(path), "path", op)),
                    op)
                .run());
  }

  /**
   * Enables a secrets engine at {@code path}. A used path raises {@code ValidationException}.
   *
   * @param path mount path
   * @param type engine type, e.g. {@code kv}, {@code transit}
   */
  public void enableSecretsEngine(String path, String type) {
    enableSecretsEngine(path, type, EnableOptions.none());
  }

  /**
   * Enables a secrets engine with options.
   *
   * @param path mount path
   * @param type engine type
   * @param options options (e.g. {@code option("version", "2")})
   */
  public void enableSecretsEngine(String path, String type, EnableOptions options) {
    await(enableSecretsEngineAsync(path, type, options), "sys.enableSecretsEngine");
  }

  /**
   * Asynchronous {@link #enableSecretsEngine(String, String, EnableOptions)}.
   *
   * @param path mount path
   * @param type engine type
   * @param options options
   * @return a future completed when done
   */
  public CompletableFuture<Void> enableSecretsEngineAsync(
      String path, String type, EnableOptions options) {
    return enable("sys/mounts", "enableSecretsEngine", path, type, options, true);
  }

  /**
   * Disables (unmounts) a secrets engine; its data is deleted.
   *
   * @param path mount path
   */
  public void disableSecretsEngine(String path) {
    await(disableSecretsEngineAsync(path), "sys.disableSecretsEngine");
  }

  /**
   * Asynchronous {@link #disableSecretsEngine(String)}.
   *
   * @param path mount path
   * @return a future completed when done
   */
  public CompletableFuture<Void> disableSecretsEngineAsync(String path) {
    return disable("sys/mounts", "disableSecretsEngine", path);
  }

  /**
   * Auth methods by path ({@code "approle/"} to info).
   *
   * @return the auth mounts
   */
  public Map<String, MountInfo> listAuthMethods() {
    return await(listAuthMethodsAsync(), "sys.listAuthMethods");
  }

  /**
   * Asynchronous {@link #listAuthMethods()}.
   *
   * @return a future with the auth mounts
   */
  public CompletableFuture<Map<String, MountInfo>> listAuthMethodsAsync() {
    return ctx.http.call("GET", "sys/auth", "sys.listAuthMethods").data().thenApply(Sys::mounts);
  }

  /**
   * Enables an auth method at {@code path}.
   *
   * @param path mount path
   * @param type method type, e.g. {@code approle}, {@code userpass}
   */
  public void enableAuthMethod(String path, String type) {
    enableAuthMethod(path, type, EnableOptions.none());
  }

  /**
   * Enables an auth method with options.
   *
   * @param path mount path
   * @param type method type
   * @param options options
   */
  public void enableAuthMethod(String path, String type, EnableOptions options) {
    await(enableAuthMethodAsync(path, type, options), "sys.enableAuthMethod");
  }

  /**
   * Asynchronous {@link #enableAuthMethod(String, String, EnableOptions)}.
   *
   * @param path mount path
   * @param type method type
   * @param options options
   * @return a future completed when done
   */
  public CompletableFuture<Void> enableAuthMethodAsync(
      String path, String type, EnableOptions options) {
    return enable("sys/auth", "enableAuthMethod", path, type, options, false);
  }

  /**
   * Disables an auth method; its tokens are revoked.
   *
   * @param path mount path
   */
  public void disableAuthMethod(String path) {
    await(disableAuthMethodAsync(path), "sys.disableAuthMethod");
  }

  /**
   * Asynchronous {@link #disableAuthMethod(String)}.
   *
   * @param path mount path
   * @return a future completed when done
   */
  public CompletableFuture<Void> disableAuthMethodAsync(String path) {
    return disable("sys/auth", "disableAuthMethod", path);
  }

  // ---- AppRole admin ----

  private static String rolePath(String mount, String name, String op, String... rest) {
    String[] parts = new String[4 + rest.length];
    parts[0] = "auth";
    parts[1] = mount == null ? "approle" : mount;
    parts[2] = "role";
    parts[3] = Wire.requireText(name, "name", op);
    System.arraycopy(rest, 0, parts, 4, rest.length);
    return Wire.encodePath(parts);
  }

  /**
   * Creates or updates an AppRole role.
   *
   * @param name role name
   * @param options role settings and mount
   */
  public void createAppRole(String name, AppRoleOptions options) {
    await(createAppRoleAsync(name, options), "sys.createAppRole");
  }

  /**
   * Asynchronous {@link #createAppRole(String, AppRoleOptions)}.
   *
   * @param name role name
   * @param o options
   * @return a future completed when done
   */
  public CompletableFuture<Void> createAppRoleAsync(String name, AppRoleOptions o) {
    String op = "sys.createAppRole " + name;
    return Wire.async(
        () ->
            ctx.http
                .call("POST", rolePath(o.mount, name, op), op)
                .json(
                    Wire.body()
                        .put("token_policies", o.tokenPolicies)
                        .put("token_ttl", Wire.optDuration(o.tokenTtl))
                        .put("token_max_ttl", Wire.optDuration(o.tokenMaxTtl))
                        .put("secret_id_ttl", Wire.optDuration(o.secretIdTtl))
                        .put("secret_id_num_uses", o.secretIdNumUses)
                        .put("bind_secret_id", o.bindSecretId)
                        .put("token_type", o.tokenType)
                        .build())
                .run());
  }

  /**
   * AppRole role names on mount {@code approle}; empty when there is none.
   *
   * @return the names
   */
  public List<String> listAppRoles() {
    return listAppRoles("approle");
  }

  /**
   * AppRole role names on a mount.
   *
   * @param mount AppRole mount
   * @return the names
   */
  public List<String> listAppRoles(String mount) {
    return await(listAppRolesAsync(mount), "sys.listAppRoles");
  }

  /**
   * Asynchronous {@link #listAppRoles(String)}.
   *
   * @param mount AppRole mount
   * @return a future with the names
   */
  public CompletableFuture<List<String>> listAppRolesAsync(String mount) {
    return Wire.orElseOnNotFound(
        ctx.http
            .call("GET", Wire.encodePath("auth", mount, "role"), "sys.listAppRoles")
            .list()
            .data()
            .thenApply(d -> Wire.strings(d.get("keys"))),
        List.of());
  }

  /**
   * Deletes an AppRole role on mount {@code approle}.
   *
   * @param name role name
   */
  public void deleteAppRole(String name) {
    deleteAppRole(name, "approle");
  }

  /**
   * Deletes an AppRole role.
   *
   * @param name role name
   * @param mount AppRole mount
   */
  public void deleteAppRole(String name, String mount) {
    await(deleteAppRoleAsync(name, mount), "sys.deleteAppRole");
  }

  /**
   * Asynchronous {@link #deleteAppRole(String, String)}.
   *
   * @param name role name
   * @param mount AppRole mount
   * @return a future completed when done
   */
  public CompletableFuture<Void> deleteAppRoleAsync(String name, String mount) {
    String op = "sys.deleteAppRole " + name;
    return Wire.async(() -> ctx.http.call("DELETE", rolePath(mount, name, op), op).run());
  }

  /**
   * The role id of an AppRole role on mount {@code approle}; {@code NotFoundException} for unknown
   * roles.
   *
   * @param name role name
   * @return the role id
   */
  public String readRoleId(String name) {
    return readRoleId(name, "approle");
  }

  /**
   * The role id of an AppRole role.
   *
   * @param name role name
   * @param mount AppRole mount
   * @return the role id
   */
  public String readRoleId(String name, String mount) {
    return await(readRoleIdAsync(name, mount), "sys.readRoleId");
  }

  /**
   * Asynchronous {@link #readRoleId(String, String)}.
   *
   * @param name role name
   * @param mount AppRole mount
   * @return a future with the role id
   */
  public CompletableFuture<String> readRoleIdAsync(String name, String mount) {
    String op = "sys.readRoleId " + name;
    return Wire.async(
        () ->
            ctx.http
                .call("GET", rolePath(mount, name, op, "role-id"), op)
                .data()
                .thenApply(
                    d -> {
                      if (!d.path("role_id").isTextual()) {
                        throw Wire.unexpected(op, "no role_id");
                      }
                      return d.get("role_id").asText();
                    }));
  }

  /**
   * Generates a new secret id for an AppRole role on mount {@code approle}.
   *
   * @param name role name
   * @return the secret id
   */
  public SecretIdInfo generateSecretId(String name) {
    return generateSecretId(name, SecretIdOptions.none());
  }

  /**
   * Generates a new secret id with options.
   *
   * @param name role name
   * @param options metadata, CIDRs, TTL, uses, mount
   * @return the secret id
   */
  public SecretIdInfo generateSecretId(String name, SecretIdOptions options) {
    return await(generateSecretIdAsync(name, options), "sys.generateSecretId");
  }

  /**
   * Asynchronous {@link #generateSecretId(String, SecretIdOptions)}.
   *
   * @param name role name
   * @param o options
   * @return a future with the secret id
   */
  public CompletableFuture<SecretIdInfo> generateSecretIdAsync(String name, SecretIdOptions o) {
    String op = "sys.generateSecretId " + name;
    return Wire.async(
        () ->
            ctx.http
                .call("POST", rolePath(o.mount, name, op, "secret-id"), op)
                .json(
                    Wire.body()
                        .put("metadata", o.metadata == null ? null : Json.stringify(o.metadata))
                        .put("cidr_list", o.cidrList)
                        .put("ttl", Wire.optDuration(o.ttl))
                        .put("num_uses", o.numUses)
                        .build())
                .data()
                .thenApply(
                    d -> {
                      if (!d.path("secret_id").isTextual()) {
                        throw Wire.unexpected(op, "no secret_id");
                      }
                      return new SecretIdInfo(
                          codes.grow.packages.openbao.core.Secret.of(d.get("secret_id").asText()),
                          codes.grow.packages.openbao.core.Secret.of(
                              Wire.str(d, "secret_id_accessor")),
                          Wire.num(d, "secret_id_num_uses"),
                          Wire.seconds(d.get("secret_id_ttl")));
                    }));
  }
}
