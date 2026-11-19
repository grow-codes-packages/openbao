package codes.grow.packages.openbao;

import codes.grow.packages.openbao.core.Secret;
import java.util.concurrent.CompletableFuture;

/**
 * AppRole login: {@code POST auth/<mount>/login {role_id, secret_id}} (default mount {@code
 * approle}).
 */
public final class AppRoleAuth implements AuthMethod {
  private final String mount;
  private final String roleId;
  private final Secret secretId;

  /**
   * Creates the method on mount {@code approle}.
   *
   * @param roleId role id
   * @param secretId secret id, may be null for roles without {@code bind_secret_id}
   */
  public AppRoleAuth(String roleId, String secretId) {
    this(roleId, secretId == null ? null : Secret.of(secretId), "approle");
  }

  /**
   * Creates the method.
   *
   * @param roleId role id
   * @param secretId secret id, may be null
   * @param mount auth mount path
   */
  public AppRoleAuth(String roleId, Secret secretId, String mount) {
    this.roleId = Wire.requireText(roleId, "roleId", "AppRoleAuth");
    this.secretId = secretId;
    this.mount = Wire.trimSlashes(mount == null ? "approle" : mount);
  }

  /**
   * Returns the mount.
   *
   * @return the mount path
   */
  public String mount() {
    return mount;
  }

  @Override
  public String method() {
    return "approle";
  }

  @Override
  public CompletableFuture<AuthInfo> login(LoginContext context) {
    return context.post(
        Wire.encodePath("auth", mount, "login"),
        Wire.body()
            .put("role_id", roleId)
            .put("secret_id", secretId == null ? null : secretId.reveal())
            .build(),
        "auth.approle.login " + mount);
  }

  @Override
  public String toString() {
    return "AppRoleAuth(" + mount + ", roleId=" + roleId + ", secretId=[REDACTED])";
  }
}
