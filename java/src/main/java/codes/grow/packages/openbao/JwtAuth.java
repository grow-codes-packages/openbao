package codes.grow.packages.openbao;

import codes.grow.packages.openbao.core.ConfigException;
import codes.grow.packages.openbao.core.Secret;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

/** JWT/OIDC login with a JWT: {@code POST auth/<mount>/login {role, jwt}}. */
public final class JwtAuth implements AuthMethod {
  private final String mount;
  private final String role;
  private final Secret jwt;

  /**
   * Creates the method on mount {@code jwt}.
   *
   * @param role role name
   * @param jwt the JWT
   */
  public JwtAuth(String role, String jwt) {
    this(role, jwt == null ? null : Secret.of(jwt), "jwt");
  }

  /**
   * Creates the method.
   *
   * @param role role name
   * @param jwt the JWT
   * @param mount auth mount path
   * @throws ConfigException when the JWT is empty
   */
  public JwtAuth(String role, Secret jwt, String mount) {
    this.role = Wire.requireText(role, "role", "JwtAuth");
    if (jwt == null || jwt.isEmpty()) {
      throw new ConfigException("JwtAuth: jwt must not be empty");
    }
    this.jwt = jwt;
    this.mount = Wire.trimSlashes(mount == null ? "jwt" : mount);
  }

  @Override
  public String method() {
    return "jwt";
  }

  @Override
  public CompletableFuture<AuthInfo> login(LoginContext context) {
    return context.post(
        Wire.encodePath("auth", mount, "login"),
        Map.of("role", role, "jwt", jwt.reveal()),
        "auth.jwt.login " + mount);
  }

  @Override
  public String toString() {
    return "JwtAuth(" + mount + ", role=" + role + ", jwt=[REDACTED])";
  }
}
