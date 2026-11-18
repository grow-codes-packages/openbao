package codes.grow.packages.openbao;

import codes.grow.packages.openbao.core.ConfigException;
import codes.grow.packages.openbao.core.Secret;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

/** Username/password login: {@code POST auth/<mount>/login/<username> {password}}. */
public final class UserpassAuth implements AuthMethod {
  private final String mount;
  private final String username;
  private final Secret password;

  /**
   * Creates the method on mount {@code userpass}.
   *
   * @param username user name
   * @param password password
   */
  public UserpassAuth(String username, String password) {
    this(username, password == null ? null : Secret.of(password), "userpass");
  }

  /**
   * Creates the method.
   *
   * @param username user name
   * @param password password
   * @param mount auth mount path
   * @throws ConfigException when the password is empty
   */
  public UserpassAuth(String username, Secret password, String mount) {
    this.username = Wire.requireText(username, "username", "UserpassAuth");
    if (password == null || password.isEmpty()) {
      throw new ConfigException("UserpassAuth: password must not be empty");
    }
    this.password = password;
    this.mount = Wire.trimSlashes(mount == null ? "userpass" : mount);
  }

  @Override
  public String method() {
    return "userpass";
  }

  @Override
  public CompletableFuture<AuthInfo> login(LoginContext context) {
    return context.post(
        Wire.encodePath("auth", mount, "login", username),
        Map.of("password", password.reveal()),
        "auth.userpass.login " + mount);
  }

  @Override
  public String toString() {
    return "UserpassAuth(" + mount + ", username=" + username + ", password=[REDACTED])";
  }
}
