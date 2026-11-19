package codes.grow.packages.openbao;

import java.util.concurrent.CompletableFuture;

/**
 * An OpenBao auth method ({@link TokenAuth}, {@link AppRoleAuth}, {@link UserpassAuth}, {@link
 * JwtAuth}, {@link KubernetesAuth}) used with {@link Auth#login(AuthMethod)}.
 */
public interface AuthMethod {
  /**
   * Returns the method name, e.g. {@code approle}.
   *
   * @return the name
   */
  String method();

  /**
   * Performs the login.
   *
   * @param context login helpers of the client
   * @return a future with the auth info
   */
  CompletableFuture<AuthInfo> login(LoginContext context);
}
