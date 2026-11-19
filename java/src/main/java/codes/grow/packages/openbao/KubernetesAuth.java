package codes.grow.packages.openbao;

import codes.grow.packages.openbao.core.ConfigException;
import codes.grow.packages.openbao.core.Secret;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

/**
 * Kubernetes login: {@code POST auth/<mount>/login {role, jwt}} with the service account token read
 * from {@code jwtPath} (default {@value #DEFAULT_JWT_PATH}) at login time.
 */
public final class KubernetesAuth implements AuthMethod {
  /** Default service account token path inside a pod. */
  public static final String DEFAULT_JWT_PATH =
      "/var/run/secrets/kubernetes.io/serviceaccount/token";

  private final String mount;
  private final String role;
  private final Path jwtPath;
  private final Secret jwt;

  /**
   * Creates the method on mount {@code kubernetes} with the default token path.
   *
   * @param role role name
   */
  public KubernetesAuth(String role) {
    this(role, Paths.get(DEFAULT_JWT_PATH), "kubernetes");
  }

  /**
   * Creates the method on mount {@code kubernetes}.
   *
   * @param role role name
   * @param jwtPath service account token file
   */
  public KubernetesAuth(String role, String jwtPath) {
    this(role, Paths.get(jwtPath), "kubernetes");
  }

  /**
   * Creates the method.
   *
   * @param role role name
   * @param jwtPath service account token file
   * @param mount auth mount path
   */
  public KubernetesAuth(String role, Path jwtPath, String mount) {
    this(role, jwtPath, null, mount);
  }

  private KubernetesAuth(String role, Path jwtPath, Secret jwt, String mount) {
    this.role = Wire.requireText(role, "role", "KubernetesAuth");
    this.jwtPath = jwtPath;
    this.jwt = jwt;
    this.mount = Wire.trimSlashes(mount == null ? "kubernetes" : mount);
  }

  /**
   * Creates the method with an explicit service account token instead of a file.
   *
   * @param role role name
   * @param jwt service account token
   * @param mount auth mount path
   * @return the method
   * @throws ConfigException when the JWT is empty
   */
  public static KubernetesAuth withJwt(String role, Secret jwt, String mount) {
    if (jwt == null || jwt.isEmpty()) {
      throw new ConfigException("KubernetesAuth: jwt must not be empty");
    }
    return new KubernetesAuth(role, Paths.get(DEFAULT_JWT_PATH), jwt, mount);
  }

  /**
   * Returns the service account token path.
   *
   * @return the path
   */
  public Path jwtPath() {
    return jwtPath;
  }

  @Override
  public String method() {
    return "kubernetes";
  }

  @Override
  public CompletableFuture<AuthInfo> login(LoginContext context) {
    String token;
    if (jwt != null) {
      token = jwt.reveal();
    } else {
      try {
        token = Files.readString(jwtPath, StandardCharsets.UTF_8).trim();
      } catch (IOException | RuntimeException e) {
        return CompletableFuture.failedFuture(
            new ConfigException(
                "auth.kubernetes.login: cannot read the service account token at " + jwtPath));
      }
      if (token.isEmpty()) {
        return CompletableFuture.failedFuture(
            new ConfigException("auth.kubernetes.login: " + jwtPath + " is empty"));
      }
    }
    return context.post(
        Wire.encodePath("auth", mount, "login"),
        Map.of("role", role, "jwt", token),
        "auth.kubernetes.login " + mount);
  }

  @Override
  public String toString() {
    return "KubernetesAuth(" + mount + ", role=" + role + ")";
  }
}
