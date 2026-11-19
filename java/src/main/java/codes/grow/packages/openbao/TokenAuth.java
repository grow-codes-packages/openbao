package codes.grow.packages.openbao;

import codes.grow.packages.openbao.core.ConfigException;
import codes.grow.packages.openbao.core.Secret;
import java.util.concurrent.CompletableFuture;

/** Uses an existing token ({@code X-Vault-Token}); {@code login} checks it with lookup-self. */
public final class TokenAuth implements AuthMethod {
  private final Secret token;

  /**
   * Creates the method.
   *
   * @param token the token
   * @throws ConfigException when the token is empty
   */
  public TokenAuth(String token) {
    this(token == null ? null : Secret.of(token));
  }

  /**
   * Creates the method.
   *
   * @param token the token
   * @throws ConfigException when the token is empty
   */
  public TokenAuth(Secret token) {
    if (token == null || token.isEmpty()) {
      throw new ConfigException("TokenAuth: token must not be empty");
    }
    this.token = token;
  }

  @Override
  public String method() {
    return "token";
  }

  @Override
  public CompletableFuture<AuthInfo> login(LoginContext context) {
    return context
        .lookup(token)
        .thenApply(
            info ->
                new AuthInfo(
                    token,
                    info.accessor(),
                    info.policies(),
                    info.policies(),
                    info.meta(),
                    info.ttl(),
                    info.renewable(),
                    info.entityId(),
                    info.type(),
                    info.orphan(),
                    info.numUses()));
  }

  @Override
  public String toString() {
    return "TokenAuth([REDACTED])";
  }
}
