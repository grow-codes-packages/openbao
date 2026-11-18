package codes.grow.packages.openbao;

import codes.grow.packages.openbao.core.Secret;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

/** What an {@link AuthMethod} can do during a login (no client token is sent). */
public interface LoginContext {
  /**
   * Posts a login request; 400/401/403 raise {@code AuthenticationException}.
   *
   * @param path path below {@code /v1/}, already encoded (e.g. {@code auth/approle/login})
   * @param body JSON body
   * @param operation operation name for errors
   * @return a future with the {@code auth} block
   */
  CompletableFuture<AuthInfo> post(String path, Map<String, Object> body, String operation);

  /**
   * Looks up a token ({@code auth/token/lookup-self} with that token).
   *
   * @param token the token
   * @return a future with the token properties
   */
  CompletableFuture<TokenInfo> lookup(Secret token);
}
