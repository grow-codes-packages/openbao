package codes.grow.packages.openbao;

import codes.grow.packages.openbao.core.HttpTransport;
import codes.grow.packages.openbao.core.Secret;
import codes.grow.packages.openbao.core.ValidationException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Logins, token self-service and token renewal: {@code client.auth()}.
 *
 * <pre>{@code
 * AuthInfo info = client.auth().login(new AppRoleAuth(roleId, secretId));
 * TokenInfo self = client.auth().lookupSelf();
 * }</pre>
 */
public final class Auth {
  private final ClientContext ctx;
  private final Set<TokenRenewer> renewers = ConcurrentHashMap.newKeySet();

  Auth(ClientContext ctx) {
    this.ctx = ctx;
  }

  /**
   * Logs in with an auth method and uses the new token for this client. Failed logins raise {@code
   * AuthenticationException}.
   *
   * @param method auth method
   * @return the auth info
   */
  public AuthInfo login(AuthMethod method) {
    return HttpTransport.await(loginAsync(method, LoginOptions.defaults()), "auth.login");
  }

  /**
   * Logs in with options (keep the current token, automatic renewal).
   *
   * @param method auth method
   * @param options login options
   * @return the auth info
   */
  public AuthInfo login(AuthMethod method, LoginOptions options) {
    return HttpTransport.await(loginAsync(method, options), "auth.login");
  }

  /**
   * Asynchronous {@link #login(AuthMethod)}.
   *
   * @param method auth method
   * @return a future with the auth info
   */
  public CompletableFuture<AuthInfo> loginAsync(AuthMethod method) {
    return loginAsync(method, LoginOptions.defaults());
  }

  /**
   * Asynchronous {@link #login(AuthMethod, LoginOptions)}.
   *
   * @param method auth method
   * @param options login options
   * @return a future with the auth info
   */
  public CompletableFuture<AuthInfo> loginAsync(AuthMethod method, LoginOptions options) {
    LoginContext context =
        new LoginContext() {
          @Override
          public CompletableFuture<AuthInfo> post(
              String path, Map<String, Object> body, String operation) {
            return ctx.http
                .call("POST", path, operation)
                .json(body)
                .noToken()
                .login()
                .envelope()
                .thenApply(env -> AuthInfo.fromEnvelope(env, operation));
          }

          @Override
          public CompletableFuture<TokenInfo> lookup(Secret token) {
            return Auth.this.lookup(token.reveal(), true);
          }
        };
    CompletableFuture<AuthInfo> f;
    try {
      f = method.login(context);
    } catch (RuntimeException e) {
      f = CompletableFuture.failedFuture(e);
    }
    return f.thenCompose(
        info -> {
          if (options.setToken()) {
            ctx.token.set(info.clientToken());
          }
          if (options.autoRenew().isEmpty()) {
            return CompletableFuture.completedFuture(info);
          }
          TokenRenewer r = track(new TokenRenewer(this, options.autoRenew().get(), method));
          return r.start(info).thenApply(x -> info);
        });
  }

  private CompletableFuture<TokenInfo> lookup(String token, boolean login) {
    VaultHttp.Call c = ctx.http.call("GET", "auth/token/lookup-self", "auth.lookupSelf");
    if (token != null) {
      c.token(token);
    }
    if (login) {
      c.login();
    }
    return c.data().thenApply(TokenInfo::fromData);
  }

  /**
   * Properties of the client token: {@code GET auth/token/lookup-self}.
   *
   * @return the token info
   */
  public TokenInfo lookupSelf() {
    return HttpTransport.await(lookupSelfAsync(), "auth.lookupSelf");
  }

  /**
   * Asynchronous {@link #lookupSelf()}.
   *
   * @return a future with the token info
   */
  public CompletableFuture<TokenInfo> lookupSelfAsync() {
    return lookup(null, false);
  }

  /**
   * Renews the client token with the server default increment.
   *
   * @return the new auth info ({@code leaseDuration} = granted TTL)
   */
  public AuthInfo renewSelf() {
    return renewSelf(null);
  }

  /**
   * Renews the client token: {@code POST auth/token/renew-self}. The granted TTL may be capped by
   * the maximum TTL. Non-renewable tokens raise {@code ValidationException}.
   *
   * @param increment requested TTL, may be null
   * @return the new auth info
   */
  public AuthInfo renewSelf(Duration increment) {
    return HttpTransport.await(renewSelfAsync(increment), "auth.renewSelf");
  }

  /**
   * Asynchronous {@link #renewSelf(Duration)}.
   *
   * @param increment requested TTL, may be null
   * @return a future with the new auth info
   */
  public CompletableFuture<AuthInfo> renewSelfAsync(Duration increment) {
    String op = "auth.renewSelf";
    try {
      return ctx.http
          .call("POST", "auth/token/renew-self", op)
          .json(Wire.body().put("increment", Wire.optDuration(increment)).build())
          .envelope()
          .thenApply(env -> AuthInfo.fromEnvelope(env, op));
    } catch (ValidationException e) {
      return CompletableFuture.failedFuture(e);
    }
  }

  /**
   * Revokes the client token ({@code POST auth/token/revoke-self}), stops the renewers and forgets
   * the token.
   */
  public void revokeSelf() {
    HttpTransport.await(revokeSelfAsync(), "auth.revokeSelf");
  }

  /**
   * Asynchronous {@link #revokeSelf()}.
   *
   * @return a future completed when the token is revoked
   */
  public CompletableFuture<Void> revokeSelfAsync() {
    return ctx.http
        .call("POST", "auth/token/revoke-self", "auth.revokeSelf")
        .run()
        .thenRun(
            () -> {
              stopRenewers();
              ctx.token.set(null);
            });
  }

  /**
   * Creates a child (or orphan) token: {@code POST auth/token/create[/<role>]}.
   *
   * @param options token options
   * @return the auth info of the new token (the client keeps its own token)
   */
  public AuthInfo createToken(CreateTokenOptions options) {
    return HttpTransport.await(createTokenAsync(options), "auth.createToken");
  }

  /**
   * Asynchronous {@link #createToken(CreateTokenOptions)}.
   *
   * @param o token options
   * @return a future with the auth info
   */
  public CompletableFuture<AuthInfo> createTokenAsync(CreateTokenOptions o) {
    String op = "auth.createToken";
    try {
      if (o.numUses != null && o.numUses < 0) {
        throw new ValidationException(op + ": numUses must be >= 0");
      }
      String path =
          o.role == null ? "auth/token/create" : Wire.encodePath("auth/token/create", o.role);
      Map<String, Object> body =
          Wire.body()
              .put("policies", o.policies)
              .put("ttl", Wire.optDuration(o.ttl))
              .put("explicit_max_ttl", Wire.optDuration(o.explicitMaxTtl))
              .put("renewable", o.renewable)
              .put("display_name", o.displayName)
              .put("meta", o.meta)
              .put("num_uses", o.numUses)
              .put("no_parent", o.noParent)
              .put("no_default_policy", o.noDefaultPolicy)
              .put("period", Wire.optDuration(o.period))
              .build();
      return ctx.http
          .call("POST", path, op)
          .json(body)
          .envelope()
          .thenApply(env -> AuthInfo.fromEnvelope(env, op));
    } catch (ValidationException e) {
      return CompletableFuture.failedFuture(e);
    }
  }

  /**
   * Starts a {@link TokenRenewer} for the current client token (reads its TTL with {@link
   * #lookupSelf()}). Stopped by {@code client.close()}.
   *
   * @param options renewal options
   * @return the running renewer
   */
  public TokenRenewer startRenewer(RenewalOptions options) {
    return HttpTransport.await(startRenewerAsync(options), "auth.startRenewer");
  }

  /**
   * Asynchronous {@link #startRenewer(RenewalOptions)}.
   *
   * @param options renewal options
   * @return a future with the running renewer
   */
  public CompletableFuture<TokenRenewer> startRenewerAsync(RenewalOptions options) {
    TokenRenewer r = track(new TokenRenewer(this, options, null));
    return r.start(null)
        .whenComplete(
            (x, err) -> {
              if (err != null) {
                r.close();
              }
            });
  }

  private TokenRenewer track(TokenRenewer r) {
    renewers.add(r);
    return r;
  }

  void forget(TokenRenewer r) {
    renewers.remove(r);
  }

  /**
   * Returns the number of active renewers.
   *
   * @return the count
   */
  public int activeRenewers() {
    return renewers.size();
  }

  /** Stops every renewer started through this API. Idempotent. */
  public void stopRenewers() {
    for (TokenRenewer r : new ArrayList<>(renewers)) {
      r.close();
    }
  }

  List<TokenRenewer> renewers() {
    return List.copyOf(renewers);
  }
}
