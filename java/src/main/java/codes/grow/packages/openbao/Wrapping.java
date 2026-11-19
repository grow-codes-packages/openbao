package codes.grow.packages.openbao;

import codes.grow.packages.openbao.core.HttpTransport;
import codes.grow.packages.openbao.core.Secret;
import com.fasterxml.jackson.databind.JsonNode;
import java.time.Duration;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;

/**
 * Response wrapping: {@code client.wrapping()}.
 *
 * <pre>{@code
 * WrapInfo w = client.wrapping().wrap(Map.of("password", "s3cret"), Duration.ofMinutes(1));
 * UnwrapResult r = other.wrapping().unwrap(w.token());
 * }</pre>
 */
public final class Wrapping {
  private final ClientContext ctx;

  Wrapping(ClientContext ctx) {
    this.ctx = ctx;
  }

  /**
   * Wraps data in a single-use token: {@code POST sys/wrapping/wrap} with {@code X-Vault-Wrap-TTL}.
   *
   * @param data data to wrap
   * @param ttl validity of the token
   * @return the wrapping token
   */
  public WrapInfo wrap(Map<String, ?> data, Duration ttl) {
    return HttpTransport.await(wrapAsync(data, ttl), "wrapping.wrap");
  }

  /**
   * Asynchronous {@link #wrap(Map, Duration)}.
   *
   * @param data data to wrap
   * @param ttl validity
   * @return a future with the wrapping token
   */
  public CompletableFuture<WrapInfo> wrapAsync(Map<String, ?> data, Duration ttl) {
    return Wire.async(
        () ->
            ctx.http
                .call("POST", "sys/wrapping/wrap", "wrapping.wrap")
                .json(data)
                .wrapTtl(ttl)
                .envelope()
                .thenApply(
                    env -> {
                      JsonNode w = env == null ? null : env.get("wrap_info");
                      if (w == null || !w.path("token").isTextual()) {
                        throw Wire.unexpected("wrapping.wrap", "no wrap_info");
                      }
                      return WrapInfo.from(w);
                    }));
  }

  /**
   * Unwraps a token: {@code POST sys/wrapping/unwrap} authenticated with the wrapping token itself.
   * A used or invalid token raises {@code ValidationException}; never retried.
   *
   * @param token wrapping token
   * @return the original response
   */
  public UnwrapResult unwrap(Secret token) {
    return HttpTransport.await(unwrapAsync(token), "wrapping.unwrap");
  }

  /**
   * Unwraps a token given as text.
   *
   * @param token wrapping token
   * @return the original response
   */
  public UnwrapResult unwrap(String token) {
    return unwrap(Secret.of(token));
  }

  /**
   * Asynchronous {@link #unwrap(Secret)}.
   *
   * @param token wrapping token
   * @return a future with the original response
   */
  public CompletableFuture<UnwrapResult> unwrapAsync(Secret token) {
    return Wire.async(
        () ->
            ctx.http
                .call("POST", "sys/wrapping/unwrap", "wrapping.unwrap")
                .token(Wire.requireText(token.reveal(), "token", "wrapping.unwrap"))
                .maxRetries(0)
                .envelope()
                .thenApply(
                    env -> {
                      if (env == null) {
                        throw Wire.unexpected("wrapping.unwrap", "empty response body");
                      }
                      JsonNode d = env.get("data");
                      JsonNode a = env.get("auth");
                      return new UnwrapResult(
                          d != null && d.isObject() ? Optional.of(Wire.toMap(d)) : Optional.empty(),
                          a != null && a.isObject()
                              ? Optional.of(AuthInfo.fromEnvelope(env, "wrapping.unwrap"))
                              : Optional.empty(),
                          Wire.str(env, "lease_id"),
                          Wire.seconds(env.get("lease_duration")),
                          Wire.bool(env, "renewable"),
                          Wire.strings(env.get("warnings")));
                    }));
  }

  /**
   * Properties of a wrapping token without using it: {@code POST sys/wrapping/lookup}.
   *
   * @param token wrapping token
   * @return the properties
   */
  public WrappingLookup lookupWrapping(Secret token) {
    return HttpTransport.await(lookupWrappingAsync(token), "wrapping.lookupWrapping");
  }

  /**
   * Properties of a wrapping token given as text.
   *
   * @param token wrapping token
   * @return the properties
   */
  public WrappingLookup lookupWrapping(String token) {
    return lookupWrapping(Secret.of(token));
  }

  /**
   * Asynchronous {@link #lookupWrapping(Secret)}.
   *
   * @param token wrapping token
   * @return a future with the properties
   */
  public CompletableFuture<WrappingLookup> lookupWrappingAsync(Secret token) {
    return Wire.async(
        () ->
            ctx.http
                .call("POST", "sys/wrapping/lookup", "wrapping.lookupWrapping")
                .json(
                    Map.of(
                        "token",
                        Wire.requireText(token.reveal(), "token", "wrapping.lookupWrapping")))
                .noToken()
                .idempotent(true)
                .data()
                .thenApply(
                    d ->
                        new WrappingLookup(
                            Wire.str(d, "creation_path"),
                            Wire.time(d.get("creation_time")),
                            Wire.seconds(d.get("creation_ttl")))));
  }
}
