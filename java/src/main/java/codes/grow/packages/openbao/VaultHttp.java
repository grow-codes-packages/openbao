package codes.grow.packages.openbao;

import codes.grow.packages.openbao.core.ErrorCode;
import codes.grow.packages.openbao.core.HttpTransport;
import codes.grow.packages.openbao.core.Json;
import codes.grow.packages.openbao.core.OpenBaoException;
import codes.grow.packages.openbao.core.Secret;
import codes.grow.packages.openbao.core.TransportRequest;
import codes.grow.packages.openbao.core.TransportResponse;
import com.fasterxml.jackson.databind.JsonNode;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.function.Supplier;
import java.util.regex.Pattern;

/**
 * OpenBao HTTP layer on top of the shared transport: {@code /v1/} prefix, {@code X-Vault-Token},
 * {@code X-Vault-Namespace}, LIST, response wrapping and the OpenBao-specific error mapping.
 */
final class VaultHttp {
  private static final Pattern AUTH_403 =
      Pattern.compile(
          "invalid token|token not found|missing client token", Pattern.CASE_INSENSITIVE);
  private static final Pattern CAS_MISMATCH =
      Pattern.compile("check-and-set parameter did not match", Pattern.CASE_INSENSITIVE);

  private final HttpTransport transport;
  private final Supplier<Secret> token;
  private final String namespace;

  VaultHttp(HttpTransport transport, Supplier<Secret> token, String namespace) {
    this.transport = transport;
    this.token = token;
    this.namespace = namespace;
  }

  HttpTransport transport() {
    return transport;
  }

  /**
   * Applies the OpenBao status mapping on top of the SPEC defaults: login endpoints map 400/401/403
   * to {@code AUTHENTICATION}; a 403 naming an invalid or missing token is {@code AUTHENTICATION}
   * (other 403 stay {@code PERMISSION_DENIED}); a CAS mismatch (400) is {@code CONFLICT}; 405 is
   * {@code UNSUPPORTED}; 501 (not initialised) is {@code UNAVAILABLE}.
   *
   * @param err the transport error
   * @param login whether the call was a login
   * @return the mapped error (the same instance when nothing changes)
   */
  static OpenBaoException map(OpenBaoException err, boolean login) {
    if (err.httpStatus().isEmpty()) {
      return err;
    }
    int status = err.httpStatus().getAsInt();
    String msg = String.valueOf(err.getMessage());
    ErrorCode code = null;
    if (login && (status == 400 || status == 401 || status == 403)) {
      code = ErrorCode.AUTHENTICATION;
    } else if (status == 403 && AUTH_403.matcher(msg).find()) {
      code = ErrorCode.AUTHENTICATION;
    } else if (status == 400 && CAS_MISMATCH.matcher(msg).find()) {
      code = ErrorCode.CONFLICT;
    } else if (status == 405) {
      code = ErrorCode.UNSUPPORTED;
    } else if (status == 501) {
      code = ErrorCode.UNAVAILABLE;
    }
    if (code == null || code == err.code()) {
      return err;
    }
    return OpenBaoException.of(
        code,
        msg,
        status,
        err.requestId().orElse(null),
        err.retryAfter().orElse(null),
        err.getCause());
  }

  /** Starts a call. */
  Call call(String method, String path, String operation) {
    return new Call(method, path, operation);
  }

  /** One OpenBao API call (fluent, single use). */
  final class Call {
    private final String method;
    private final String path;
    private final String operation;
    private final Map<String, Object> query = new LinkedHashMap<>();
    private final Map<String, String> headers = new LinkedHashMap<>();
    private Object json;
    private String contentType = "application/json";
    private Boolean idempotent;
    private int[] accept = new int[0];
    private boolean noToken;
    private String tokenOverride;
    private boolean login;
    private Integer maxRetries;

    private Call(String method, String path, String operation) {
      this.method = method;
      this.path = path;
      this.operation = operation;
    }

    Call query(String name, Object value) {
      if (value != null) {
        query.put(name, value);
      }
      return this;
    }

    Call list() {
      return query("list", "true");
    }

    Call json(Object body) {
      this.json = body;
      return this;
    }

    Call contentType(String contentType) {
      this.contentType = contentType;
      return this;
    }

    Call header(String name, String value) {
      headers.put(name, value);
      return this;
    }

    Call wrapTtl(Duration ttl) {
      return header("X-Vault-Wrap-TTL", Wire.duration(ttl));
    }

    Call idempotent(boolean idempotent) {
      this.idempotent = idempotent;
      return this;
    }

    Call accept(int... statuses) {
      this.accept = statuses.clone();
      return this;
    }

    Call noToken() {
      this.noToken = true;
      return this;
    }

    Call token(String token) {
      this.tokenOverride = token;
      return this;
    }

    Call login() {
      this.login = true;
      return this;
    }

    Call maxRetries(int maxRetries) {
      this.maxRetries = maxRetries;
      return this;
    }

    TransportRequest build() {
      TransportRequest.Builder b =
          TransportRequest.builder(method, "/v1/" + path).operation(operation).acceptStatus(accept);
      query.forEach(b::query);
      if (namespace != null) {
        b.header("X-Vault-Namespace", namespace);
      }
      if (tokenOverride != null) {
        b.header("X-Vault-Token", tokenOverride);
      } else if (!noToken) {
        Secret t = token.get();
        if (t != null && !t.isCleared()) {
          b.header("X-Vault-Token", t.reveal());
        }
      }
      headers.forEach(b::header);
      if (json != null) {
        b.body(Json.encode(json), contentType);
      }
      if (idempotent != null) {
        b.idempotent(idempotent);
      }
      if (maxRetries != null) {
        b.maxRetries(maxRetries);
      }
      return b.build();
    }

    /** Sends the call; the future fails with a mapped {@link OpenBaoException}. */
    CompletableFuture<TransportResponse> send() {
      TransportRequest request;
      try {
        request = build();
      } catch (OpenBaoException e) {
        return CompletableFuture.failedFuture(e);
      }
      boolean isLogin = login;
      return transport
          .sendAsync(request)
          .handle(
              (r, t) -> {
                if (t != null) {
                  throw new CompletionException(
                      map(HttpTransport.asSdkException(t, operation), isLogin));
                }
                return r;
              });
    }

    /** Sends the call and decodes the JSON envelope ({@code null} for an empty body). */
    CompletableFuture<JsonNode> envelope() {
      return send().thenApply(VaultHttp::body);
    }

    /** Sends the call and returns {@code envelope.data}; fails when it is missing. */
    CompletableFuture<JsonNode> data() {
      String op = operation;
      return envelope()
          .thenApply(
              env -> {
                JsonNode d = env == null ? null : env.get("data");
                if (d == null || d.isNull()) {
                  throw Wire.unexpected(op, "response has no data");
                }
                return d;
              });
    }

    /** Sends the call and ignores the body. */
    CompletableFuture<Void> run() {
      return send().thenApply(r -> null);
    }
  }

  /**
   * Decodes a JSON body; {@code null} for an empty body.
   *
   * @param r response
   * @return the tree or null
   */
  static JsonNode body(TransportResponse r) {
    byte[] b = r.body();
    if (b.length == 0) {
      return null;
    }
    return r.jsonNode();
  }
}
