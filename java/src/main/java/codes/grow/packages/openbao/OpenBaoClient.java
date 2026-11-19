package codes.grow.packages.openbao;

import codes.grow.packages.openbao.core.AuthenticationException;
import codes.grow.packages.openbao.core.CancelledException;
import codes.grow.packages.openbao.core.ConfigException;
import codes.grow.packages.openbao.core.EnvReader;
import codes.grow.packages.openbao.core.HealthCheck;
import codes.grow.packages.openbao.core.HealthStatus;
import codes.grow.packages.openbao.core.Hooks;
import codes.grow.packages.openbao.core.HttpTransport;
import codes.grow.packages.openbao.core.Logger;
import codes.grow.packages.openbao.core.OpenBaoException;
import codes.grow.packages.openbao.core.RetryPolicy;
import codes.grow.packages.openbao.core.Secret;
import codes.grow.packages.openbao.core.TlsOptions;
import codes.grow.packages.openbao.core.UnsupportedException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Client for OpenBao.
 *
 * <p>Implements SPEC section 2.4 plus the OpenBao modules: {@link #auth()}, {@link #kv()}, {@link
 * #transit()}, {@link #database()}, {@link #leases()}, {@link #pki()}, {@link #sys()}, {@link
 * #wrapping()} and the {@code SecretsProvider} {@link #secrets()}. Thread-safe; create one per
 * endpoint and close it when done.
 *
 * <pre>{@code
 * try (OpenBaoClient client = OpenBaoClient.fromEnv()) {   // BAO_ADDR / BAO_TOKEN / GROW_OPENBAO_*
 *   client.kv().write("app/db", Map.of("password", "s3cret"));
 *   KvSecret secret = client.kv().read("app/db");
 * }
 * }</pre>
 *
 * <p>Every I/O method has a blocking form and an {@code ...Async} form returning {@link
 * CompletableFuture}.
 */
public final class OpenBaoClient implements AutoCloseable {
  private final OpenBaoConfig config;
  private final HttpTransport transport;
  private final AtomicReference<Secret> token;
  private final ClientContext ctx;
  private final Auth auth;
  private final Sys sys;
  private final Wrapping wrapping;
  private final LeaseManager leases;
  private final Map<String, KvMount> kvMounts = new ConcurrentHashMap<>();
  private final AtomicBoolean closed = new AtomicBoolean();
  private final List<AutoCloseable> resources = new ArrayList<>();

  private OpenBaoClient(OpenBaoConfig config) {
    this.config = config;
    this.token = new AtomicReference<>(config.token().orElse(null));
    this.transport =
        new HttpTransport(
            config.toTransportConfig(
                () -> {
                  Secret t = token.get();
                  return t == null || t.isCleared() ? List.of() : List.of(t.reveal());
                }));
    VaultHttp http = new VaultHttp(transport, token::get, config.namespace().orElse(null));
    this.ctx = new ClientContext(http, config, token);
    this.auth = new Auth(ctx);
    this.sys = new Sys(ctx);
    this.wrapping = new Wrapping(ctx);
    this.leases = new LeaseManager(ctx);
  }

  /**
   * Creates a client.
   *
   * @param config validated configuration
   * @return a new client
   * @throws ConfigException when TLS or proxy settings are invalid
   */
  public static OpenBaoClient create(OpenBaoConfig config) {
    config.validate();
    return new OpenBaoClient(config);
  }

  /**
   * Creates a client from the SDK and vendor environment variables ({@code GROW_OPENBAO_*}, {@code
   * BAO_*}, {@code VAULT_*}).
   *
   * @return a new client
   */
  public static OpenBaoClient fromEnv() {
    return create(OpenBaoConfig.fromEnv());
  }

  /**
   * Starts a client builder.
   *
   * @return a new builder
   */
  public static Builder builder() {
    return new Builder();
  }

  /**
   * Returns the configuration.
   *
   * @return the configuration
   */
  public OpenBaoConfig config() {
    return config;
  }

  /**
   * Returns the HTTP transport, for modules built on this client.
   *
   * @return the transport
   */
  public HttpTransport transport() {
    return transport;
  }

  /**
   * Returns the current client token (from the config, a login or {@link #setToken}).
   *
   * @return the token, or empty
   */
  public Optional<Secret> token() {
    return Optional.ofNullable(token.get());
  }

  /**
   * Replaces the client token.
   *
   * @param token the new token, or null to send none
   */
  public void setToken(Secret token) {
    this.token.set(token);
  }

  /**
   * Replaces the client token.
   *
   * @param token the new token, or null to send none
   */
  public void setToken(String token) {
    setToken(token == null ? null : Secret.of(token));
  }

  /**
   * Registers a resource (watcher, renewer, provider) closed with the client.
   *
   * @param resource the resource
   */
  public void register(AutoCloseable resource) {
    synchronized (resources) {
      resources.add(resource);
    }
  }

  private void unregister(AutoCloseable resource) {
    synchronized (resources) {
      resources.remove(resource);
    }
  }

  // ---- modules ----

  /**
   * Logins, token self-service and token renewal.
   *
   * @return the auth module
   */
  public Auth auth() {
    return auth;
  }

  /**
   * System backend (health, seal status, policies, mounts, auth methods, AppRole admin).
   *
   * @return the sys module
   */
  public Sys sys() {
    return sys;
  }

  /**
   * Response wrapping.
   *
   * @return the wrapping module
   */
  public Wrapping wrapping() {
    return wrapping;
  }

  /**
   * Lease renew / revoke / lookup and automatic lease renewal.
   *
   * @return the lease manager
   */
  public LeaseManager leases() {
    return leases;
  }

  /**
   * The default KV mount ({@link OpenBaoConfig#kvMount()}) with auto-detected version.
   *
   * @return the mount
   */
  public KvMount kv() {
    return kv(config.kvMount());
  }

  /**
   * A KV mount with auto-detected version; the same instance is returned for the same mount.
   *
   * @param mount mount path
   * @return the mount
   */
  public KvMount kv(String mount) {
    String key = Wire.trimSlashes(mount);
    return kvMounts.computeIfAbsent(
        key,
        k ->
            new KvMount(
                ctx, k, config.kvVersion().isPresent() ? config.kvVersion().getAsInt() : null));
  }

  /**
   * A KV version 1 mount (no detection).
   *
   * @param mount mount path
   * @return the mount
   */
  public KvV1 kvV1(String mount) {
    return new KvV1(ctx, mount);
  }

  /**
   * A KV version 2 mount (no detection).
   *
   * @param mount mount path
   * @return the mount
   */
  public KvV2 kvV2(String mount) {
    return new KvV2(ctx, mount);
  }

  /**
   * The transit engine on mount {@code transit}.
   *
   * @return the transit module
   */
  public Transit transit() {
    return transit("transit");
  }

  /**
   * The transit engine on a mount.
   *
   * @param mount mount path
   * @return the transit module
   */
  public Transit transit(String mount) {
    return new Transit(ctx, mount);
  }

  /**
   * The database engine on mount {@code database}.
   *
   * @return the database module
   */
  public Database database() {
    return database("database");
  }

  /**
   * The database engine on a mount.
   *
   * @param mount mount path
   * @return the database module
   */
  public Database database(String mount) {
    return new Database(ctx, mount);
  }

  /**
   * The PKI engine on mount {@code pki}.
   *
   * @return the PKI module
   */
  public Pki pki() {
    return pki("pki");
  }

  /**
   * The PKI engine on a mount.
   *
   * @param mount mount path
   * @return the PKI module
   */
  public Pki pki(String mount) {
    return new Pki(ctx, mount);
  }

  /**
   * {@code SecretsProvider} over the default KV mount. {@link #close()} stops its watchers.
   *
   * @return the provider
   */
  public OpenBaoSecretsProvider secrets() {
    return secrets(SecretsOptions.builder().build());
  }

  /**
   * {@code SecretsProvider} over a KV mount and base path.
   *
   * @param options mount, base path, value field
   * @return the provider
   */
  public OpenBaoSecretsProvider secrets(SecretsOptions options) {
    OpenBaoSecretsProvider[] holder = new OpenBaoSecretsProvider[1];
    holder[0] =
        new OpenBaoSecretsProvider(
            kv(options.mount == null ? config.kvMount() : options.mount),
            SecretsOptions.builder()
                .path(options.path == null ? config.secretsPath() : options.path)
                .valueField(options.valueField == null ? config.valueField() : options.valueField)
                .build(),
            () -> unregister(holder[0]));
    register(holder[0]);
    return holder[0];
  }

  // ---- raw requests ----

  /**
   * Calls any OpenBao API path ({@code /v1/<path>}) with the client token, namespace, retries and
   * error mapping. Use it for endpoints this SDK has no method for.
   *
   * @param method HTTP method ({@code GET}, {@code POST}, {@code PUT}, {@code DELETE}, {@code LIST}
   *     is sent as {@code GET ?list=true})
   * @param path path below {@code /v1/} (each segment is percent-encoded)
   * @param body JSON body, may be null
   * @return the decoded envelope
   */
  public RawResponse request(String method, String path, Object body) {
    return HttpTransport.await(requestAsync(method, path, body), "request");
  }

  /**
   * Asynchronous {@link #request(String, String, Object)}.
   *
   * @param method HTTP method
   * @param path path below {@code /v1/}
   * @param body JSON body, may be null
   * @return a future with the decoded envelope
   */
  public CompletableFuture<RawResponse> requestAsync(String method, String path, Object body) {
    String m = method.toUpperCase(java.util.Locale.ROOT);
    boolean list = m.equals("LIST");
    String op = m + " " + Wire.trimSlashes(path);
    return Wire.async(
        () -> {
          VaultHttp.Call c = ctx.http.call(list ? "GET" : m, Wire.encodePath(path), op);
          if (list) {
            c.list();
          }
          if (body != null) {
            c.json(body);
          }
          return c.send().thenApply(r -> RawResponse.from(r.status(), VaultHttp.body(r)));
        });
  }

  // ---- shared surface ----

  /**
   * Unauthenticated health ({@code GET /v1/sys/health}, answers 200 in every node state). {@code
   * healthy} is true only for an active, unsealed node; {@code status} is {@code active}, {@code
   * standby}, {@code perfstandby}, {@code sealed} or {@code uninitialized} ({@code unreachable} on
   * errors). Never throws except for cancellation and configuration errors.
   *
   * @return the health status
   * @throws CancelledException when interrupted or closed
   */
  public HealthStatus health() {
    return HttpTransport.await(healthAsync(), "health");
  }

  /**
   * Asynchronous {@link #health()}.
   *
   * @return a future with the health status
   */
  public CompletableFuture<HealthStatus> healthAsync() {
    return sys.probeAsync()
        .handle(
            (h, err) -> {
              if (err == null) {
                Map<String, String> details = new LinkedHashMap<>();
                details.put("version", h.version());
                details.put("initialized", String.valueOf(h.initialized()));
                details.put("sealed", String.valueOf(h.sealed()));
                details.put("standby", String.valueOf(h.standby()));
                if (!h.clusterName().isEmpty()) {
                  details.put("clusterName", h.clusterName());
                }
                return new HealthStatus(h.state().equals("active"), h.state(), details);
              }
              OpenBaoException e = HttpTransport.asSdkException(err, "health");
              if (e instanceof CancelledException || e instanceof ConfigException) {
                throw e;
              }
              return HealthCheck.fromError(e);
            });
  }

  /**
   * Authenticated round trip ({@code GET /v1/auth/token/lookup-self}, allowed for every valid
   * token).
   *
   * @return the latency
   * @throws AuthenticationException on a missing, invalid or revoked token
   */
  public Duration ping() {
    return HttpTransport.await(pingAsync(), "ping");
  }

  /**
   * Asynchronous {@link #ping()}.
   *
   * @return a future with the latency
   */
  public CompletableFuture<Duration> pingAsync() {
    long start = System.nanoTime();
    return ctx.http
        .call("GET", "auth/token/lookup-self", "ping")
        .login()
        .run()
        .thenApply(r -> Duration.ofNanos(System.nanoTime() - start));
  }

  /**
   * Returns the server version from {@code sys/health} (e.g. {@code 2.7.2}).
   *
   * @return the version string
   * @throws UnsupportedException when the server reports none
   */
  public String serverVersion() {
    return HttpTransport.await(serverVersionAsync(), "serverVersion");
  }

  /**
   * Asynchronous {@link #serverVersion()}.
   *
   * @return a future with the version
   */
  public CompletableFuture<String> serverVersionAsync() {
    return sys.versionAsync();
  }

  /**
   * Returns whether {@link #close()} was called.
   *
   * @return true once closed
   */
  public boolean isClosed() {
    return closed.get();
  }

  /**
   * Stops token renewers, managed leases (revoking those with {@code revokeOnStop}) and secret
   * watchers, then releases the transport. Idempotent.
   */
  @Override
  public void close() {
    if (!closed.compareAndSet(false, true)) {
      return;
    }
    auth.stopRenewers();
    try {
      leases
          .stopAllAsync()
          .get(config.requestTimeout().toMillis(), java.util.concurrent.TimeUnit.MILLISECONDS);
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
    } catch (java.util.concurrent.ExecutionException | java.util.concurrent.TimeoutException e) {
      // best effort: close must not throw
    }
    List<AutoCloseable> copy;
    synchronized (resources) {
      copy = new ArrayList<>(resources);
      resources.clear();
    }
    for (AutoCloseable r : copy) {
      try {
        r.close();
      } catch (Exception ignored) {
        // best effort: close must not throw
      }
    }
    transport.close();
  }

  @Override
  public String toString() {
    return "OpenBaoClient{" + config + "}";
  }

  /** Builder that configures and creates a client in one chain. */
  public static final class Builder {
    private final OpenBaoConfig.Builder config = OpenBaoConfig.builder();

    private Builder() {}

    /**
     * Fills unset fields from an environment reader.
     *
     * @param env reader, e.g. {@link EnvReader#system()}
     * @return this builder
     */
    public Builder fromEnv(EnvReader env) {
      config.fromEnv(env);
      return this;
    }

    /**
     * Sets the endpoint base URL.
     *
     * @param url URL
     * @return this builder
     */
    public Builder url(String url) {
      config.url(url);
      return this;
    }

    /**
     * Sets the API token.
     *
     * @param token token
     * @return this builder
     */
    public Builder token(String token) {
      config.token(token);
      return this;
    }

    /**
     * Sets the API token.
     *
     * @param token token
     * @return this builder
     */
    public Builder token(Secret token) {
      config.token(token);
      return this;
    }

    /**
     * Sets the connect timeout.
     *
     * @param d duration
     * @return this builder
     */
    public Builder connectTimeout(Duration d) {
      config.connectTimeout(d);
      return this;
    }

    /**
     * Sets the per-attempt timeout.
     *
     * @param d duration
     * @return this builder
     */
    public Builder requestTimeout(Duration d) {
      config.requestTimeout(d);
      return this;
    }

    /**
     * Sets the total timeout.
     *
     * @param d duration
     * @return this builder
     */
    public Builder totalTimeout(Duration d) {
      config.totalTimeout(d);
      return this;
    }

    /**
     * Sets the retry policy.
     *
     * @param retry policy
     * @return this builder
     */
    public Builder retry(RetryPolicy retry) {
      config.retry(retry);
      return this;
    }

    /**
     * Sets the TLS options.
     *
     * @param tls options
     * @return this builder
     */
    public Builder tls(TlsOptions tls) {
      config.tls(tls);
      return this;
    }

    /**
     * Sets the proxy URL.
     *
     * @param proxy URL
     * @return this builder
     */
    public Builder proxy(String proxy) {
      config.proxy(proxy);
      return this;
    }

    /**
     * Adds a header.
     *
     * @param name name
     * @param value value
     * @return this builder
     */
    public Builder header(String name, String value) {
      config.header(name, value);
      return this;
    }

    /**
     * Sets the user agent suffix.
     *
     * @param suffix suffix
     * @return this builder
     */
    public Builder userAgentSuffix(String suffix) {
      config.userAgentSuffix(suffix);
      return this;
    }

    /**
     * Sets hooks.
     *
     * @param hooks hooks
     * @return this builder
     */
    public Builder hooks(Hooks hooks) {
      config.hooks(hooks);
      return this;
    }

    /**
     * Sets the logger.
     *
     * @param logger logger
     * @return this builder
     */
    public Builder logger(Logger logger) {
      config.logger(logger);
      return this;
    }

    /**
     * Sets the namespace ({@code X-Vault-Namespace}).
     *
     * @param namespace namespace
     * @return this builder
     */
    public Builder namespace(String namespace) {
      config.namespace(namespace);
      return this;
    }

    /**
     * Sets the default KV mount.
     *
     * @param kvMount mount path
     * @return this builder
     */
    public Builder kvMount(String kvMount) {
      config.kvMount(kvMount);
      return this;
    }

    /**
     * Fixes the KV version (skips auto-detection).
     *
     * @param kvVersion 1 or 2
     * @return this builder
     */
    public Builder kvVersion(int kvVersion) {
      config.kvVersion(kvVersion);
      return this;
    }

    /**
     * Builds the configuration and the client.
     *
     * @return a new client
     * @throws ConfigException when the configuration is invalid
     */
    public OpenBaoClient build() {
      return create(config.build());
    }
  }
}
