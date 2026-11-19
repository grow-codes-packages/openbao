package codes.grow.packages.openbao;

import codes.grow.packages.openbao.core.ConfigException;
import codes.grow.packages.openbao.core.EnvReader;
import codes.grow.packages.openbao.core.Hooks;
import codes.grow.packages.openbao.core.Logger;
import codes.grow.packages.openbao.core.Redaction;
import codes.grow.packages.openbao.core.RetryPolicy;
import codes.grow.packages.openbao.core.Secret;
import codes.grow.packages.openbao.core.TlsOptions;
import codes.grow.packages.openbao.core.TransportConfig;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.file.Paths;
import java.time.Duration;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.OptionalInt;
import java.util.function.Supplier;

/**
 * Immutable configuration of a {@link OpenBaoClient} (SPEC section 2.2).
 *
 * <p>Build one with {@link #builder()} or read it from the environment with {@link #fromEnv()}.
 * Precedence: explicit builder value &gt; SDK variable ({@link EnvReader#DEFAULT_PREFIX} + name)
 * &gt; vendor variables &gt; default. {@link #toString()} never prints credentials.
 *
 * <p>Environment variables ({@link #fromEnv()}): {@code GROW_OPENBAO_URL} / {@code BAO_ADDR} /
 * {@code VAULT_ADDR}, {@code GROW_OPENBAO_TOKEN} / {@code BAO_TOKEN} / {@code VAULT_TOKEN}, {@code
 * GROW_OPENBAO_NAMESPACE} / {@code BAO_NAMESPACE} / {@code VAULT_NAMESPACE}, {@code
 * GROW_OPENBAO_CA_CERT} / {@code BAO_CACERT} / {@code VAULT_CACERT}, {@code
 * GROW_OPENBAO_CLIENT_CERT} / {@code BAO_CLIENT_CERT} / {@code VAULT_CLIENT_CERT}, {@code
 * GROW_OPENBAO_CLIENT_KEY} / {@code BAO_CLIENT_KEY} / {@code VAULT_CLIENT_KEY}, {@code
 * GROW_OPENBAO_INSECURE_SKIP_VERIFY} / {@code BAO_SKIP_VERIFY} / {@code VAULT_SKIP_VERIFY}, {@code
 * GROW_OPENBAO_KV_MOUNT}, {@code GROW_OPENBAO_KV_VERSION} ({@code 1}, {@code 2}; {@code 0} =
 * auto-detect), {@code GROW_OPENBAO_SECRETS_PATH}, plus {@code GROW_OPENBAO_PROXY}, the timeouts
 * and {@code GROW_OPENBAO_MAX_RETRIES}.
 */
public final class OpenBaoConfig {
  /** Default endpoint. */
  public static final String DEFAULT_URL = "http://127.0.0.1:8200";

  /** Default KV mount used by {@code client.kv()} and {@code client.secrets()}. */
  public static final String DEFAULT_KV_MOUNT = "secret";

  /** Default KV data field that holds a {@code client.secrets()} value. */
  public static final String DEFAULT_VALUE_FIELD = "value";

  /** Vendor variables read for {@code url} after the SDK variable {@code URL}, in order. */
  static final String[] URL_VENDOR_VARS = {"BAO_ADDR", "VAULT_ADDR"};

  /** Vendor variables read for {@code token} after the SDK variable {@code TOKEN}, in order. */
  static final String[] TOKEN_VENDOR_VARS = {"BAO_TOKEN", "VAULT_TOKEN"};

  /** Vendor variables read for the CA bundle after the SDK variable {@code CA_CERT}. */
  static final String[] CA_CERT_VENDOR_VARS = {"BAO_CACERT", "VAULT_CACERT"};

  /** Vendor variables read for the namespace after the SDK variable {@code NAMESPACE}. */
  static final String[] NAMESPACE_VENDOR_VARS = {"BAO_NAMESPACE", "VAULT_NAMESPACE"};

  /** Vendor variables read for the client certificate after {@code CLIENT_CERT}. */
  static final String[] CLIENT_CERT_VENDOR_VARS = {"BAO_CLIENT_CERT", "VAULT_CLIENT_CERT"};

  /** Vendor variables read for the client key after {@code CLIENT_KEY}. */
  static final String[] CLIENT_KEY_VENDOR_VARS = {"BAO_CLIENT_KEY", "VAULT_CLIENT_KEY"};

  /** Vendor variables read for TLS verification after {@code INSECURE_SKIP_VERIFY}. */
  static final String[] SKIP_VERIFY_VENDOR_VARS = {"BAO_SKIP_VERIFY", "VAULT_SKIP_VERIFY"};

  private final String url;
  private final Secret token;
  private final Duration connectTimeout;
  private final Duration requestTimeout;
  private final Duration totalTimeout;
  private final RetryPolicy retry;
  private final TlsOptions tls;
  private final String proxy;
  private final Map<String, String> headers;
  private final String userAgentSuffix;
  private final Hooks hooks;
  private final Logger logger;
  private final String namespace;
  private final String kvMount;
  private final Integer kvVersion;
  private final String secretsPath;
  private final String valueField;

  private OpenBaoConfig(Builder b) {
    this.url = b.url != null ? b.url : DEFAULT_URL;
    this.token = b.token;
    this.connectTimeout = b.connectTimeout != null ? b.connectTimeout : Duration.ofSeconds(10);
    this.requestTimeout = b.requestTimeout != null ? b.requestTimeout : Duration.ofSeconds(30);
    this.totalTimeout = b.totalTimeout != null ? b.totalTimeout : Duration.ofSeconds(120);
    this.retry = b.retry != null ? b.retry : RetryPolicy.defaults();
    this.tls = b.tls != null ? b.tls : TlsOptions.defaults();
    this.proxy = b.proxy;
    this.headers = Map.copyOf(b.headers);
    this.userAgentSuffix = b.userAgentSuffix;
    this.hooks = b.hooks != null ? b.hooks : Hooks.NONE;
    this.logger = b.logger != null ? b.logger : Logger.NOOP;
    this.namespace = b.namespace == null || b.namespace.isEmpty() ? null : b.namespace;
    this.kvMount = b.kvMount != null ? b.kvMount : DEFAULT_KV_MOUNT;
    this.kvVersion = b.kvVersion;
    this.secretsPath = b.secretsPath == null ? "" : b.secretsPath.replaceAll("^/+|/+$", "");
    this.valueField = b.valueField != null ? b.valueField : DEFAULT_VALUE_FIELD;
  }

  /**
   * Starts an empty builder (every field at its default).
   *
   * @return a new builder
   */
  public static Builder builder() {
    return new Builder();
  }

  /**
   * Reads the configuration from the process environment.
   *
   * @return the validated configuration
   * @throws ConfigException when a variable holds an invalid value (the message names the variable,
   *     never the value)
   */
  public static OpenBaoConfig fromEnv() {
    return builder().fromEnv(EnvReader.system()).build();
  }

  /**
   * Reads the configuration from an explicit variable map (tests).
   *
   * @param env variable map
   * @return the validated configuration
   */
  public static OpenBaoConfig fromEnv(Map<String, String> env) {
    return builder().fromEnv(EnvReader.of(env)).build();
  }

  /**
   * Checks URL scheme, positive timeouts, retry limits and TLS pairs.
   *
   * @throws ConfigException when a rule is violated
   */
  public void validate() {
    URI u;
    try {
      u = new URI(url);
    } catch (URISyntaxException e) {
      throw new ConfigException("config: url is not a valid URL");
    }
    String scheme = u.getScheme() == null ? "" : u.getScheme().toLowerCase(Locale.ROOT);
    if (!(scheme.equals("http") || scheme.equals("https")) || u.getHost() == null) {
      throw new ConfigException("config: url must use http or https and include a host");
    }
    requirePositive("connectTimeout", connectTimeout);
    requirePositive("requestTimeout", requestTimeout);
    requirePositive("totalTimeout", totalTimeout);
    tls.validate();
    if (retry.maxRetries() < 0) {
      throw new ConfigException("config: maxRetries must be >= 0");
    }
    if (token != null && !token.isCleared() && token.reveal().trim().isEmpty()) {
      throw new ConfigException("config: token must not be blank");
    }
    if (kvMount.replaceAll("^/+|/+$", "").isEmpty()) {
      throw new ConfigException("config: kvMount must not be empty");
    }
    if (kvVersion != null && kvVersion != 1 && kvVersion != 2) {
      throw new ConfigException("config: kvVersion must be 1 or 2");
    }
    if (valueField.trim().isEmpty()) {
      throw new ConfigException("config: valueField must not be empty");
    }
    if (proxy != null) {
      try {
        URI p = new URI(proxy);
        if (p.getHost() == null) {
          throw new ConfigException("config: proxy must be an absolute URL");
        }
      } catch (URISyntaxException e) {
        throw new ConfigException("config: proxy is not a valid URL");
      }
    }
  }

  private static void requirePositive(String name, Duration d) {
    if (d.isZero() || d.isNegative()) {
      throw new ConfigException("config: " + name + " must be positive");
    }
  }

  /**
   * Translates the common fields into transport settings.
   *
   * @return the transport configuration
   */
  public TransportConfig toTransportConfig() {
    return toTransportConfig(
        () -> token == null || token.isCleared() ? List.of() : List.of(token.reveal()));
  }

  /**
   * Translates the common fields into transport settings with a custom source of secret values to
   * redact (the client adds tokens obtained by a login).
   *
   * @param knownSecrets supplier of credential values removed from error messages
   * @return the transport configuration
   */
  public TransportConfig toTransportConfig(Supplier<Collection<String>> knownSecrets) {
    return TransportConfig.builder(url)
        .connectTimeout(connectTimeout)
        .requestTimeout(requestTimeout)
        .totalTimeout(totalTimeout)
        .retry(retry)
        .tls(tls)
        .proxy(proxy)
        .headers(headers)
        .userAgentSuffix(userAgentSuffix)
        .hooks(hooks)
        .logger(logger)
        .knownSecrets(knownSecrets)
        .build();
  }

  /**
   * Returns the endpoint base URL.
   *
   * @return the URL
   */
  public String url() {
    return url;
  }

  /**
   * Returns the API token.
   *
   * @return the token, or empty
   */
  public Optional<Secret> token() {
    return Optional.ofNullable(token);
  }

  /**
   * Returns the connect timeout.
   *
   * @return the timeout
   */
  public Duration connectTimeout() {
    return connectTimeout;
  }

  /**
   * Returns the per-attempt timeout.
   *
   * @return the timeout
   */
  public Duration requestTimeout() {
    return requestTimeout;
  }

  /**
   * Returns the total timeout per call including retries.
   *
   * @return the timeout
   */
  public Duration totalTimeout() {
    return totalTimeout;
  }

  /**
   * Returns the retry policy.
   *
   * @return the policy
   */
  public RetryPolicy retry() {
    return retry;
  }

  /**
   * Returns the TLS options.
   *
   * @return the options
   */
  public TlsOptions tls() {
    return tls;
  }

  /**
   * Returns the explicit proxy URL.
   *
   * @return the proxy, or empty
   */
  public Optional<String> proxy() {
    return Optional.ofNullable(proxy);
  }

  /**
   * Returns the extra request headers.
   *
   * @return immutable map
   */
  public Map<String, String> headers() {
    return headers;
  }

  /**
   * Returns the user agent suffix.
   *
   * @return the suffix, or empty
   */
  public Optional<String> userAgentSuffix() {
    return Optional.ofNullable(userAgentSuffix);
  }

  /**
   * Returns the hooks.
   *
   * @return the hooks
   */
  public Hooks hooks() {
    return hooks;
  }

  /**
   * Returns the logger.
   *
   * @return the logger
   */
  public Logger logger() {
    return logger;
  }

  /**
   * Returns the namespace sent as {@code X-Vault-Namespace}.
   *
   * @return the namespace, or empty
   */
  public Optional<String> namespace() {
    return Optional.ofNullable(namespace);
  }

  /**
   * Returns the default KV mount (default {@code secret}).
   *
   * @return the mount
   */
  public String kvMount() {
    return kvMount;
  }

  /**
   * Returns the fixed KV version that skips auto-detection.
   *
   * @return 1 or 2, or empty for auto-detection per mount
   */
  public OptionalInt kvVersion() {
    return kvVersion == null ? OptionalInt.empty() : OptionalInt.of(kvVersion);
  }

  /**
   * Returns the base path of {@code client.secrets()} inside the KV mount.
   *
   * @return the path without surrounding slashes ({@code ""} = the mount root)
   */
  public String secretsPath() {
    return secretsPath;
  }

  /**
   * Returns the KV data field that holds a {@code client.secrets()} value.
   *
   * @return the field (default {@code value})
   */
  public String valueField() {
    return valueField;
  }

  @Override
  public String toString() {
    return "OpenBaoConfig{url="
        + Redaction.redactUrl(url)
        + ", token="
        + (token == null ? "null" : Redaction.REDACTED)
        + ", connectTimeout="
        + connectTimeout
        + ", requestTimeout="
        + requestTimeout
        + ", totalTimeout="
        + totalTimeout
        + ", retry="
        + retry
        + ", tls="
        + tls
        + ", proxy="
        + (proxy == null ? "null" : Redaction.redactUrl(proxy))
        + ", headers="
        + Redaction.redactHeaders(headers)
        + ", userAgentSuffix="
        + userAgentSuffix
        + ", namespace="
        + namespace
        + ", kvMount="
        + kvMount
        + ", kvVersion="
        + kvVersion
        + ", secretsPath="
        + secretsPath
        + ", valueField="
        + valueField
        + "}";
  }

  /**
   * Builder of the configuration.
   *
   * <p>Unset fields take the environment (when {@link #fromEnv(EnvReader)} is called) or the
   * default.
   */
  public static final class Builder {
    private String url;
    private Secret token;
    private Duration connectTimeout;
    private Duration requestTimeout;
    private Duration totalTimeout;
    private RetryPolicy retry;
    private TlsOptions tls;
    private String proxy;
    private final Map<String, String> headers = new LinkedHashMap<>();
    private String userAgentSuffix;
    private Hooks hooks;
    private Logger logger;
    private String namespace;
    private String kvMount;
    private Integer kvVersion;
    private String secretsPath;
    private String valueField;

    private Builder() {}

    /**
     * Fills every field that was not set explicitly from the environment.
     *
     * @param env environment reader
     * @return this builder
     * @throws ConfigException when a variable holds an invalid value
     */
    public Builder fromEnv(EnvReader env) {
      if (url == null) {
        url = env.string("URL", URL_VENDOR_VARS).orElse(null);
      }
      if (token == null) {
        token = env.string("TOKEN", TOKEN_VENDOR_VARS).map(Secret::of).orElse(null);
      }
      if (connectTimeout == null) {
        connectTimeout = env.duration("CONNECT_TIMEOUT").orElse(null);
      }
      if (requestTimeout == null) {
        requestTimeout = env.duration("REQUEST_TIMEOUT").orElse(null);
      }
      if (totalTimeout == null) {
        totalTimeout = env.duration("TOTAL_TIMEOUT").orElse(null);
      }
      if (retry == null && env.integer("MAX_RETRIES").isPresent()) {
        int n = env.integer("MAX_RETRIES").getAsInt();
        if (n < 0) {
          String variable = EnvReader.DEFAULT_PREFIX + "MAX_RETRIES";
          throw new ConfigException("config: invalid value in " + variable + " (expected >= 0)");
        }
        retry = RetryPolicy.builder().maxRetries(n).build();
      }
      if (tls == null) {
        TlsOptions.Builder t = TlsOptions.builder();
        env.string("CA_CERT", CA_CERT_VENDOR_VARS).ifPresent(p -> t.caCertPath(Paths.get(p)));
        env.string("CLIENT_CERT", CLIENT_CERT_VENDOR_VARS)
            .ifPresent(p -> t.clientCertPath(Paths.get(p)));
        env.string("CLIENT_KEY", CLIENT_KEY_VENDOR_VARS)
            .ifPresent(p -> t.clientKeyPath(Paths.get(p)));
        env.bool("INSECURE_SKIP_VERIFY", SKIP_VERIFY_VENDOR_VARS).ifPresent(t::insecureSkipVerify);
        tls = t.build();
      }
      if (proxy == null) {
        proxy = env.string("PROXY").orElse(null);
      }
      if (namespace == null) {
        namespace = env.string("NAMESPACE", NAMESPACE_VENDOR_VARS).orElse(null);
      }
      if (kvMount == null) {
        kvMount = env.string("KV_MOUNT").orElse(null);
      }
      if (secretsPath == null) {
        secretsPath = env.string("SECRETS_PATH").orElse(null);
      }
      if (kvVersion == null && env.integer("KV_VERSION").isPresent()) {
        int v = env.integer("KV_VERSION").getAsInt();
        if (v != 0 && v != 1 && v != 2) {
          String variable = EnvReader.DEFAULT_PREFIX + "KV_VERSION";
          throw new ConfigException("config: invalid value in " + variable + " (expected 1 or 2)");
        }
        kvVersion = v == 0 ? null : v;
      }
      return this;
    }

    /**
     * Sets the base path inside the KV mount under which {@code client.secrets()} stores secrets
     * (env {@code GROW_OPENBAO_SECRETS_PATH}, default {@code ""} = the mount root).
     *
     * @param secretsPath base path
     * @return this builder
     */
    public Builder secretsPath(String secretsPath) {
      this.secretsPath = secretsPath;
      return this;
    }

    /**
     * Sets the KV data field that holds a {@code client.secrets()} value (default {@code value}).
     *
     * @param valueField field name
     * @return this builder
     */
    public Builder valueField(String valueField) {
      this.valueField = valueField;
      return this;
    }

    /**
     * Sets the namespace sent as {@code X-Vault-Namespace} (env {@code GROW_OPENBAO_NAMESPACE},
     * {@code BAO_NAMESPACE}, {@code VAULT_NAMESPACE}).
     *
     * @param namespace namespace path, e.g. {@code team-a}
     * @return this builder
     */
    public Builder namespace(String namespace) {
      this.namespace = namespace;
      return this;
    }

    /**
     * Sets the default KV mount (default {@code secret}).
     *
     * @param kvMount mount path
     * @return this builder
     */
    public Builder kvMount(String kvMount) {
      this.kvMount = kvMount;
      return this;
    }

    /**
     * Fixes the KV version of every mount and skips auto-detection ({@code
     * sys/internal/ui/mounts}); set it for tokens that cannot read the preflight endpoint.
     *
     * @param kvVersion 1 or 2
     * @return this builder
     */
    public Builder kvVersion(int kvVersion) {
      this.kvVersion = kvVersion;
      return this;
    }

    /**
     * Sets the endpoint base URL.
     *
     * @param url {@code http} or {@code https} URL
     * @return this builder
     */
    public Builder url(String url) {
      this.url = url;
      return this;
    }

    /**
     * Sets the API token.
     *
     * @param token token
     * @return this builder
     */
    public Builder token(Secret token) {
      this.token = token;
      return this;
    }

    /**
     * Sets the API token.
     *
     * @param token token
     * @return this builder
     */
    public Builder token(String token) {
      this.token = token == null ? null : Secret.of(token);
      return this;
    }

    /**
     * Sets the connect timeout (default 10 s).
     *
     * @param d positive duration
     * @return this builder
     */
    public Builder connectTimeout(Duration d) {
      this.connectTimeout = d;
      return this;
    }

    /**
     * Sets the per-attempt timeout (default 30 s).
     *
     * @param d positive duration
     * @return this builder
     */
    public Builder requestTimeout(Duration d) {
      this.requestTimeout = d;
      return this;
    }

    /**
     * Sets the total timeout per call including retries (default 120 s).
     *
     * @param d positive duration
     * @return this builder
     */
    public Builder totalTimeout(Duration d) {
      this.totalTimeout = d;
      return this;
    }

    /**
     * Sets the retry policy (default {@link RetryPolicy#defaults()}).
     *
     * @param retry policy
     * @return this builder
     */
    public Builder retry(RetryPolicy retry) {
      this.retry = retry;
      return this;
    }

    /**
     * Sets the TLS options; environment TLS variables are then ignored.
     *
     * @param tls options
     * @return this builder
     */
    public Builder tls(TlsOptions tls) {
      this.tls = tls;
      return this;
    }

    /**
     * Sets an explicit proxy URL; environment proxies ({@code HTTPS_PROXY}) are never used.
     *
     * @param proxy proxy URL
     * @return this builder
     */
    public Builder proxy(String proxy) {
      this.proxy = proxy;
      return this;
    }

    /**
     * Adds a header sent with every request.
     *
     * @param name header name
     * @param value header value
     * @return this builder
     */
    public Builder header(String name, String value) {
      this.headers.put(name, value);
      return this;
    }

    /**
     * Sets the text appended to the {@code User-Agent}.
     *
     * @param suffix suffix
     * @return this builder
     */
    public Builder userAgentSuffix(String suffix) {
      this.userAgentSuffix = suffix;
      return this;
    }

    /**
     * Sets request hooks.
     *
     * @param hooks hooks
     * @return this builder
     */
    public Builder hooks(Hooks hooks) {
      this.hooks = hooks;
      return this;
    }

    /**
     * Sets the logger (default silent).
     *
     * @param logger logger
     * @return this builder
     */
    public Builder logger(Logger logger) {
      this.logger = logger;
      return this;
    }

    /**
     * Builds and validates the configuration.
     *
     * @return the configuration
     * @throws ConfigException when a rule is violated
     */
    public OpenBaoConfig build() {
      OpenBaoConfig c = new OpenBaoConfig(this);
      c.validate();
      return c;
    }
  }
}
