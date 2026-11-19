package codes.grow.packages.openbao.integration;

import codes.grow.packages.openbao.OpenBaoClient;
import codes.grow.packages.openbao.OpenBaoSecretsProvider;
import codes.grow.packages.openbao.SecretsOptions;
import codes.grow.packages.openbao.core.EnvReader;
import codes.grow.packages.openbao.testing.ConformanceRunner;

/**
 * Conformance targets of this service (owned by the service repository).
 *
 * <p>{@code core} is the client; {@code secrets} is the KV v2 {@code SecretsProvider} on mount
 * {@code secret}. Every capability is supported (write, versions, delete, version).
 */
final class Factories {
  /** Capabilities the deployment under test offers (see the scenario {@code requires}). */
  static final String[] CAPABILITIES = {"version", "write", "versions", "delete"};

  private Factories() {}

  static void register(ConformanceRunner.Builder runner, EnvReader env) {
    runner.target("core", scenario -> OpenBaoClient.builder().fromEnv(env).build());
    runner.target(
        "secrets",
        scenario -> {
          OpenBaoClient client = OpenBaoClient.builder().fromEnv(env).build();
          OpenBaoSecretsProvider provider =
              client.secrets(SecretsOptions.builder().mount("secret").build());
          return provider;
        });
  }
}
