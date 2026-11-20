// Service-owned: generated once by sdk-kit, then maintained in this repository.
package codes.grow.packages.openbao;

import codes.grow.packages.openbao.secrets.ConfigLoader.SecretsBootstrap;
import codes.grow.packages.openbao.secrets.ConfigLoader.SecretsConnection;
import java.util.HashMap;
import java.util.Map;

/**
 * Connector of {@code ConfigLoader.load()} for OpenBao: AppRole login + KV provider at the mount.
 */
public final class SecretsConnect {
  private static final String PREFIX = "GROW_OPENBAO_";

  private SecretsConnect() {}

  /**
   * Builds a client from the bootstrap (address, KV mount; KV v2 for AppRole tokens, which may not
   * read the mount preflight endpoint) and the package's own variables, logs in with AppRole when
   * {@code GROW_SECRETS_AUTH=approle}, and returns the provider rooted at the mount ({@code
   * ConfigLoader} reads {@code GROW_SECRETS_PATH} below it).
   *
   * @param bootstrap parsed GROW_SECRETS_* bootstrap
   * @param env environment the bootstrap was read from
   * @return the connection
   */
  public static SecretsConnection connect(SecretsBootstrap bootstrap, Map<String, String> env) {
    Map<String, String> merged = new HashMap<>(env);
    if (bootstrap.addr() != null) {
      merged.put(PREFIX + "URL", bootstrap.addr());
    }
    if (bootstrap.kvMount() != null) {
      merged.put(PREFIX + "KV_MOUNT", bootstrap.kvMount());
    }
    boolean approle = "approle".equals(bootstrap.auth()) && bootstrap.roleId() != null;
    if (approle) {
      merged.putIfAbsent(PREFIX + "KV_VERSION", "2");
    }
    merged.remove(PREFIX + "SECRETS_PATH");
    OpenBaoClient client = OpenBaoClient.create(OpenBaoConfig.fromEnv(merged));
    try {
      if (approle) {
        client
            .auth()
            .login(new AppRoleAuth(bootstrap.roleId().reveal(), bootstrap.secretId().reveal()));
      }
    } catch (RuntimeException e) {
      client.close();
      throw e;
    }
    return new SecretsConnection(client.secrets(), bootstrap.path(), client::close);
  }
}
