package codes.grow.packages.openbao;

import codes.grow.packages.openbao.core.Secret;
import java.util.concurrent.atomic.AtomicReference;

/** What a service module needs from the client: HTTP layer, config and the current token. */
final class ClientContext {
  final VaultHttp http;
  final OpenBaoConfig config;
  final AtomicReference<Secret> token;

  ClientContext(VaultHttp http, OpenBaoConfig config, AtomicReference<Secret> token) {
    this.http = http;
    this.config = config;
    this.token = token;
  }
}
