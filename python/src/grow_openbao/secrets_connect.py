"""Connector used by ``load_config()``.

Service-owned: generated once by sdk-kit, then maintained in this repository. A client from the
``GROW_SECRETS_*`` bootstrap (address, KV mount) and the package's own variables, an AppRole login
when ``GROW_SECRETS_AUTH=approle``, and the KV provider rooted at the mount (``load_config`` reads
``GROW_SECRETS_PATH`` below it).
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from ._secrets.load_config import SecretsBootstrap, SecretsConnection
from .auth import AppRoleAuth
from .client import OpenBaoClient


def connect_secrets(bootstrap: SecretsBootstrap, env: Mapping[str, str]) -> SecretsConnection:
    """Build the client, log in with AppRole when asked and return the mount-rooted provider."""
    overrides: dict[str, Any] = {}
    if bootstrap.addr is not None:
        overrides["url"] = bootstrap.addr
    if bootstrap.kv_mount is not None:
        overrides["kv_mount"] = bootstrap.kv_mount
    if bootstrap.auth == "approle" and not env.get("GROW_OPENBAO_KV_VERSION"):
        overrides["kv_version"] = 2  # AppRole tokens may not read the mount preflight endpoint
    client = OpenBaoClient.from_env(env, **overrides)
    try:
        if bootstrap.auth == "approle" and bootstrap.role_id is not None:
            client.auth.login(AppRoleAuth(bootstrap.role_id.reveal(), bootstrap.secret_id))
    except BaseException:
        client.close()
        raise
    return SecretsConnection(
        provider=client.secrets(path=""), path=bootstrap.path, close=client.close
    )
