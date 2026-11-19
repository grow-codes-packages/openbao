"""Factories the integration suite and the conformance runner use (owned by this repository)."""

from __future__ import annotations

from collections.abc import Mapping

import grow_openbao as sdk

URL_VAR = "GROW_OPENBAO_URL"

#: Capabilities of the deployment under test for the core scenarios ("version" = serverVersion).
CORE_CAPABILITIES: set[str] = {"version"}


def core_client(env: Mapping[str, str]) -> sdk.OpenBaoClient:
    """A client configured from the test environment (URL, root token from /bootstrap/env)."""
    return sdk.OpenBaoClient.from_env(env)


def async_core_client(env: Mapping[str, str]) -> sdk.AsyncOpenBaoClient:
    return sdk.AsyncOpenBaoClient.from_env(env)


#: Capabilities for the secrets scenarios: write, delete, versions (KV v2 mount `secret`).
SECRETS_CAPABILITIES: set[str] = {"write", "delete", "versions"}


def secrets_provider(client: sdk.OpenBaoClient) -> sdk.SecretsProvider | None:
    """The KV v2 backed secrets provider on top of ``client``."""
    return client.secrets()
