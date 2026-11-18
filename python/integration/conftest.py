"""Integration fixtures: environment from /bootstrap/env and the service URL (SPEC section 8)."""

from __future__ import annotations

import os
import secrets as _random
from collections.abc import Iterator
from pathlib import Path

import pytest
from factories import URL_VAR, core_client

import grow_openbao as sdk


def load_env() -> dict[str, str]:
    """Process environment overlaid with the KEY=value lines of the bootstrap file."""
    env = dict(os.environ)
    path = Path(env.get("GROW_BOOTSTRAP_ENV", "/bootstrap/env"))
    if path.is_file():
        for raw in path.read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if line and not line.startswith("#") and "=" in line:
                key, _, value = line.partition("=")
                env.setdefault(key.strip(), value.strip())
    return env


@pytest.fixture(scope="session")
def env() -> dict[str, str]:
    values = load_env()
    if not values.get(URL_VAR):
        pytest.skip(f"{URL_VAR} is not set (run through docker/compose.yml)")
    return values


@pytest.fixture
def client(env: dict[str, str]) -> Iterator[sdk.OpenBaoClient]:
    with core_client(env) as c:
        yield c


@pytest.fixture
def run_id() -> str:
    """Unique lowercase id per test (names never collide between runs or languages)."""
    return f"py{os.environ.get('GROW_TEST_RUN_ID', 'local')}{_random.token_hex(4)}".lower()
