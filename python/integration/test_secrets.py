"""Secrets conformance scenarios plus the KV mapping details against the real service."""

from __future__ import annotations

import base64
import os
from collections.abc import Iterator
from typing import Any

import pytest
from factories import SECRETS_CAPABILITIES, core_client, secrets_provider

import grow_openbao as sdk
from grow_openbao.testing import ConformanceRunner, assert_scenario, pytest_params


@pytest.fixture
def provider(env: dict[str, str]) -> Iterator[sdk.SecretsProvider]:
    with core_client(env) as client:
        found = secrets_provider(client)
        assert found is not None
        yield found


@pytest.mark.parametrize("scenario", pytest_params(categories=["secrets"]))
def test_secrets_conformance(provider: sdk.SecretsProvider, scenario: dict[str, Any]) -> None:
    run_id = os.environ.get("GROW_TEST_RUN_ID", "local")
    runner = ConformanceRunner(
        {"secrets": lambda ctx: provider},
        capabilities=SECRETS_CAPABILITIES,
        prefix=f"grow-conformance/{run_id}-py-${{run}}/",
    )
    assert_scenario(runner, scenario)


@pytest.mark.parametrize("scenario", pytest_params(categories=["secrets"]))
def test_secrets_conformance_kv_v1(env: dict[str, str], scenario: dict[str, Any]) -> None:
    run_id = os.environ.get("GROW_TEST_RUN_ID", "local")
    with core_client(env) as client:
        runner = ConformanceRunner(
            {"secrets": lambda ctx: client.secrets("kv1")},
            capabilities={"write", "delete"},
            prefix=f"grow-conformance/{run_id}-py1-${{run}}/",
        )
        assert_scenario(runner, scenario)


def test_kv_mapping(client: sdk.OpenBaoClient, run_id: str) -> None:
    p = client.secrets(path=f"py/{run_id}")
    assert p.set("text", "hello", tags={"team": "sdk"}) == "1"
    assert p.set("text", "hello2", cas=1) == "2"
    with pytest.raises(sdk.ConflictError):
        p.set("text", "x", cas=1)
    assert p.get("text", version="1").reveal() == "hello"  # type: ignore[union-attr]
    raw = client.kv_v2().read(f"py/{run_id}/text").data
    assert raw == {"value": "hello2"}
    p.set("bin", b"\xff\x00")
    assert client.kv_v2().read(f"py/{run_id}/bin").data == {
        "value": base64.b64encode(b"\xff\x00").decode(),
        "encoding": "base64",
    }
    assert p.get("bin").reveal_bytes() == b"\xff\x00"  # type: ignore[union-attr]
    p.set("obj", {"a": 1})
    assert p.get_json("obj") == {"a": 1}
    client.kv_v2().write(f"py/{run_id}/multi", {"u": "x", "p": "y"})
    assert p.get_json("multi") == {"u": "x", "p": "y"}
    meta = p.metadata("text")
    assert meta is not None and meta.version == "2" and meta.tags == {"team": "sdk"}
    assert meta.versions == 2
    names = [m.name for m in p.list()]
    assert names == ["bin", "multi", "obj", "text"]
    p.delete("text", versions=["2"])
    assert p.get_string("text") is None
    p.delete("text", permanent=True)
    assert p.metadata("text") is None
    with pytest.raises(sdk.NotFoundError):
        p.delete("text", permanent=True)
    environ: dict[str, str] = {}
    assert p.load_env({"OBJ": "obj"}, environ=environ) == {"OBJ": "obj"}
    assert environ == {"OBJ": '{"a":1}'}


def test_watch_and_cache(client: sdk.OpenBaoClient, run_id: str) -> None:
    import threading

    p = client.secrets(path=f"py/{run_id}")
    p.set("w", "1")
    changed = threading.Event()
    seen: list[str | None] = []

    def on_change(new: sdk.SecretValue | None, old: sdk.SecretValue | None) -> None:
        seen.append(None if new is None else new.reveal())
        changed.set()

    handle = p.watch("w", 0.2, on_change)
    p.set("w", "2")
    assert changed.wait(10)
    handle.stop()
    assert "2" in seen
    cache = sdk.SecretCache(p, ttl_s=60)
    assert cache.get_string("w") == "2"
    assert cache.get_string("w") == "2"
    assert cache.stats().hits == 1
