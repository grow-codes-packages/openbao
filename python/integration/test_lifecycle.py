"""testing.lifecycle (init/unseal/seal) against the second, Shamir-sealed server."""

from __future__ import annotations

import asyncio

import pytest

import grow_openbao as sdk
from grow_openbao.testing import lifecycle


def test_init_unseal_seal(env: dict[str, str]) -> None:
    url = env.get("GROW_OPENBAO_TEST_SHAMIR_URL")
    if not url:
        pytest.skip("no Shamir server in this fixture")
    with sdk.OpenBaoClient(sdk.OpenBaoConfig(url=url)) as c:
        assert c.health().status in {"uninitialized", "sealed"}
        if lifecycle.init_status(c):
            pytest.skip("Shamir server already initialised (reused volume)")
        result = lifecycle.init(c, secret_shares=1, secret_threshold=1)
        assert len(result.keys) == 1 and result.root_token.reveal()
        assert result.root_token.reveal() not in repr(result)
        assert lifecycle.init_status(c)
        with pytest.raises(sdk.ValidationError):
            lifecycle.init(c)
        assert c.sys.seal_status().sealed
        with pytest.raises(sdk.ValidationError):
            lifecycle.unseal(c, "not-a-key!")
        status = lifecycle.unseal(c, result.keys[0])
        assert not status.sealed
        assert lifecycle.wait_for_active(c, timeout_s=30).state == "active"
        c.set_token(result.root_token)
        lifecycle.seal(c)
        assert c.sys.seal_status().sealed

    async def run() -> None:
        async with sdk.AsyncOpenBaoClient(
            sdk.OpenBaoConfig(url=url, token=result.root_token.reveal())
        ) as a:
            assert await lifecycle.ainit_status(a)
            reset = await lifecycle.aunseal(a, reset=True)
            assert reset.progress == 0
            assert not (await lifecycle.aunseal(a, result.keys_base64[0])).sealed
            assert (await lifecycle.await_for_active(a, timeout_s=30)).state == "active"
            await lifecycle.aseal(a)
            assert (await a.health()).status == "sealed"
            with pytest.raises(sdk.ValidationError):
                await lifecycle.ainit(a)

    asyncio.run(run())
