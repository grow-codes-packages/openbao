"""The async client against the real server: every module once."""

from __future__ import annotations

import asyncio

import grow_openbao as sdk


def test_async_modules(env: dict[str, str], run_id: str) -> None:
    async def run() -> None:
        async with sdk.AsyncOpenBaoClient.from_env(env) as c:
            assert (await c.health()).healthy
            assert await c.ping() >= 0
            assert await c.server_version() == env["GROW_OPENBAO_TEST_SERVER_VERSION"]
            kv = c.kv()
            assert await kv.version() == 2
            await kv.write(f"py/{run_id}/async", {"a": "1"})
            assert (await kv.read(f"py/{run_id}/async")).data == {"a": "1"}
            await c.kv_v2().patch(f"py/{run_id}/async", {"b": "2"})
            assert await c.kv_v2().list(f"py/{run_id}") == ["async"]
            assert (await c.kv_v2().read_metadata(f"py/{run_id}/async")).current_version == 2
            await c.kv_v2().delete_metadata(f"py/{run_id}/async")
            await c.kv_v1("kv1").write(f"py/{run_id}/v1", {"x": "y"})
            assert (await c.kv_v1("kv1").read(f"py/{run_id}/v1")).data == {"x": "y"}
            await c.kv_v1("kv1").delete(f"py/{run_id}/v1")
            t = c.transit()
            ct = await t.encrypt(env["GROW_OPENBAO_TEST_TRANSIT_AES_KEY"], "async")
            assert (
                await t.decrypt(env["GROW_OPENBAO_TEST_TRANSIT_AES_KEY"], ct.ciphertext) == b"async"
            )
            lease = await c.database().get_credentials(env["GROW_OPENBAO_TEST_DB_ROLE"])
            assert (await c.leases.lookup(lease.lease_id)).renewable
            handle = c.leases.manage(lease, revoke_on_stop=True)
            assert handle.running
            await handle.stop()
            cert = await c.pki().issue_certificate(
                env["GROW_OPENBAO_TEST_PKI_ROLE"], f"a{run_id}.example.test"
            )
            assert (await c.pki().read_certificate(cert.serial_number)).certificate
            assert "default" in await c.sys.list_policies()
            w = await c.wrapping.wrap({"z": "1"}, 30)
            assert (await c.wrapping.unwrap(w.token)).data == {"z": "1"}
            raw = await c.request("GET", "sys/mounts")
            assert raw.data is not None
            provider = c.secrets(path=f"py/{run_id}/prov")
            assert await provider.set("s", "v") == "1"
            assert await provider.get_string("s") == "v"
            assert [m.name for m in await provider.list()] == ["s"]
            assert len(await provider.get_all()) == 1
            await provider.delete("s", permanent=True)
            assert await provider.get("s") is None

    asyncio.run(run())
