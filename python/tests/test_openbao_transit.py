"""Transit engine (recorded fixtures)."""

from __future__ import annotations

import base64

import pytest

import grow_openbao as sdk
from obao import NO_CONTENT, Router, aclient, client, err, ok


def b64(value: bytes) -> str:
    return base64.b64encode(value).decode()


def test_keys() -> None:
    r = Router()
    r.on("POST", "transit/keys/k1", "transit.createKey.ok", NO_CONTENT)
    r.on("GET", "transit/keys/k1", "transit.readKey.ok")
    r.on("GET", "transit/keys/", "transit.listKeys.ok")
    r.on("GET", "transit/keys/none/", err(404))
    r.on("POST", "transit/keys/k1/rotate", "transit.rotateKey.ok")
    r.on("POST", "transit/keys/k1/config", "transit.updateKeyConfig.ok")
    r.on("DELETE", "transit/keys/k1", "transit.deleteKey.ok")
    with client(r) as c:
        t = c.transit()
        key = t.create_key(
            "k1",
            "aes256-gcm96",
            exportable=False,
            derived=False,
            auto_rotate_period_s=3600,
            allow_plaintext_backup=False,
            key_size=None,
        )
        assert key.type == "aes256-gcm96" and key.latest_version >= 1
        assert key.supports_encryption and "1" in key.keys
        assert r.last().json == {
            "type": "aes256-gcm96",
            "exportable": False,
            "derived": False,
            "auto_rotate_period": "3600s",
            "allow_plaintext_backup": False,
        }
        # 204 on create (older servers) → falls back to reading the key
        assert t.create_key("k1").name
        assert t.read_key("k1").name
        assert t.list_keys(limit=5)
        assert r.last().query["limit"] == "5"
        assert t.rotate_key("k1").latest_version >= 2
        cfg = t.update_key_config("k1", deletion_allowed=True, min_decryption_version=1)
        assert cfg.min_decryption_version >= 1
        assert r.last().json == {"deletion_allowed": True, "min_decryption_version": 1}
        t.delete_key("k1")
        with pytest.raises(sdk.ValidationError):
            t.read_key("")


def test_asymmetric_key_versions_are_json() -> None:
    body = {"name": "s", "type": "ed25519", "keys": {"1": {"public_key": "abc"}, "2": 17}}
    r = Router().on("GET", "transit/keys/s", ok(body))
    with client(r) as c:
        key = c.transit().read_key("s")
    assert key.keys == {"1": '{"public_key":"abc"}', "2": "17"}
    assert key.auto_rotate_period_s == 0


def test_encrypt_decrypt_rewrap() -> None:
    r = Router()
    r.on("POST", "transit/encrypt/k", "transit.encrypt.ok")
    r.on("POST", "transit/decrypt/k", "transit.decrypt.ok", "transit.decrypt.invalid")
    r.on("POST", "transit/rewrap/k", "transit.rewrap.ok")
    with client(r) as c:
        t = c.transit()
        ct = t.encrypt("k", "hello", context=b"ctx", key_version=1, associated_data="ad")
        assert ct.ciphertext.startswith("vault:v")
        assert r.last().json == {
            "plaintext": b64(b"hello"),
            "context": b64(b"ctx"),
            "key_version": 1,
            "associated_data": b64(b"ad"),
        }
        assert isinstance(t.decrypt("k", ct.ciphertext, context="c"), bytes)
        with pytest.raises(sdk.ValidationError):
            t.decrypt("k", "vault:v1:bad")
        with pytest.raises(sdk.ValidationError):
            t.decrypt("k", "")
        assert t.rewrap("k", ct.ciphertext, key_version=2).ciphertext.startswith("vault:v")
    r = Router().on("POST", "transit/encrypt/k", ok({"nothing": 1}))
    with client(r) as c, pytest.raises(sdk.UnavailableError, match="no ciphertext"):
        c.transit().encrypt("k", "x")


def test_batches() -> None:
    r = Router()
    r.on("POST", "transit/encrypt/k", "transit.encryptBatch.ok")
    r.on("POST", "transit/decrypt/k", "transit.decryptBatch.partial-207", ok({"x": 1}))
    with client(r) as c:
        t = c.transit()
        assert t.encrypt_batch("k", []) == []
        enc = t.encrypt_batch(
            "k", [sdk.EncryptBatchItem("one", reference="a"), sdk.EncryptBatchItem(b"two", b"c")]
        )
        assert all(e.ciphertext for e in enc) and enc[0].key_version
        sent = r.last().json
        assert sent["partial_failure_response_code"] == 207
        assert sent["batch_input"][0] == {"plaintext": b64(b"one"), "reference": "a"}
        assert sent["batch_input"][1]["context"] == b64(b"c")
        dec = t.decrypt_batch(
            "k", [sdk.DecryptBatchItem("vault:v1:a"), sdk.DecryptBatchItem("vault:v1:b", "x")]
        )
        assert dec[0].plaintext == b"one" and dec[0].error is None
        assert dec[1].plaintext is None and dec[1].error == "invalid ciphertext length"
        assert "b'one'" not in repr(dec[0])
        with pytest.raises(sdk.UnavailableError, match="batch_results"):
            t.decrypt_batch("k", [sdk.DecryptBatchItem("vault:v1:a")])


def test_datakey_hmac_sign_verify_hash_random() -> None:
    r = Router()
    r.on("POST", "transit/datakey/plaintext/k", "transit.generateDataKey.plaintext")
    r.on("POST", "transit/datakey/wrapped/k", "transit.generateDataKey.wrapped")
    r.on("POST", "transit/hmac/k/sha2-256", "transit.hmac.ok")
    r.on("POST", "transit/hmac/k", ok({}))
    r.on("POST", "transit/sign/s", "transit.sign.ed25519", ok({}))
    r.on("POST", "transit/sign/rsa/sha2-256", "transit.sign.rsa-pkcs1v15")
    r.on("POST", "transit/verify/s", "transit.verify.valid", "transit.verify.invalid")
    r.on("POST", "transit/verify/k/sha2-256", "transit.verify.hmac-valid")
    r.on("POST", "transit/hash", "transit.hash.default-hex", ok({}))
    r.on("POST", "transit/hash/sha2-256", "transit.hash.base64")
    r.on("POST", "transit/random", "transit.randomBytes.base64", ok({}))
    with client(r) as c:
        t = c.transit()
        dk = t.generate_data_key("k", bits=128, context="c")
        assert dk.plaintext and dk.ciphertext.startswith("vault:v")
        assert r.last().json == {"bits": 128, "context": b64(b"c")}
        assert "plaintext=" not in repr(dk) or str(dk.plaintext) not in repr(dk)
        wrapped = t.generate_data_key("k", plaintext=False)
        assert wrapped.plaintext is None
        mac = t.hmac("k", b"data", algorithm="sha2-256", key_version=1)
        assert mac.startswith("vault:v")
        with pytest.raises(sdk.UnavailableError, match="no hmac"):
            t.hmac("k", "data")
        sig = t.sign("s", "msg", prehashed=False, context="c")
        assert sig.signature.startswith("vault:v")
        with pytest.raises(sdk.UnavailableError, match="no signature"):
            t.sign("s", "msg")
        rsig = t.sign("rsa", "msg", hash_algorithm="sha2-256", signature_algorithm="pkcs1v15")
        assert r.last().json["signature_algorithm"] == "pkcs1v15"
        assert rsig.key_version >= 1
        assert t.verify("s", "msg", signature=sig.signature) is True
        assert t.verify("s", "msg", signature=sig.signature) is False
        assert t.verify("k", "data", hmac=mac, hash_algorithm="sha2-256") is True
        for kwargs in ({}, {"signature": "a", "hmac": "b"}):
            with pytest.raises(sdk.ValidationError, match="exactly one"):
                t.verify("s", "msg", **kwargs)  # type: ignore[arg-type]
        assert len(t.hash("abc")) == 64
        with pytest.raises(sdk.UnavailableError, match="no sum"):
            t.hash("abc")
        assert t.hash("abc", algorithm="sha2-256", format="base64")
        assert t.random_bytes(16)
        assert r.last().json == {"bytes": 16, "format": "base64"}
        with pytest.raises(sdk.UnavailableError, match="random_bytes"):
            t.random_bytes(16, format="hex")
        for bad in (0, -1, True, 1.5):
            with pytest.raises(sdk.ValidationError):
                t.random_bytes(bad)  # type: ignore[arg-type]


def test_transit_errors_map() -> None:
    r = Router()
    r.on("POST", "transit/sign/aes", "transit.sign.unsupported-key-type")
    r.on("DELETE", "transit/keys/k", "transit.deleteKey.not-allowed")
    r.on("GET", "transit/keys/gone", "transit.readKey.not-found")
    r.on("POST", "transit/encrypt/k", "transit.encrypt.not-base64")
    with client(r) as c:
        t = c.transit("/transit/")
        with pytest.raises(sdk.ValidationError):
            t.sign("aes", "m")
        with pytest.raises(sdk.ValidationError):
            t.delete_key("k")
        with pytest.raises(sdk.NotFoundError):
            t.read_key("gone")
        with pytest.raises(sdk.ValidationError):
            t.encrypt("k", "x")
        assert t.list_keys() == []


async def test_async_transit() -> None:
    r = Router()
    r.on("POST", "transit/encrypt/k", "transit.encrypt.ok")
    r.on("POST", "transit/decrypt/k", "transit.decrypt.ok")
    async with aclient(r) as c:
        ct = await c.transit().encrypt("k", "one")
        assert await c.transit().decrypt("k", ct.ciphertext)
