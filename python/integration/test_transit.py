"""Transit against the real server (every transit function with a round trip)."""

from __future__ import annotations

import base64
import hashlib

import pytest

import grow_openbao as sdk


def test_key_lifecycle(client: sdk.OpenBaoClient, run_id: str) -> None:
    t = client.transit()
    name = f"py-{run_id}"
    key = t.create_key(name, "aes256-gcm96")
    assert key.name == name and key.type == "aes256-gcm96" and key.latest_version == 1
    assert t.create_key(name).latest_version == 1  # idempotent
    assert t.read_key(name).supports_encryption
    assert name in t.list_keys()
    assert len(t.list_keys(limit=1)) == 1
    ct1 = t.encrypt(name, "hello")
    assert t.rotate_key(name).latest_version == 2
    rewrapped = t.rewrap(name, ct1.ciphertext)
    assert rewrapped.ciphertext.startswith("vault:v2:") and rewrapped.key_version == 2
    assert t.decrypt(name, rewrapped.ciphertext) == b"hello"
    cfg = t.update_key_config(name, min_decryption_version=2, deletion_allowed=True)
    assert cfg.min_decryption_version == 2 and cfg.deletion_allowed
    with pytest.raises(sdk.ValidationError):
        t.decrypt(name, ct1.ciphertext)
    t.delete_key(name)
    with pytest.raises(sdk.NotFoundError):
        t.read_key(name)


def test_delete_without_permission_is_validation_error(
    client: sdk.OpenBaoClient, run_id: str
) -> None:
    t = client.transit()
    t.create_key(f"py-nodel-{run_id}")
    with pytest.raises(sdk.ValidationError):
        t.delete_key(f"py-nodel-{run_id}")


def test_encrypt_decrypt_batch_datakey(client: sdk.OpenBaoClient, env: dict[str, str]) -> None:
    t = client.transit()
    aes = env["GROW_OPENBAO_TEST_TRANSIT_AES_KEY"]
    ct = t.encrypt(aes, b"\x00\x01binary")
    assert ct.ciphertext.startswith("vault:v")
    assert t.decrypt(aes, ct.ciphertext) == b"\x00\x01binary"
    enc = t.encrypt_batch(
        aes,
        [sdk.EncryptBatchItem("one", reference="a"), sdk.EncryptBatchItem(b"two", reference="b")],
    )
    assert [r.reference for r in enc] == ["a", "b"]
    dec = t.decrypt_batch(
        aes,
        [
            sdk.DecryptBatchItem(enc[0].ciphertext or "", reference="a"),
            sdk.DecryptBatchItem("vault:v1:bm90LXZhbGlk", reference="bad"),
            sdk.DecryptBatchItem(enc[1].ciphertext or "", reference="b"),
        ],
    )
    assert dec[0].plaintext == b"one" and dec[2].plaintext == b"two"
    assert dec[1].error and dec[1].plaintext is None
    dk = t.generate_data_key(aes, bits=256)
    assert dk.plaintext is not None and len(dk.plaintext) == 32
    assert t.decrypt(aes, dk.ciphertext) == dk.plaintext
    wrapped = t.generate_data_key(aes, plaintext=False)
    assert wrapped.plaintext is None and wrapped.ciphertext.startswith("vault:v")


def test_hmac_sign_verify_hash_random(client: sdk.OpenBaoClient, env: dict[str, str]) -> None:
    t = client.transit()
    aes = env["GROW_OPENBAO_TEST_TRANSIT_AES_KEY"]
    mac = t.hmac(aes, "data", algorithm="sha2-256")
    assert mac.startswith("vault:v")
    assert t.verify(aes, "data", hmac=mac, hash_algorithm="sha2-256")
    assert not t.verify(aes, "other", hmac=mac, hash_algorithm="sha2-256")
    sig = t.sign(env["GROW_OPENBAO_TEST_TRANSIT_SIGN_KEY"], "msg")
    assert sig.signature.startswith("vault:v") and sig.key_version >= 1
    assert t.verify(env["GROW_OPENBAO_TEST_TRANSIT_SIGN_KEY"], "msg", signature=sig.signature)
    assert not t.verify(
        env["GROW_OPENBAO_TEST_TRANSIT_SIGN_KEY"], "tampered", signature=sig.signature
    )
    rsa = env["GROW_OPENBAO_TEST_TRANSIT_RSA_KEY"]
    rsig = t.sign(rsa, "msg", hash_algorithm="sha2-256", signature_algorithm="pkcs1v15")
    assert t.verify(
        rsa,
        "msg",
        signature=rsig.signature,
        hash_algorithm="sha2-256",
        signature_algorithm="pkcs1v15",
    )
    with pytest.raises(sdk.ValidationError):
        t.sign(aes, "msg")
    assert t.hash("abc") == hashlib.sha256(b"abc").hexdigest()
    assert (
        t.hash("abc", algorithm="sha2-512", format="base64")
        == base64.b64encode(hashlib.sha512(b"abc").digest()).decode()
    )
    assert len(base64.b64decode(t.random_bytes(16))) == 16
    assert len(t.random_bytes(8, format="hex")) == 16
