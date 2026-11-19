"""PKI against the real server (issue, sign, revoke, read, list, tidy)."""

from __future__ import annotations

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

import grow_openbao as sdk


def test_issue_read_revoke_list(
    client: sdk.OpenBaoClient, env: dict[str, str], run_id: str
) -> None:
    pki = client.pki(env["GROW_OPENBAO_TEST_PKI_MOUNT"])
    role = env["GROW_OPENBAO_TEST_PKI_ROLE"]
    cn = f"{run_id}.example.test"
    cert = pki.issue_certificate(role, cn, alt_names=[f"alt.{cn}"], ttl_s=3600)
    assert cert.certificate.startswith("-----BEGIN CERTIFICATE-----")
    assert cert.private_key.reveal().startswith("-----BEGIN")
    assert cert.private_key.reveal() not in repr(cert)
    assert cert.private_key_type == "ec"
    parsed = x509.load_pem_x509_certificate(cert.certificate.encode())
    assert parsed.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == cn
    assert cert.serial_number in pki.list_certificates()
    read = pki.read_certificate(cert.serial_number)
    assert read.certificate.strip() == cert.certificate.strip() and not read.revoked
    revoked = pki.revoke_certificate(cert.serial_number)
    assert revoked.revocation_time is not None
    assert pki.read_certificate(cert.serial_number).revoked
    chain = pki.read_ca_chain()
    assert "BEGIN CERTIFICATE" in chain
    with pytest.raises(sdk.ValidationError):
        pki.issue_certificate(role, "evil.example.com")
    with pytest.raises(sdk.NotFoundError):
        pki.read_certificate("ff:ff:ff:ff")
    with pytest.raises(sdk.ValidationError):
        pki.revoke_certificate("ff:ff:ff:ff")


def test_sign_csr(client: sdk.OpenBaoClient, env: dict[str, str], run_id: str) -> None:
    key = ec.generate_private_key(ec.SECP256R1())
    cn = f"csr-{run_id}.example.test"
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
        .sign(key, hashes.SHA256())
    )
    pem = csr.public_bytes(serialization.Encoding.PEM).decode()
    signed = client.pki().sign_csr(env["GROW_OPENBAO_TEST_PKI_ROLE"], pem, ttl_s=600)
    parsed = x509.load_pem_x509_certificate(signed.certificate.encode())
    assert parsed.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ) == key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    assert signed.serial_number and signed.expiration is not None
    with pytest.raises(sdk.ValidationError):
        client.pki().sign_csr(env["GROW_OPENBAO_TEST_PKI_ROLE"], "not a csr")


def test_tidy(client: sdk.OpenBaoClient) -> None:
    status = client.pki().tidy(safety_buffer_s=1, timeout_s=60)
    assert status.state == "Finished", status
    assert client.pki().tidy_status().state == "Finished"
    started = client.pki().tidy(wait=False)
    assert started.state in {"Running", "Finished"}
