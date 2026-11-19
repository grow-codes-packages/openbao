"""PKI secrets engine: issue, sign, revoke, read and tidy certificates (API.md §7)."""

from __future__ import annotations

import dataclasses
import datetime as _dt
import time
from collections.abc import Mapping, Sequence
from typing import Any, Literal

from ._api import (
    AsyncModule,
    AsyncRunner,
    Call,
    Duration,
    Op,
    Sleep,
    SyncModule,
    SyncRunner,
    async_op,
    compact,
    encode_path,
    integer,
    list_keys,
    opt_duration,
    parse_time,
    require_text,
    send,
    strings,
    sync_op,
    text,
    trim_slashes,
    unexpected,
)
from ._api import data as get_data
from ._core import Secret, TimeoutError, to_seconds

__all__ = [
    "SignedCertificate",
    "IssuedCertificate",
    "RevocationInfo",
    "CertificateInfo",
    "TidyStatus",
    "Pki",
    "AsyncPki",
]

#: Tidy states after which polling stops.
TIDY_DONE = frozenset({"Finished", "Error", "Cancelled"})


@dataclasses.dataclass(frozen=True)
class SignedCertificate:
    """A certificate issued or signed by the PKI engine."""

    #: PEM certificate.
    certificate: str
    #: PEM issuing CA.
    issuing_ca: str
    #: PEM CA chain.
    ca_chain: list[str]
    #: Colon-separated hex serial, e.g. ``1b:51:...``.
    serial_number: str
    expiration: _dt.datetime | None


@dataclasses.dataclass(frozen=True)
class IssuedCertificate(SignedCertificate):
    """An issued certificate with its private key (a :class:`Secret`)."""

    private_key: Secret = dataclasses.field(default_factory=lambda: Secret(""))
    #: ``rsa``, ``ec`` or ``ed25519``.
    private_key_type: str = ""


@dataclasses.dataclass(frozen=True)
class RevocationInfo:
    """Result of :meth:`Pki.revoke_certificate`."""

    revocation_time: _dt.datetime | None
    #: ``revoked``.
    state: str


@dataclasses.dataclass(frozen=True)
class CertificateInfo:
    """Result of :meth:`Pki.read_certificate`."""

    #: PEM certificate.
    certificate: str
    #: Revocation time, ``None`` when not revoked.
    revocation_time: _dt.datetime | None

    @property
    def revoked(self) -> bool:
        """Whether the certificate is revoked."""
        return self.revocation_time is not None


@dataclasses.dataclass(frozen=True)
class TidyStatus:
    """Tidy progress from ``<mount>/tidy-status``."""

    #: ``Inactive``, ``Running``, ``Finished``, ``Error`` or ``Cancelled``.
    state: str
    error: str | None
    cert_store_deleted_count: int
    revoked_cert_deleted_count: int
    time_started: _dt.datetime | None
    time_finished: _dt.datetime | None


def _signed(d: Mapping[str, Any], op: str) -> dict[str, Any]:
    if not isinstance(d.get("certificate"), str):
        raise unexpected(op, "no certificate")
    return {
        "certificate": d["certificate"],
        "issuing_ca": text(d.get("issuing_ca")),
        "ca_chain": strings(d.get("ca_chain")),
        "serial_number": text(d.get("serial_number")),
        "expiration": parse_time(d.get("expiration")),
    }


def _join(values: Sequence[str] | None) -> str | None:
    return ",".join(values) if values else None


def _revocation_time(d: Mapping[str, Any]) -> _dt.datetime | None:
    return parse_time(d.get("revocation_time_rfc3339")) or parse_time(d.get("revocation_time"))


def _issue_certificate(
    m: Any,
    /,
    role: str,
    common_name: str,
    *,
    alt_names: Sequence[str] | None = None,
    ip_sans: Sequence[str] | None = None,
    uri_sans: Sequence[str] | None = None,
    ttl_s: Duration | None = None,
    format: Literal["pem", "der", "pem_bundle"] | None = None,  # noqa: A002 - wire name
    private_key_format: Literal["der", "pkcs8"] | None = None,
    exclude_cn_from_sans: bool | None = None,
) -> Op[IssuedCertificate]:
    """Issue a certificate and private key for a role (``POST <mount>/issue/<role>``).

    A common name the role does not allow raises :class:`ValidationError`.
    """
    op = f"pki.issueCertificate {role}"
    d = yield from get_data(
        Call(
            "POST",
            encode_path(m.mount, "issue", require_text(role, "role", op)),
            op,
            json=compact(
                {
                    "common_name": require_text(common_name, "common_name", op),
                    "alt_names": _join(alt_names),
                    "ip_sans": _join(ip_sans),
                    "uri_sans": _join(uri_sans),
                    "ttl": opt_duration(ttl_s),
                    "format": format,
                    "private_key_format": private_key_format,
                    "exclude_cn_from_sans": exclude_cn_from_sans,
                }
            ),
        )
    )
    return IssuedCertificate(
        **_signed(d, op),
        private_key=Secret(text(d.get("private_key"))),
        private_key_type=text(d.get("private_key_type")),
    )


def _sign_csr(
    m: Any,
    /,
    role: str,
    csr: str,
    *,
    common_name: str | None = None,
    alt_names: Sequence[str] | None = None,
    ip_sans: Sequence[str] | None = None,
    uri_sans: Sequence[str] | None = None,
    ttl_s: Duration | None = None,
    format: Literal["pem", "der", "pem_bundle"] | None = None,  # noqa: A002 - wire name
    exclude_cn_from_sans: bool | None = None,
) -> Op[SignedCertificate]:
    """Sign a PEM CSR for a role (``POST <mount>/sign/<role>``)."""
    op = f"pki.signCsr {role}"
    d = yield from get_data(
        Call(
            "POST",
            encode_path(m.mount, "sign", require_text(role, "role", op)),
            op,
            json=compact(
                {
                    "csr": require_text(csr, "csr", op),
                    "common_name": common_name,
                    "alt_names": _join(alt_names),
                    "ip_sans": _join(ip_sans),
                    "uri_sans": _join(uri_sans),
                    "ttl": opt_duration(ttl_s),
                    "format": format,
                    "exclude_cn_from_sans": exclude_cn_from_sans,
                }
            ),
        )
    )
    return SignedCertificate(**_signed(d, op))


def _revoke_certificate(m: Any, /, serial: str) -> Op[RevocationInfo]:
    """Revoke a certificate by serial (``aa:bb:...``); unknown serials raise
    :class:`ValidationError`."""
    op = f"pki.revokeCertificate {serial}"
    d = yield from get_data(
        Call(
            "POST",
            encode_path(m.mount, "revoke"),
            op,
            json={"serial_number": require_text(serial, "serial", op)},
            idempotent=True,
        )
    )
    return RevocationInfo(_revocation_time(d), text(d.get("state")) or "revoked")


def _read_ca_chain(m: Any, /) -> Op[str]:
    """The CA chain as PEM text (``GET <mount>/ca_chain``, raw PEM)."""
    resp = yield from send(
        Call(
            "GET",
            encode_path(m.mount, "ca_chain"),
            "pki.readCaChain",
            headers={"Accept": "application/pem-certificate-chain, text/plain, */*"},
        )
    )
    return resp.text


def _read_certificate(m: Any, /, serial: str) -> Op[CertificateInfo]:
    """A certificate by serial; :class:`NotFoundError` when unknown."""
    op = f"pki.readCertificate {serial}"
    d = yield from get_data(
        Call("GET", encode_path(m.mount, "cert", require_text(serial, "serial", op)), op)
    )
    cert = d.get("certificate")
    if not isinstance(cert, str) or not cert:
        raise unexpected(op, "no certificate")
    return CertificateInfo(cert, _revocation_time(d))


def _list_certificates(m: Any, /) -> Op[list[str]]:
    """Serials of all stored certificates; ``[]`` when there is none."""
    return (
        yield from list_keys(
            Call("GET", encode_path(m.mount, "certs") + "/", "pki.listCertificates")
        )
    )


def _tidy_status(m: Any, /) -> Op[TidyStatus]:
    """Current tidy progress (``GET <mount>/tidy-status``)."""
    d = yield from get_data(Call("GET", encode_path(m.mount, "tidy-status"), "pki.tidyStatus"))
    error = d.get("error")
    return TidyStatus(
        state=text(d.get("state")),
        error=error if isinstance(error, str) and error else None,
        cert_store_deleted_count=integer(d.get("cert_store_deleted_count")),
        revoked_cert_deleted_count=integer(d.get("revoked_cert_deleted_count")),
        time_started=parse_time(d.get("time_started")),
        time_finished=parse_time(d.get("time_finished")),
    )


def _tidy(
    m: Any,
    /,
    *,
    tidy_cert_store: bool = True,
    tidy_revoked_certs: bool = True,
    safety_buffer_s: Duration | None = None,
    wait: bool = True,
    timeout_s: Duration = 60.0,
    interval_s: Duration = 0.5,
) -> Op[TidyStatus]:
    """Start a tidy run (``POST <mount>/tidy``, 202).

    Unless ``wait=False``, poll ``tidy-status`` until it is ``Finished``, ``Error`` or
    ``Cancelled`` (:class:`TimeoutError` after ``timeout_s``). Returns the last status.
    """
    yield Call(
        "POST",
        encode_path(m.mount, "tidy"),
        "pki.tidy",
        json=compact(
            {
                "tidy_cert_store": tidy_cert_store,
                "tidy_revoked_certs": tidy_revoked_certs,
                "safety_buffer": opt_duration(safety_buffer_s),
            }
        ),
    )
    status = yield from _tidy_status(m)
    if not wait:
        return status
    deadline = time.monotonic() + to_seconds(timeout_s)
    interval = to_seconds(interval_s)
    while status.state not in TIDY_DONE:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError(f"pki.tidy: not finished within {to_seconds(timeout_s):g}s")
        yield Sleep(min(interval, remaining))
        status = yield from _tidy_status(m)
    return status


class Pki(SyncModule):
    """PKI engine on one mount: ``client.pki(mount="pki")``."""

    __slots__ = ("mount",)

    def __init__(self, runner: SyncRunner, mount: str = "pki") -> None:
        super().__init__(runner)
        self.mount = trim_slashes(mount)

    issue_certificate = sync_op(_issue_certificate)
    sign_csr = sync_op(_sign_csr)
    revoke_certificate = sync_op(_revoke_certificate)
    read_ca_chain = sync_op(_read_ca_chain)
    read_certificate = sync_op(_read_certificate)
    list_certificates = sync_op(_list_certificates)
    tidy = sync_op(_tidy)
    tidy_status = sync_op(_tidy_status)


class AsyncPki(AsyncModule):
    """Async :class:`Pki`."""

    __slots__ = ("mount",)

    def __init__(self, runner: AsyncRunner, mount: str = "pki") -> None:
        super().__init__(runner)
        self.mount = trim_slashes(mount)

    issue_certificate = async_op(_issue_certificate)
    sign_csr = async_op(_sign_csr)
    revoke_certificate = async_op(_revoke_certificate)
    read_ca_chain = async_op(_read_ca_chain)
    read_certificate = async_op(_read_certificate)
    list_certificates = async_op(_list_certificates)
    tidy = async_op(_tidy)
    tidy_status = async_op(_tidy_status)
