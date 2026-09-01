"""Transport security checks: TLS version support and certificate validity.

A note on why the certificate code looks the way it does. The obvious implementation is
to disable verification (so an expired or self-signed certificate can still be read) and
call ``getpeercert()``. That does not work: CPython returns an empty dict from
``getpeercert()`` unless the peer certificate was validated, so every certificate finding
silently became unreachable. This module therefore attempts a verified handshake first
and falls back to reading the raw DER, which *is* available without verification.
"""

from __future__ import annotations

import socket
import ssl
from dataclasses import dataclass
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.backends import default_backend

from ..models import Finding

TLS_VERSIONS = {
    "TLSv1": ssl.TLSVersion.TLSv1,
    "TLSv1.1": ssl.TLSVersion.TLSv1_1,
    "TLSv1.2": ssl.TLSVersion.TLSv1_2,
    "TLSv1.3": ssl.TLSVersion.TLSv1_3,
}

#: Days before expiry at which a certificate is reported as expiring soon.
EXPIRY_WARNING_DAYS = 30


@dataclass
class CertificateInfo:
    """What the handshake revealed about the server certificate."""

    not_before: datetime | None
    not_after: datetime | None
    subject: str | None
    issuer: str | None
    chain_verified: bool
    verification_error: str | None = None
    hostname_matches: bool = True


def _supports_tls_version(hostname: str, version: ssl.TLSVersion, timeout: float = 3.0) -> bool:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    try:
        context.minimum_version = version
        context.maximum_version = version
    except ValueError:
        # The local OpenSSL build refuses to enable this version at all.
        return False
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    try:
        with (
            socket.create_connection((hostname, 443), timeout=timeout) as sock,
            context.wrap_socket(sock, server_hostname=hostname),
        ):
            return True
    except (OSError, ssl.SSLError):
        return False


def detect_supported_tls_versions(hostname: str, timeout: float = 3.0) -> list[str]:
    return [
        name
        for name, version in TLS_VERSIONS.items()
        if _supports_tls_version(hostname, version, timeout=timeout)
    ]


def _parse_der(der: bytes) -> tuple[datetime | None, datetime | None, str | None, str | None]:
    cert = x509.load_der_x509_certificate(der, default_backend())
    try:
        not_before = cert.not_valid_before_utc
        not_after = cert.not_valid_after_utc
    except AttributeError:  # cryptography < 42
        not_before = cert.not_valid_before.replace(tzinfo=timezone.utc)
        not_after = cert.not_valid_after.replace(tzinfo=timezone.utc)
    return not_before, not_after, cert.subject.rfc4514_string(), cert.issuer.rfc4514_string()


def get_certificate_info(hostname: str, timeout: float = 3.0) -> CertificateInfo | None:
    """Read the server certificate, whether or not its chain validates.

    First a verified handshake, which also tells us the chain and hostname are good.
    If that fails, an unverified handshake reads the raw DER so an expired or
    self-signed certificate is still reported rather than silently skipped.
    """
    verified_context = ssl.create_default_context()
    try:
        with (
            socket.create_connection((hostname, 443), timeout=timeout) as sock,
            verified_context.wrap_socket(sock, server_hostname=hostname) as tls,
        ):
            der = tls.getpeercert(binary_form=True)
        if der:
            not_before, not_after, subject, issuer = _parse_der(der)
            return CertificateInfo(not_before, not_after, subject, issuer, chain_verified=True)
    except ssl.SSLCertVerificationError as exc:
        # verify_message is not populated on every SSLCertVerificationError instance.
        verification_error = getattr(exc, "verify_message", None) or str(exc)
        hostname_mismatch = "hostname mismatch" in verification_error.lower()
        info = _read_unverified(hostname, timeout)
        if info is None:
            return None
        info.chain_verified = False
        info.verification_error = verification_error
        info.hostname_matches = not hostname_mismatch
        return info
    except (OSError, ssl.SSLError, ValueError):
        return _read_unverified(hostname, timeout)

    return None


def _read_unverified(hostname: str, timeout: float) -> CertificateInfo | None:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    try:
        with (
            socket.create_connection((hostname, 443), timeout=timeout) as sock,
            context.wrap_socket(sock, server_hostname=hostname) as tls,
        ):
            der = tls.getpeercert(binary_form=True)
    except (OSError, ssl.SSLError):
        return None

    if not der:
        return None

    try:
        not_before, not_after, subject, issuer = _parse_der(der)
    except (ValueError, TypeError):
        return None

    return CertificateInfo(not_before, not_after, subject, issuer, chain_verified=False)


def analyze_certificate(cert: CertificateInfo, now: datetime | None = None) -> list[Finding]:
    now = now or datetime.now(timezone.utc)
    findings: list[Finding] = []

    if cert.not_after is not None:
        days_left = (cert.not_after - now).days

        if days_left < 0:
            findings.append(
                Finding(
                    id="TLS-001",
                    title="TLS certificate expired",
                    severity="high",
                    description="The certificate presented by the server is past its expiry date.",
                    remediation="Renew and redeploy the certificate immediately.",
                    evidence=f"Expired {abs(days_left)} days ago on {cert.not_after.date()}",
                )
            )
        elif days_left < EXPIRY_WARNING_DAYS:
            findings.append(
                Finding(
                    id="TLS-002",
                    title="TLS certificate expiring soon",
                    severity="medium",
                    description=(
                        f"The certificate expires within {EXPIRY_WARNING_DAYS} days. "
                        "Automated renewal may not be configured."
                    ),
                    remediation="Confirm automated renewal, or renew manually before expiry.",
                    evidence=f"Expires on {cert.not_after.date()} ({days_left} days left)",
                )
            )

    if cert.not_before is not None and cert.not_before > now:
        findings.append(
            Finding(
                id="TLS-005",
                title="TLS certificate not yet valid",
                severity="high",
                description="The certificate's validity period starts in the future.",
                remediation="Check the certificate issuance process and server clock.",
                evidence=f"Valid from {cert.not_before.date()}",
            )
        )

    if not cert.hostname_matches:
        findings.append(
            Finding(
                id="TLS-006",
                title="TLS certificate hostname mismatch",
                severity="high",
                description=(
                    "The certificate does not cover the hostname it was served for, so "
                    "clients cannot verify they reached the intended host."
                ),
                remediation="Issue a certificate covering this hostname, or correct the routing.",
                evidence=cert.verification_error or "Hostname not present in certificate",
            )
        )
    elif not cert.chain_verified:
        findings.append(
            Finding(
                id="TLS-007",
                title="TLS certificate chain does not validate",
                severity="medium",
                description=(
                    "The certificate chain could not be verified against the system trust "
                    "store. Browsers will warn or refuse the connection."
                ),
                remediation="Serve the full chain, or replace a self-signed certificate.",
                evidence=cert.verification_error or "Chain verification failed",
            )
        )

    return findings


def analyze_tls_versions(supported_versions: list[str]) -> list[Finding]:
    findings: list[Finding] = []
    listed = ", ".join(supported_versions) if supported_versions else "none detected"

    deprecated = [v for v in ("TLSv1", "TLSv1.1") if v in supported_versions]
    if deprecated:
        findings.append(
            Finding(
                id="TLS-003",
                title="Deprecated TLS versions supported",
                severity="high",
                description=(
                    "The server accepts TLS 1.0 or 1.1. Both are deprecated by RFC 8996 and "
                    "are rejected by current browsers."
                ),
                remediation="Disable TLS below 1.2 at the load balancer or web server.",
                evidence=f"Accepted: {', '.join(deprecated)} (all supported: {listed})",
            )
        )

    if supported_versions and not {"TLSv1.2", "TLSv1.3"} & set(supported_versions):
        findings.append(
            Finding(
                id="TLS-004",
                title="No modern TLS version supported",
                severity="high",
                description="The server supports neither TLS 1.2 nor TLS 1.3.",
                remediation="Enable TLS 1.2 and TLS 1.3.",
                evidence=f"Supported versions: {listed}",
            )
        )

    return findings
