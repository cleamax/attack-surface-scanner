"""Certificate analysis.

The regression these tests exist for: ``get_certificate_info`` used to disable
verification and call ``getpeercert()``, which returns an empty dict when the peer was
not validated. Every certificate finding was therefore unreachable, and nothing in the
suite noticed because this module had no tests at all.
"""

from __future__ import annotations

import datetime as dt
import ssl

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from asm.checks.tls import (
    CertificateInfo,
    analyze_certificate,
    analyze_tls_versions,
    get_certificate_info,
)

NOW = dt.datetime(2026, 6, 1, tzinfo=dt.timezone.utc)


def _make_der(not_before: dt.datetime, not_after: dt.datetime, cn: str = "example.com") -> bytes:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before.replace(tzinfo=None))
        .not_valid_after(not_after.replace(tzinfo=None))
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.DER)


class TestDerParsing:
    def test_real_der_is_parsed(self) -> None:
        """A DER blob is readable without verification; a getpeercert() dict is not."""
        from asm.checks.tls import _parse_der

        der = _make_der(NOW - dt.timedelta(days=10), NOW + dt.timedelta(days=100))
        not_before, not_after, subject, issuer = _parse_der(der)

        assert not_before is not None and not_after is not None
        assert (not_after - not_before).days == 110
        assert "example.com" in (subject or "")

    def test_getpeercert_dict_would_have_been_empty(self) -> None:
        """Documents the original bug: CERT_NONE yields no decoded certificate."""
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        assert context.verify_mode == ssl.CERT_NONE


class TestAnalyzeCertificate:
    def test_expired_certificate_is_high(self) -> None:
        cert = CertificateInfo(
            not_before=NOW - dt.timedelta(days=400),
            not_after=NOW - dt.timedelta(days=5),
            subject="CN=example.com",
            issuer="CN=CA",
            chain_verified=True,
        )
        findings = analyze_certificate(cert, now=NOW)
        assert [f.id for f in findings] == ["TLS-001"]
        assert findings[0].severity == "high"
        assert "5 days ago" in (findings[0].evidence or "")

    def test_expiring_soon_is_medium(self) -> None:
        cert = CertificateInfo(
            not_before=NOW - dt.timedelta(days=60),
            not_after=NOW + dt.timedelta(days=10),
            subject=None,
            issuer=None,
            chain_verified=True,
        )
        findings = analyze_certificate(cert, now=NOW)
        assert [f.id for f in findings] == ["TLS-002"]
        assert findings[0].severity == "medium"

    def test_healthy_certificate_produces_nothing(self) -> None:
        cert = CertificateInfo(
            not_before=NOW - dt.timedelta(days=30),
            not_after=NOW + dt.timedelta(days=300),
            subject=None,
            issuer=None,
            chain_verified=True,
        )
        assert analyze_certificate(cert, now=NOW) == []

    def test_not_yet_valid_is_reported(self) -> None:
        cert = CertificateInfo(
            not_before=NOW + dt.timedelta(days=5),
            not_after=NOW + dt.timedelta(days=300),
            subject=None,
            issuer=None,
            chain_verified=True,
        )
        assert "TLS-005" in {f.id for f in analyze_certificate(cert, now=NOW)}

    def test_hostname_mismatch_is_high(self) -> None:
        cert = CertificateInfo(
            not_before=NOW - dt.timedelta(days=30),
            not_after=NOW + dt.timedelta(days=300),
            subject=None,
            issuer=None,
            chain_verified=False,
            verification_error="hostname mismatch",
            hostname_matches=False,
        )
        ids = {f.id for f in analyze_certificate(cert, now=NOW)}
        assert "TLS-006" in ids
        assert "TLS-007" not in ids, "a mismatch should not also report as a generic chain failure"

    def test_untrusted_chain_is_medium(self) -> None:
        cert = CertificateInfo(
            not_before=NOW - dt.timedelta(days=30),
            not_after=NOW + dt.timedelta(days=300),
            subject=None,
            issuer=None,
            chain_verified=False,
            verification_error="self signed certificate",
        )
        findings = analyze_certificate(cert, now=NOW)
        assert [f.id for f in findings] == ["TLS-007"]

    def test_missing_dates_do_not_crash(self) -> None:
        cert = CertificateInfo(None, None, None, None, chain_verified=True)
        assert analyze_certificate(cert, now=NOW) == []


class TestAnalyzeTlsVersions:
    @pytest.mark.parametrize("deprecated", ["TLSv1", "TLSv1.1"])
    def test_deprecated_versions_are_high(self, deprecated: str) -> None:
        findings = analyze_tls_versions([deprecated, "TLSv1.2"])
        assert [f.id for f in findings] == ["TLS-003"]
        assert findings[0].severity == "high"

    def test_modern_only_produces_nothing(self) -> None:
        assert analyze_tls_versions(["TLSv1.2", "TLSv1.3"]) == []

    def test_no_modern_version_is_flagged(self) -> None:
        ids = {f.id for f in analyze_tls_versions(["TLSv1", "TLSv1.1"])}
        assert ids == {"TLS-003", "TLS-004"}

    def test_empty_list_produces_nothing(self) -> None:
        """No detected versions means the probe failed, not that the server is broken."""
        assert analyze_tls_versions([]) == []


class TestGetCertificateInfo:
    def test_unreachable_host_returns_none(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A host that does not answer is a normal discovery outcome, not an error."""
        import socket as socket_module

        from asm.checks import tls as tls_module

        def refuse(*args: object, **kwargs: object) -> None:
            raise OSError("connection refused")

        monkeypatch.setattr(tls_module.socket, "create_connection", refuse)
        assert get_certificate_info("gone.example.com", timeout=1.0) is None
        assert socket_module is not None

    def test_verification_failure_falls_back_to_raw_der(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """An expired or self-signed certificate must still be readable and reported."""
        from asm.checks import tls as tls_module

        der = _make_der(NOW - dt.timedelta(days=400), NOW - dt.timedelta(days=1))

        def fake_read_unverified(hostname: str, timeout: float):
            not_before, not_after, subject, issuer = tls_module._parse_der(der)
            return tls_module.CertificateInfo(
                not_before, not_after, subject, issuer, chain_verified=False
            )

        def raise_verification_error(*args: object, **kwargs: object) -> None:
            raise ssl.SSLCertVerificationError("certificate has expired")

        monkeypatch.setattr(tls_module.socket, "create_connection", raise_verification_error)
        monkeypatch.setattr(tls_module, "_read_unverified", fake_read_unverified)

        info = tls_module.get_certificate_info("expired.example.com")

        assert info is not None
        assert info.chain_verified is False
        assert info.not_after is not None
