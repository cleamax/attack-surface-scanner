from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone
from typing import List, Dict, Optional

from ..models import Finding


TLS_VERSIONS = {
    "TLSv1": ssl.TLSVersion.TLSv1,
    "TLSv1.1": ssl.TLSVersion.TLSv1_1,
    "TLSv1.2": ssl.TLSVersion.TLSv1_2,
    "TLSv1.3": ssl.TLSVersion.TLSv1_3,
}


def _supports_tls_version(hostname: str, version: ssl.TLSVersion, timeout: float = 3.0) -> bool:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = version
    context.maximum_version = version
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    try:
        with socket.create_connection((hostname, 443), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname):
                return True
    except Exception:
        return False


def detect_supported_tls_versions(hostname: str) -> List[str]:
    supported: List[str] = []
    for name, version in TLS_VERSIONS.items():
        if _supports_tls_version(hostname, version):
            supported.append(name)
    return supported


def get_certificate_info(hostname: str, timeout: float = 3.0) -> Optional[Dict]:
    """
    Fetch server certificate via TLS handshake.
    """
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    try:
        with socket.create_connection((hostname, 443), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
    except Exception:
        return None

    return cert


def analyze_certificate(cert: Dict) -> List[Finding]:
    findings: List[Finding] = []

    not_after_str = cert.get("notAfter")
    if not_after_str:
        expiry = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        days_left = (expiry - datetime.now(timezone.utc)).days

        if days_left < 0:
            findings.append(
                Finding(
                    id="TLS-001",
                    title="TLS certificate expired",
                    severity="high",
                    description="The TLS certificate has expired.",
                    remediation="Renew and redeploy the TLS certificate immediately.",
                    evidence=f"Expired on {expiry.isoformat()}",
                )
            )
        elif days_left < 14:
            findings.append(
                Finding(
                    id="TLS-002",
                    title="TLS certificate expiring soon",
                    severity="medium",
                    description="The TLS certificate will expire soon.",
                    remediation="Renew the TLS certificate before expiration.",
                    evidence=f"Expires on {expiry.isoformat()} ({days_left} days left)",
                )
            )

    return findings


def analyze_tls_versions(supported_versions: List[str]) -> List[Finding]:
    findings: List[Finding] = []

    if "TLSv1" in supported_versions or "TLSv1.1" in supported_versions:
        findings.append(
            Finding(
                id="TLS-003",
                title="Deprecated TLS versions supported",
                severity="high",
                description="The server supports deprecated TLS versions (TLS 1.0 / 1.1).",
                remediation="Disable TLS versions below TLS 1.2 in the load balancer or server configuration.",
                evidence=f"Supported versions: {', '.join(supported_versions)}",
            )
        )

    if "TLSv1.2" not in supported_versions and "TLSv1.3" not in supported_versions:
        findings.append(
            Finding(
                id="TLS-004",
                title="No modern TLS version supported",
                severity="high",
                description="The server does not support TLS 1.2 or TLS 1.3.",
                remediation="Enable TLS 1.2 or TLS 1.3.",
                evidence=f"Supported versions: {', '.join(supported_versions)}",
            )
        )

    return findings
