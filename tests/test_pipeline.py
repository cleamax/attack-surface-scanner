"""End-to-end pipeline behaviour, with the network stubbed out.

The pipeline had no coverage at all, which is how a plaintext-only host could score LOW
and how header findings could be raised against WAF error pages.
"""

from __future__ import annotations

import datetime as dt

import pytest

from asm import pipeline
from asm.checks.tls import CertificateInfo
from asm.utils.http import HttpProbeResult

HEALTHY_HEADERS = {
    "strict-transport-security": "max-age=31536000",
    "content-security-policy": "default-src 'self'",
    "x-frame-options": "DENY",
    "x-content-type-options": "nosniff",
    "referrer-policy": "no-referrer",
}


@pytest.fixture
def stub_network(monkeypatch: pytest.MonkeyPatch):
    """Replace DNS, HTTP and TLS with controllable stubs."""
    state: dict = {
        "ips": ["203.0.113.10"],
        "https": None,
        "http": None,
        "tls_versions": ["TLSv1.2", "TLSv1.3"],
        "certificate": CertificateInfo(
            not_before=dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=30),
            not_after=dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=300),
            subject="CN=example.com",
            issuer="CN=CA",
            chain_verified=True,
        ),
    }

    def fake_probe(url: str, timeout: float = 5.0) -> HttpProbeResult:
        key = "https" if url.startswith("https://") else "http"
        configured = state[key]
        if configured is None:
            return HttpProbeResult(url=url, error="connect_error")
        return HttpProbeResult(url=url, **configured)

    monkeypatch.setattr(pipeline, "resolve_ips", lambda host, timeout=2.0: state["ips"])
    monkeypatch.setattr(pipeline, "probe_url", fake_probe)
    monkeypatch.setattr(
        pipeline, "detect_supported_tls_versions", lambda host, timeout=3.0: state["tls_versions"]
    )
    monkeypatch.setattr(pipeline, "get_certificate_info", lambda host, timeout=3.0: state["certificate"])
    return state


def https_response(status: int = 200, headers: dict | None = None, final: str = "https://a.example.com") -> dict:
    return {
        "final_url": final,
        "status_code": status,
        "headers": headers if headers is not None else dict(HEALTHY_HEADERS),
        "redirect_chain": [],
        "response_ms": 42,
    }


class TestScanAsset:
    def test_healthy_https_host_is_low(self, stub_network: dict) -> None:
        stub_network["https"] = https_response()
        stub_network["http"] = None

        asset, warning = pipeline.scan_asset("a.example.com")

        assert asset.risk == "low"
        assert asset.findings == []
        assert asset.uses_https is True
        assert warning is None

    def test_plaintext_only_host_is_high(self, stub_network: dict) -> None:
        """The regression: uses_https was tracked but never produced a finding."""
        stub_network["https"] = None
        stub_network["http"] = https_response(final="http://a.example.com")

        asset, _ = pipeline.scan_asset("a.example.com")

        assert asset.uses_https is False
        assert asset.risk == "high"
        assert "NET-001" in {f.id for f in asset.findings}

    def test_http_not_redirecting_is_medium(self, stub_network: dict) -> None:
        stub_network["https"] = https_response()
        stub_network["http"] = https_response(final="http://a.example.com")

        asset, _ = pipeline.scan_asset("a.example.com")

        assert asset.redirects_to_https is False
        assert "NET-002" in {f.id for f in asset.findings}

    def test_http_redirecting_to_https_is_clean(self, stub_network: dict) -> None:
        stub_network["https"] = https_response()
        stub_network["http"] = https_response(final="https://a.example.com")

        asset, _ = pipeline.scan_asset("a.example.com")

        assert asset.redirects_to_https is True
        assert asset.findings == []

    def test_waf_block_page_produces_no_header_findings(self, stub_network: dict) -> None:
        """403 with no headers must not be reported as a missing-CSP finding."""
        stub_network["https"] = https_response(status=403, headers={})
        stub_network["http"] = None

        asset, _ = pipeline.scan_asset("a.example.com")

        assert not any(f.id.startswith("HDR-") for f in asset.findings)

    def test_deprecated_tls_is_reported(self, stub_network: dict) -> None:
        stub_network["https"] = https_response()
        stub_network["http"] = None
        stub_network["tls_versions"] = ["TLSv1", "TLSv1.2"]

        asset, _ = pipeline.scan_asset("a.example.com")

        assert asset.risk == "high"
        assert "TLS-003" in {f.id for f in asset.findings}
        assert asset.tls_versions == ["TLSv1", "TLSv1.2"]

    def test_expired_certificate_is_reported(self, stub_network: dict) -> None:
        stub_network["https"] = https_response()
        stub_network["http"] = None
        stub_network["certificate"] = CertificateInfo(
            not_before=dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=400),
            not_after=dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=1),
            subject=None,
            issuer=None,
            chain_verified=True,
        )

        asset, _ = pipeline.scan_asset("a.example.com")

        assert "TLS-001" in {f.id for f in asset.findings}

    def test_unresolvable_host_is_recorded_but_not_probed_for_tls(self, stub_network: dict) -> None:
        stub_network["ips"] = []
        stub_network["https"] = None
        stub_network["http"] = None

        asset, _ = pipeline.scan_asset("gone.example.com")

        assert asset.reachable is False
        assert asset.tls_versions == []
        assert asset.findings == []

    def test_proxy_failure_surfaces_a_warning(self, stub_network: dict, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            pipeline,
            "probe_url",
            lambda url, timeout=5.0: HttpProbeResult(url=url, error="proxy_auth_required"),
        )

        _, warning = pipeline.scan_asset("a.example.com")

        assert warning is not None and "407" in warning

    def test_both_schemes_are_recorded_as_endpoints(self, stub_network: dict) -> None:
        stub_network["https"] = https_response()
        stub_network["http"] = https_response(final="https://a.example.com")

        asset, _ = pipeline.scan_asset("a.example.com")

        assert {e.scheme for e in asset.endpoints} == {"http", "https"}


class TestRunScan:
    def test_scan_aggregates_and_reports_scope_rejections(
        self, stub_network: dict, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from asm.discovery.crtsh import DiscoveryResult

        stub_network["https"] = https_response()
        stub_network["http"] = None

        monkeypatch.setattr(
            pipeline,
            "discover_hostnames",
            lambda domain: DiscoveryResult(
                {"example.com", "www.example.com"},
                source="crt.sh",
                out_of_scope_rejected=3,
                rejected_examples=["evilexample.com"],
            ),
        )

        result = pipeline.run_scan("example.com")

        assert result.asset_count == 2
        assert result.resolved_count == 2
        assert result.discovery_source == "crt.sh"
        assert result.out_of_scope_rejected == 3
        assert any("outside the target scope" in w for w in result.warnings)
        assert result.duration_seconds is not None
        assert sum(result.risk_summary.values()) == 2

    def test_apex_domain_is_scanned(self, stub_network: dict, monkeypatch: pytest.MonkeyPatch) -> None:
        """Scanning example.com must actually check example.com."""
        stub_network["https"] = https_response()
        stub_network["http"] = None

        monkeypatch.setattr(
            pipeline.__name__ + ".discover_hostnames",
            __import__("asm.discovery.crtsh", fromlist=["discover_hostnames"]).discover_hostnames,
            raising=True,
        )
        monkeypatch.setattr(
            "asm.discovery.crtsh.requests.get",
            lambda *a, **k: (_ for _ in ()).throw(
                __import__("requests").exceptions.ConnectionError("offline")
            ),
        )

        result = pipeline.run_scan("example.com")

        assert "example.com" in {a.hostname for a in result.assets}
