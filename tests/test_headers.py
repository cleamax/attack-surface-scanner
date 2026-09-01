"""Header analysis, including the conditions under which it must stay silent."""

from __future__ import annotations

import pytest

from asm.checks.headers import check_security_headers, check_transport

ALL_HEADERS = {
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "Content-Security-Policy": "default-src 'self'",
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
}


class TestSecurityHeaders:
    def test_all_headers_present_produces_nothing(self) -> None:
        assert check_security_headers(ALL_HEADERS, status_code=200) == []

    def test_header_names_are_case_insensitive(self) -> None:
        lowered = {k.lower(): v for k, v in ALL_HEADERS.items()}
        assert check_security_headers(lowered, status_code=200) == []

    def test_missing_headers_are_reported(self) -> None:
        ids = {f.id for f in check_security_headers({}, status_code=200)}
        assert ids == {"HDR-001", "HDR-002", "HDR-003", "HDR-004", "HDR-005"}

    @pytest.mark.parametrize("status", [400, 401, 403, 404, 429, 500, 502, 503])
    def test_error_responses_produce_no_findings(self, status: int) -> None:
        """A WAF block page or 404 is not evidence about the application's configuration.

        Without this gate the scanner reports missing CSP on every blocked request,
        which is noise the operator cannot act on.
        """
        assert check_security_headers({}, status_code=status) == []

    @pytest.mark.parametrize("status", [200, 201, 204, 301, 302, 304])
    def test_success_and_redirect_responses_are_analysed(self, status: int) -> None:
        assert check_security_headers({}, status_code=status)

    def test_hsts_is_not_expected_over_plain_http(self) -> None:
        """Browsers ignore HSTS on HTTP, so its absence there is not the finding."""
        ids = {f.id for f in check_security_headers({}, status_code=200, scheme="http")}
        assert "HDR-001" not in ids
        assert "HDR-002" in ids

    def test_hsts_is_expected_over_https(self) -> None:
        ids = {f.id for f in check_security_headers({}, status_code=200, scheme="https")}
        assert "HDR-001" in ids

    def test_findings_record_the_response_they_came_from(self) -> None:
        findings = check_security_headers({}, status_code=200, scheme="https")
        assert all("200" in (f.evidence or "") for f in findings)

    def test_unknown_status_is_analysed(self) -> None:
        assert check_security_headers({}, status_code=None)


class TestTransport:
    def test_http_only_host_is_high(self) -> None:
        """Previously tracked as uses_https but never scored, so plaintext hosts read LOW."""
        findings = check_transport(uses_https=False, http_reachable=True, redirects_to_https=False)
        assert [f.id for f in findings] == ["NET-001"]
        assert findings[0].severity == "high"

    def test_http_without_redirect_is_medium(self) -> None:
        findings = check_transport(uses_https=True, http_reachable=True, redirects_to_https=False)
        assert [f.id for f in findings] == ["NET-002"]
        assert findings[0].severity == "medium"

    def test_http_redirecting_to_https_is_clean(self) -> None:
        assert check_transport(uses_https=True, http_reachable=True, redirects_to_https=True) == []

    def test_https_only_host_is_clean(self) -> None:
        assert check_transport(uses_https=True, http_reachable=False, redirects_to_https=False) == []

    def test_unreachable_host_produces_nothing(self) -> None:
        assert check_transport(uses_https=False, http_reachable=False, redirects_to_https=False) == []
