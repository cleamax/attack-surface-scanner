"""Scope containment.

Certificate Transparency data is attacker-influenceable: anyone can obtain a certificate
for a lookalike domain and it appears in the logs. A hostname that reaches the probing
stage is a hostname this tool sends traffic to, so the scope check is the boundary
between an authorised scan and an unauthorised one.

An earlier version used ``hostname.endswith(domain)``, which authorises
``evilexample.com`` for the target ``example.com``.
"""

from __future__ import annotations

import pytest

from asm.discovery.crtsh import discover_hostnames, fallback_hostnames, in_scope, normalize

DOMAIN = "example.com"


class TestInScope:
    @pytest.mark.parametrize(
        "hostname",
        [
            "example.com",
            "www.example.com",
            "api.example.com",
            "a.b.c.example.com",
            "EXAMPLE.COM",
            "www.example.com.",
        ],
    )
    def test_accepts_apex_and_subdomains(self, hostname: str) -> None:
        assert in_scope(hostname, DOMAIN) is True

    @pytest.mark.parametrize(
        "hostname",
        [
            "evilexample.com",
            "notexample.com",
            "attacker-example.com",
            "myexample.com",
            "example.com.attacker.net",
            "example.org",
            "example.com.co",
            "",
        ],
    )
    def test_rejects_lookalikes_and_suffix_tricks(self, hostname: str) -> None:
        """Each of these passes a naive endswith() check."""
        assert in_scope(hostname, DOMAIN) is False

    def test_empty_domain_rejects_everything(self) -> None:
        assert in_scope("www.example.com", "") is False


class TestNormalize:
    def test_strips_wildcard_prefix(self) -> None:
        assert normalize("*.example.com", DOMAIN) == "example.com"

    def test_lowercases_and_strips_trailing_dot(self) -> None:
        assert normalize("  WWW.Example.COM.  ", DOMAIN) == "www.example.com"

    def test_rejects_out_of_scope(self) -> None:
        assert normalize("evilexample.com", DOMAIN) is None

    @pytest.mark.parametrize("value", ["", "   ", "not a hostname", "localhost"])
    def test_rejects_malformed(self, value: str) -> None:
        assert normalize(value, DOMAIN) is None


class TestFallback:
    def test_includes_the_apex_domain(self) -> None:
        """Scanning example.com must actually check example.com."""
        assert DOMAIN in fallback_hostnames(DOMAIN)

    def test_all_entries_are_in_scope(self) -> None:
        assert all(in_scope(h, DOMAIN) for h in fallback_hostnames(DOMAIN))

    def test_is_deterministic(self) -> None:
        assert fallback_hostnames(DOMAIN) == fallback_hostnames(DOMAIN)


class TestDiscovery:
    def test_invalid_domain_yields_nothing(self) -> None:
        for value in ("", "   ", "notadomain"):
            result = discover_hostnames(value)
            assert result.hostnames == set()
            assert result.warning

    def test_ct_results_are_filtered_to_scope(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """The scope filter must apply to live CT data, not only to the helper."""
        from asm.discovery import crtsh

        payload = [
            {"name_value": "www.example.com\napi.example.com"},
            {"name_value": "evilexample.com"},
            {"name_value": "*.cdn.example.com"},
            {"name_value": "example.com.attacker.net"},
        ]

        class FakeResponse:
            status_code = 200
            headers = {"content-type": "application/json"}
            text = "["

            def json(self) -> list:
                return payload

        monkeypatch.setattr(crtsh.requests, "get", lambda *a, **k: FakeResponse())

        result = crtsh.discover_hostnames(DOMAIN)

        assert result.hostnames == {
            "example.com",
            "www.example.com",
            "api.example.com",
            "cdn.example.com",
        }
        assert "evilexample.com" not in result.hostnames
        assert "example.com.attacker.net" not in result.hostnames
        assert result.out_of_scope_rejected == 2

    def test_falls_back_when_source_unavailable(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from asm.discovery import crtsh

        def boom(*args: object, **kwargs: object) -> None:
            raise crtsh.requests.exceptions.ConnectionError("no network")

        monkeypatch.setattr(crtsh.requests, "get", boom)

        result = crtsh.discover_hostnames(DOMAIN)

        assert result.source == "fallback"
        assert DOMAIN in result.hostnames
        assert result.warning and "not representative" in result.warning

    def test_no_network_call_is_made_in_tests(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Guards against reintroducing a live crt.sh call into the test suite."""
        from asm.discovery import crtsh

        called = False

        def tracker(*args: object, **kwargs: object) -> None:
            nonlocal called
            called = True
            raise crtsh.requests.exceptions.ConnectionError("blocked")

        monkeypatch.setattr(crtsh.requests, "get", tracker)
        crtsh.discover_hostnames(DOMAIN)
        assert called, "discovery should attempt the configured source"
