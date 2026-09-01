"""DNS resolution. An unresolvable hostname is a normal discovery outcome."""

from __future__ import annotations

import dns.exception
import dns.resolver
import pytest

from asm.discovery import resolver as resolver_module
from asm.discovery.resolver import resolve_ips


class _Rdata:
    def __init__(self, value: str) -> None:
        self.value = value

    def __str__(self) -> str:
        return self.value


def _patch_resolver(monkeypatch: pytest.MonkeyPatch, behaviour) -> None:
    class FakeResolver:
        timeout = 2.0
        lifetime = 2.0

        def resolve(self, hostname: str, record_type: str):
            return behaviour(hostname, record_type)

    monkeypatch.setattr(resolver_module.dns.resolver, "Resolver", FakeResolver)


def test_a_and_aaaa_are_merged_and_sorted(monkeypatch: pytest.MonkeyPatch) -> None:
    def behaviour(hostname: str, record_type: str):
        if record_type == "A":
            return [_Rdata("203.0.113.10"), _Rdata("203.0.113.1")]
        return [_Rdata("2001:db8::1")]

    _patch_resolver(monkeypatch, behaviour)

    assert resolve_ips("a.example.com") == ["2001:db8::1", "203.0.113.1", "203.0.113.10"]


def test_duplicates_are_removed(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_resolver(monkeypatch, lambda h, t: [_Rdata("203.0.113.10"), _Rdata("203.0.113.10")])
    assert resolve_ips("a.example.com") == ["203.0.113.10"]


@pytest.mark.parametrize(
    "exception",
    [
        dns.resolver.NXDOMAIN(),
        dns.resolver.NoAnswer(),
        dns.exception.Timeout(),
    ],
)
def test_lookup_failures_return_empty(monkeypatch: pytest.MonkeyPatch, exception: Exception) -> None:
    def behaviour(hostname: str, record_type: str):
        raise exception

    _patch_resolver(monkeypatch, behaviour)
    assert resolve_ips("gone.example.com") == []


def test_partial_failure_still_returns_what_resolved(monkeypatch: pytest.MonkeyPatch) -> None:
    def behaviour(hostname: str, record_type: str):
        if record_type == "AAAA":
            raise dns.resolver.NoAnswer()
        return [_Rdata("203.0.113.10")]

    _patch_resolver(monkeypatch, behaviour)
    assert resolve_ips("a.example.com") == ["203.0.113.10"]
