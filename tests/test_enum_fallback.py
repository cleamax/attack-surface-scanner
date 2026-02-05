from ass.enum.crtsh import enumerate_subdomains, fallback_subdomains


def test_fallback_subdomains_are_deterministic():
    subs = fallback_subdomains("example.com")
    assert "www.example.com" in subs
    assert "api.example.com" in subs
    assert len(subs) >= 5


def test_enumerate_subdomains_returns_non_empty_via_fallback():
    res = enumerate_subdomains("example.com")
    assert len(res.subdomains) > 0
