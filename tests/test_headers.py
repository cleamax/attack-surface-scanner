from ass.checks.headers import check_security_headers


def test_missing_headers_produce_findings():
    findings = check_security_headers({})
    ids = {f.id for f in findings}
    assert "HDR-001" in ids  # HSTS missing
    assert "HDR-002" in ids  # CSP missing


def test_present_headers_reduce_findings():
    headers = {
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
        "Content-Security-Policy": "default-src 'self'",
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "no-referrer",
    }
    findings = check_security_headers(headers)
    assert findings == []
