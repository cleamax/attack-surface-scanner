"""HTTP probe behaviour: errors are outcomes, not exceptions."""

from __future__ import annotations

import httpx
import pytest

from asm.utils import http as http_module
from asm.utils.http import HttpProbeResult, probe_url


class TestProbeResult:
    def test_ok_requires_a_status_code(self) -> None:
        assert HttpProbeResult(url="https://a.example.com", status_code=200).ok is True
        assert HttpProbeResult(url="https://a.example.com", error="timeout").ok is False

    def test_final_scheme_is_read_from_the_final_url(self) -> None:
        result = HttpProbeResult(url="http://a.example.com", final_url="https://a.example.com/x")
        assert result.final_scheme == "https"

    def test_final_scheme_is_none_without_a_final_url(self) -> None:
        assert HttpProbeResult(url="http://a.example.com").final_scheme is None


class TestProbeUrl:
    @pytest.mark.parametrize(
        ("exception", "expected"),
        [
            (httpx.ProxyError("407"), "proxy_auth_required"),
            (httpx.ConnectTimeout("slow"), "timeout"),
            (httpx.ReadTimeout("slow"), "read_timeout"),
            (httpx.ConnectError("refused"), "connect_error"),
        ],
    )
    def test_network_failures_become_error_strings(
        self, monkeypatch: pytest.MonkeyPatch, exception: Exception, expected: str
    ) -> None:
        """A scan must survive an unreachable host; every hostname is a candidate."""

        class FailingClient:
            def __init__(self, *args: object, **kwargs: object) -> None:
                pass

            def __enter__(self) -> FailingClient:
                return self

            def __exit__(self, *args: object) -> None:
                return None

            def get(self, url: str) -> None:
                raise exception

        monkeypatch.setattr(http_module.httpx, "Client", FailingClient)

        result = probe_url("https://a.example.com")

        assert result.error == expected
        assert result.status_code is None
        assert result.ok is False

    def test_successful_response_captures_headers_and_timing(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        class FakeResponse:
            url = "https://a.example.com/"
            status_code = 200
            headers = httpx.Headers({"Content-Security-Policy": "default-src 'self'"})
            history: list = []

        class FakeClient:
            def __init__(self, *args: object, **kwargs: object) -> None:
                pass

            def __enter__(self) -> FakeClient:
                return self

            def __exit__(self, *args: object) -> None:
                return None

            def get(self, url: str) -> FakeResponse:
                return FakeResponse()

        monkeypatch.setattr(http_module.httpx, "Client", FakeClient)

        result = probe_url("https://a.example.com")

        assert result.status_code == 200
        assert "content-security-policy" in result.headers
        assert result.response_ms is not None and result.response_ms >= 0

    def test_redirect_chain_is_recorded(self, monkeypatch: pytest.MonkeyPatch) -> None:
        class Step:
            def __init__(self, url: str) -> None:
                self.url = url

        class FakeResponse:
            url = "https://a.example.com/"
            status_code = 200
            headers = httpx.Headers({})
            history = [Step("http://a.example.com/")]

        class FakeClient:
            def __init__(self, *args: object, **kwargs: object) -> None:
                pass

            def __enter__(self) -> FakeClient:
                return self

            def __exit__(self, *args: object) -> None:
                return None

            def get(self, url: str) -> FakeResponse:
                return FakeResponse()

        monkeypatch.setattr(http_module.httpx, "Client", FakeClient)

        result = probe_url("http://a.example.com")

        assert result.redirect_chain == ["http://a.example.com/"]
        assert result.final_scheme == "https"
