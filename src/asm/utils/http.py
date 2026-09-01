from __future__ import annotations

import time
from dataclasses import dataclass, field

import httpx

USER_AGENT = "asm-scanner/0.2 (+https://github.com/richter-max/attack-surface-scanner)"


@dataclass
class HttpProbeResult:
    url: str
    final_url: str | None = None
    status_code: int | None = None
    redirect_chain: list[str] = field(default_factory=list)
    headers: dict[str, str] = field(default_factory=dict)
    response_ms: int | None = None
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.status_code is not None

    @property
    def final_scheme(self) -> str | None:
        if not self.final_url:
            return None
        return self.final_url.split("://", 1)[0].lower()


def probe_url(url: str, timeout: float = 5.0) -> HttpProbeResult:
    """One non-intrusive GET, following up to five redirects.

    Headers are captured here rather than fetched again by the caller, so a finding is
    always attributed to the same response that produced the status code.
    """
    started = time.perf_counter()
    try:
        with httpx.Client(
            timeout=timeout,
            follow_redirects=True,
            max_redirects=5,
            headers={"User-Agent": USER_AGENT},
            trust_env=True,
        ) as client:
            response = client.get(url)

        return HttpProbeResult(
            url=url,
            final_url=str(response.url),
            status_code=response.status_code,
            redirect_chain=[str(step.url) for step in response.history],
            headers={k.lower(): v for k, v in response.headers.items()},
            response_ms=int((time.perf_counter() - started) * 1000),
        )
    except httpx.ProxyError:
        return HttpProbeResult(url=url, error="proxy_auth_required")
    except httpx.ConnectTimeout:
        return HttpProbeResult(url=url, error="timeout")
    except httpx.ReadTimeout:
        return HttpProbeResult(url=url, error="read_timeout")
    except httpx.TooManyRedirects:
        return HttpProbeResult(url=url, error="too_many_redirects")
    except httpx.ConnectError:
        return HttpProbeResult(url=url, error="connect_error")
    except httpx.HTTPError as exc:
        return HttpProbeResult(url=url, error=exc.__class__.__name__.lower())
