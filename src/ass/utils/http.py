from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional

import httpx


@dataclass
class HttpProbeResult:
    url: str
    final_url: Optional[str]
    status_code: Optional[int]
    redirect_chain: List[str]
    error: Optional[str] = None


def probe_url(url: str, timeout: float = 5.0) -> HttpProbeResult:
    """
    Safe HTTP probe using GET with redirects (max 5).
    Uses system proxy settings by default (httpx trust_env=True).
    """
    try:
        with httpx.Client(
            timeout=timeout,
            follow_redirects=True,
            max_redirects=5,
            headers={"User-Agent": "ass-scanner/0.1"},
            trust_env=True,  # reads HTTPS_PROXY/HTTP_PROXY if set (home)
        ) as client:
            r = client.get(url)
            chain = [str(h.url) for h in r.history] if r.history else []
            return HttpProbeResult(
                url=url,
                final_url=str(r.url),
                status_code=r.status_code,
                redirect_chain=chain,
                error=None,
            )
    except httpx.ProxyError:
        return HttpProbeResult(url, None, None, [], error="proxy_auth_required")
    except httpx.ConnectTimeout:
        return HttpProbeResult(url, None, None, [], error="timeout")
    except httpx.ConnectError:
        return HttpProbeResult(url, None, None, [], error="connect_error")
    except Exception:
        return HttpProbeResult(url, None, None, [], error="unknown_error")
