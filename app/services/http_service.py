"""Verificação de disponibilidade HTTP(S)."""
import time

import httpx

SECURITY_HEADERS = [
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
]


def lookup(domain: str, timeout: float = 10.0) -> dict:
    last_error = None
    for scheme in ("https", "http"):
        url = f"{scheme}://{domain}"
        start = time.perf_counter()
        try:
            with httpx.Client(
                follow_redirects=True, timeout=timeout, verify=False,
                headers={"User-Agent": "WhoisNotification/2.0 (+monitor)"},
            ) as c:
                resp = c.get(url)
            ms = round((time.perf_counter() - start) * 1000)
            chain = [{"url": str(r.url), "status": r.status_code} for r in resp.history]
            headers = {k.lower(): v for k, v in resp.headers.items()}
            return {
                "url": url,
                "final_url": str(resp.url),
                "status": resp.status_code,
                "reason": resp.reason_phrase,
                "ms": ms,
                "redirects": chain,
                "https": str(resp.url).startswith("https://"),
                "http_version": resp.http_version,
                "server": headers.get("server"),
                "security_headers": {h: (h in headers) for h in SECURITY_HEADERS},
                "online": resp.status_code < 500,
            }
        except httpx.HTTPError as e:
            last_error = f"{scheme.upper()}: {type(e).__name__}: {e}"
    return {"url": f"https://{domain}", "online": False, "error": last_error, "status": None, "ms": None}
