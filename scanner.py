import argparse
import asyncio
import json
import random
from pathlib import Path
from typing import Dict, List, Optional
from urllib.parse import urlparse

import httpx

SECURITY_HEADERS = [
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
]


def is_in_scope(url: str, allowed_hosts: List[str]) -> bool:
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    return host in [h.lower() for h in allowed_hosts]


async def fetch_with_retry(
    client: httpx.AsyncClient,
    url: str,
    headers: Optional[Dict[str, str]] = None,
    retries: int = 2,
    jitter_max: float = 0.25,
) -> Optional[httpx.Response]:
    for attempt in range(retries + 1):
        try:
            await asyncio.sleep(random.uniform(0.05, jitter_max))
            resp = await client.get(url, headers=headers or {}, follow_redirects=False)
            return resp
        except (httpx.TimeoutException, httpx.TransportError):
            if attempt == retries:
                return None
            await asyncio.sleep(0.3 * (attempt + 1))
    return None


async def audit_endpoint(
    client: httpx.AsyncClient,
    sem: asyncio.Semaphore,
    url: str,
    allowed_hosts: List[str],
) -> Dict:
    if not is_in_scope(url, allowed_hosts):
        return {"url": url, "skipped": True, "reason": "host not in allowed scope"}

    async with sem:
        resp = await fetch_with_retry(client, url)
        if resp is None:
            return {"url": url, "error": "request failed after retries"}

        findings: List[Dict[str, str]] = []
        resp_headers = {k.lower(): v for k, v in resp.headers.items()}

        # 1. check missing security headers
        for h in SECURITY_HEADERS:
            if h not in resp_headers:
                findings.append({"type": "missing_header", "detail": "missing %s" % h})

        # 2. check CORS with untrusted origin
        cors_resp = await fetch_with_retry(
            client, url, headers={"Origin": "https://untrusted.example.invalid"}
        )
        if cors_resp is not None:
            acao = cors_resp.headers.get("access-control-allow-origin", "")
            acac = cors_resp.headers.get("access-control-allow-credentials", "").lower()
            if acao == "*" and acac == "true":
                findings.append({"type": "cors", "detail": "wildcard origin with credentials=true"})
            elif "untrusted.example.invalid" in acao:
                findings.append({"type": "cors", "detail": "reflects arbitrary Origin header"})

        # 3. passive open-redirect check on common param
        sep = "&" if "?" in url else "?"
        redir_resp = await fetch_with_retry(
            client, url + sep + "next=https://example.invalid/test"
        )
        if redir_resp is not None and redir_resp.status_code in (301, 302, 303, 307, 308):
            loc = redir_resp.headers.get("location", "")
            if loc.startswith("https://example.invalid"):
                findings.append({"type": "open_redirect", "detail": "Location reflects ?next= target"})

        # 4. basic auth / cookie flag checks
        if "www-authenticate" in resp_headers and url.startswith("http://"):
            findings.append({"type": "auth", "detail": "Basic/Auth challenge over plain HTTP"})

