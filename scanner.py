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
