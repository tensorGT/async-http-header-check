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
