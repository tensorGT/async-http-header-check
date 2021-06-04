import argparse
import asyncio
import json
import random
from pathlib import Path
from typing import Dict, List, Optional
from urllib.parse import urlparse

import httpx

SECURITY_HEADERS = [
