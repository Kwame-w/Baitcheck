"""Optional VirusTotal enrichment (API v3).

Only hashes and domains are looked up; URLs and files are never submitted, so
nothing from the email is shared that wasn't already public. Set VT_API_KEY
to enable it (a free community key works, at 4 requests per minute).
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass

API = "https://www.virustotal.com/api/v3"


@dataclass
class VTResult:
    ioc: str
    kind: str  # file or domain
    malicious: int | None
    suspicious: int | None
    error: str | None = None

    @property
    def flagged(self) -> bool:
        return bool(self.malicious or self.suspicious)


def _default_fetch(url: str, api_key: str) -> dict:
    request = urllib.request.Request(url, headers={"x-apikey": api_key, "accept": "application/json"})
    # The URL is always built from the fixed https API constant above.
    with urllib.request.urlopen(request, timeout=20) as response:  # nosec B310
        return json.loads(response.read().decode())


def lookup(
    iocs: dict[str, list[str]],
    api_key: str,
    fetch: Callable[[str, str], dict] = _default_fetch,
    delay: float = 15.0,
    limit: int = 8,
) -> list[VTResult]:
    """Look up attachment hashes and link domains. ``fetch`` is injectable for tests."""
    targets = [("files", h, "file") for h in iocs.get("attachment_sha256", [])]
    targets += [("domains", d, "domain") for d in iocs.get("domains", [])]
    results = []
    for i, (endpoint, value, kind) in enumerate(targets[:limit]):
        if i and delay:
            time.sleep(delay)  # respect the free-tier rate limit
        try:
            data = fetch(f"{API}/{endpoint}/{value}", api_key)
            stats = data["data"]["attributes"]["last_analysis_stats"]
            results.append(VTResult(value, kind, stats.get("malicious", 0), stats.get("suspicious", 0)))
        except urllib.error.HTTPError as exc:
            msg = "not found in VirusTotal" if exc.code == 404 else f"HTTP {exc.code}"
            results.append(VTResult(value, kind, None, None, msg))
        except (urllib.error.URLError, KeyError, ValueError, TimeoutError) as exc:
            results.append(VTResult(value, kind, None, None, str(exc)))
    return results
