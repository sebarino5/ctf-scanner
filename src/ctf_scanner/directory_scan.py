from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urljoin, urlparse

import requests


STANDARD_WORDLIST = [
    "admin",
    "login",
    "dashboard",
    "api",
    "robots.txt",
    "sitemap.xml",
    ".git",
    "backup",
    "uploads",
    "config",
    "status",
    "health",
    "docs",
    "readme",
    "test",
]

INTERESTING_CODES = {200, 204, 301, 302, 307, 308, 401, 403}


@dataclass
class DirectoryFinding:
    target: str
    url: str
    status_code: int
    content_length: int | None
    location: str | None


def _base_url(raw_url: str) -> str:
    parsed = urlparse(raw_url)
    if not parsed.scheme or not parsed.netloc:
        raise ValueError(f"Invalid base URL for directory scan: {raw_url}")
    return f"{parsed.scheme}://{parsed.netloc}/"


def run_directory_scan(target_urls: list[str], timeout: float = 5.0) -> list[DirectoryFinding]:
    findings: list[DirectoryFinding] = []

    with requests.Session() as session:
        session.headers.update({"User-Agent": "ctf-scanner/1.0"})

        for target_url in target_urls:
            base = _base_url(target_url)
            for word in STANDARD_WORDLIST:
                probe = urljoin(base, word)
                try:
                    response = session.get(probe, timeout=timeout, allow_redirects=False)
                except requests.RequestException:
                    continue

                if response.status_code not in INTERESTING_CODES:
                    continue

                length_header = response.headers.get("Content-Length")
                content_length = int(length_header) if length_header and length_header.isdigit() else None
                findings.append(
                    DirectoryFinding(
                        target=target_url,
                        url=probe,
                        status_code=response.status_code,
                        content_length=content_length,
                        location=response.headers.get("Location"),
                    )
                )

    return findings
