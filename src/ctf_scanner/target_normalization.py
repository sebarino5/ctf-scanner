from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse


DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.?$")


@dataclass(frozen=True)
class NormalizedTarget:
    raw: str
    normalized: str
    kind: str
    for_nmap: str
    for_http: str | None


def _normalize_url(value: str) -> NormalizedTarget:
    parsed = urlparse(value)
    if not parsed.scheme or not parsed.netloc:
        raise ValueError(f"Ungueltige URL: {value}")
    host = parsed.hostname
    if not host:
        raise ValueError(f"Ungueltige URL ohne Host: {value}")
    path = parsed.path or "/"
    base = f"{parsed.scheme}://{host}"
    return NormalizedTarget(
        raw=value,
        normalized=value,
        kind="url",
        for_nmap=host,
        for_http=base + path,
    )


def _normalize_ip_or_cidr(value: str) -> NormalizedTarget:
    try:
        ip = ipaddress.ip_address(value)
        return NormalizedTarget(
            raw=value,
            normalized=str(ip),
            kind="ip",
            for_nmap=str(ip),
            for_http=f"http://{ip}",
        )
    except ValueError:
        pass

    try:
        network = ipaddress.ip_network(value, strict=False)
        return NormalizedTarget(
            raw=value,
            normalized=str(network),
            kind="cidr",
            for_nmap=str(network),
            for_http=None,
        )
    except ValueError:
        raise ValueError(f"Ungueltiges IP/CIDR Ziel: {value}") from None


def _normalize_domain(value: str) -> NormalizedTarget:
    candidate = value.strip().lower()
    if not DOMAIN_RE.match(candidate):
        raise ValueError(f"Ungueltige Domain: {value}")
    domain = candidate.rstrip(".")
    return NormalizedTarget(
        raw=value,
        normalized=domain,
        kind="domain",
        for_nmap=domain,
        for_http=f"http://{domain}",
    )


def normalize_target(value: str) -> NormalizedTarget:
    candidate = value.strip()
    if not candidate:
        raise ValueError("Leeres Ziel ist nicht erlaubt")

    if "://" in candidate:
        return _normalize_url(candidate)

    try:
        return _normalize_ip_or_cidr(candidate)
    except ValueError:
        return _normalize_domain(candidate)


def make_output_dir(base: Path, targets: list[NormalizedTarget]) -> Path:
    """outputs/<sanitized-target>/  — z.B. outputs/10.10.10.5/ oder outputs/example.com/"""
    name = "_".join(t.normalized for t in targets)
    safe = re.sub(r"[^\w.\-]", "_", name).strip("_") or "scan"
    return base / safe


def normalize_targets(values: list[str]) -> list[NormalizedTarget]:
    normalized: list[NormalizedTarget] = []
    seen: set[str] = set()

    for item in values:
        target = normalize_target(item)
        key = f"{target.kind}:{target.for_nmap}:{target.for_http or ''}"
        if key in seen:
            continue
        seen.add(key)
        normalized.append(target)

    return normalized
