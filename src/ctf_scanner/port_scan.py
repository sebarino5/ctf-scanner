from __future__ import annotations

import os
import shutil
import subprocess
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path


PROFILE_FLAGS: dict[str, list[str]] = {
    "quick": ["-T4", "--max-retries", "1", "--host-timeout", "30s"],
    "balanced": ["-T3", "-sV", "--version-light"],
    "deep": ["-T3", "-sV", "-sC", "--script", "default,safe", "--reason"],
}


@dataclass
class ScriptResult:
    id: str
    output: str


@dataclass
class PortResult:
    port: int
    protocol: str
    state: str
    service: str
    product: str | None
    version: str | None
    scripts: list[ScriptResult] = field(default_factory=list)


@dataclass
class HostResult:
    host: str
    state: str
    open_ports: list[PortResult]
    os_matches: list[str] = field(default_factory=list)


@dataclass
class NmapRunResult:
    xml_path: Path
    command: list[str]
    hosts: list[HostResult]


def _build_port_flags(ports_mode: str, custom_ports: str | None) -> list[str]:
    if ports_mode == "top100":
        return ["--top-ports", "100"]
    if ports_mode == "top1000":
        return ["--top-ports", "1000"]
    if ports_mode == "full":
        return ["-p-"]
    if ports_mode == "custom":
        if not custom_ports:
            raise ValueError("Bei ports-mode 'custom' muss --ports gesetzt sein.")
        return ["-p", custom_ports]
    raise ValueError(f"Unbekannter ports-mode: {ports_mode}")


def _dedupe_keep_order(items: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        if item in seen:
            continue
        seen.add(item)
        out.append(item)
    return out


def _combined_profile_flags(profiles: list[str]) -> list[str]:
    flags: list[str] = []
    for profile in profiles:
        flags.extend(PROFILE_FLAGS[profile])
    return _dedupe_keep_order(flags)


def _parse_host_address(host_node: ET.Element) -> str:
    addr = host_node.find("address")
    if addr is not None and addr.attrib.get("addr"):
        return addr.attrib["addr"]
    hostname = host_node.find("hostnames/hostname")
    if hostname is not None and hostname.attrib.get("name"):
        return hostname.attrib["name"]
    return "unknown"


def parse_nmap_xml(xml_path: Path) -> list[HostResult]:
    tree = ET.parse(xml_path)
    root = tree.getroot()
    hosts: list[HostResult] = []

    for host in root.findall("host"):
        status = host.find("status")
        state = status.attrib.get("state", "unknown") if status is not None else "unknown"
        host_id = _parse_host_address(host)

        ports: list[PortResult] = []
        for port in host.findall("ports/port"):
            port_state = port.find("state")
            if port_state is None:
                continue
            if port_state.attrib.get("state") != "open":
                continue

            service = port.find("service")
            scripts = [
                ScriptResult(id=s.attrib.get("id", ""), output=s.attrib.get("output", ""))
                for s in port.findall("script")
                if s.attrib.get("id")
            ]
            ports.append(
                PortResult(
                    port=int(port.attrib.get("portid", "0")),
                    protocol=port.attrib.get("protocol", "tcp"),
                    state=port_state.attrib.get("state", "unknown"),
                    service=service.attrib.get("name", "unknown") if service is not None else "unknown",
                    product=service.attrib.get("product") if service is not None else None,
                    version=service.attrib.get("version") if service is not None else None,
                    scripts=scripts,
                )
            )

        os_matches = [
            f"{m.attrib['name']} ({m.attrib.get('accuracy', '?')}%)"
            for m in host.findall("os/osmatch")
            if m.attrib.get("name")
        ]

        hosts.append(HostResult(host=host_id, state=state, open_ports=ports, os_matches=os_matches))

    return hosts


def run_nmap_scan(
    targets: list[str],
    profiles: list[str],
    ports_mode: str,
    custom_ports: str | None,
    output_dir: Path,
) -> NmapRunResult:
    if shutil.which("nmap") is None:
        raise RuntimeError("nmap wurde nicht gefunden. Bitte nmap installieren und erneut ausfuehren.")

    output_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    xml_path = output_dir / f"nmap_{timestamp}.xml"

    command = ["nmap", "-oX", os.fspath(xml_path), "--open"]
    command.extend(_combined_profile_flags(profiles))
    if "deep" in profiles and hasattr(os, "getuid") and os.getuid() == 0:
        command.extend(["-O", "--osscan-guess"])
    command.extend(_build_port_flags(ports_mode, custom_ports))
    command.extend(targets)

    completed = subprocess.run(command, capture_output=True, text=True)
    if completed.returncode != 0:
        stderr = completed.stderr.strip() or completed.stdout.strip() or "Unbekannter Fehler"
        raise RuntimeError(f"nmap Scan fehlgeschlagen: {stderr}")

    hosts = parse_nmap_xml(xml_path)
    return NmapRunResult(xml_path=xml_path, command=command, hosts=hosts)
