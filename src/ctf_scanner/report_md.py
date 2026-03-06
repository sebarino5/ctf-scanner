from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from .directory_scan import DirectoryFinding
from .port_scan import NmapRunResult
from .target_normalization import NormalizedTarget


def _host_section(run_result: NmapRunResult) -> list[str]:
    lines: list[str] = ["## Port Scan Ergebnisse", ""]

    if not run_result.hosts:
        lines.extend(["Keine Hosts im Nmap XML gefunden.", ""])
        return lines

    for host in run_result.hosts:
        lines.append(f"### Host: `{host.host}` ({host.state})")

        if host.os_matches:
            lines.append(f"**OS Detection:** {' | '.join(host.os_matches)}")
        lines.append("")

        if not host.open_ports:
            lines.append("Keine offenen Ports im gewaehlten Profil gefunden.")
            lines.append("")
            continue

        lines.append("| Port | Proto | Service | Produkt/Version |")
        lines.append("|---|---|---|---|")
        for port in sorted(host.open_ports, key=lambda p: (p.port, p.protocol)):
            pv = " ".join([p for p in [port.product, port.version] if p]).strip() or "-"
            lines.append(f"| {port.port} | {port.protocol} | {port.service} | {pv} |")
        lines.append("")

        scripts_found = [s for port in host.open_ports for s in port.scripts]
        if scripts_found:
            lines.append("#### Script Ergebnisse")
            lines.append("")
            for port in sorted(host.open_ports, key=lambda p: p.port):
                for script in port.scripts:
                    lines.append(f"**{port.port}/{port.protocol} — {script.id}:**")
                    lines.append("```")
                    lines.append(script.output.strip())
                    lines.append("```")
                    lines.append("")

    return lines


def _directory_section(findings: list[DirectoryFinding]) -> list[str]:
    lines: list[str] = ["## Directory Scan Ergebnisse", ""]

    if not findings:
        lines.extend(["Keine auffaelligen Pfade gefunden.", ""])
        return lines

    lines.append("| Ziel | URL | Status | Content-Length | Redirect |")
    lines.append("|---|---|---|---|---|")
    for finding in findings:
        redirect = finding.location or "-"
        size = str(finding.content_length) if finding.content_length is not None else "-"
        lines.append(
            f"| `{finding.target}` | `{finding.url}` | {finding.status_code} | {size} | `{redirect}` |"
        )
    lines.append("")
    return lines


def write_markdown_report(
    output_dir: Path,
    targets: list[NormalizedTarget],
    profiles: list[str],
    ports_mode: str,
    custom_ports: str | None,
    nmap_result: NmapRunResult,
    dir_findings: list[DirectoryFinding],
) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    report_path = output_dir / f"report_{timestamp}.md"

    lines: list[str] = [
        "# CTF Scanner Report",
        "",
        f"Erstellt (UTC): {datetime.now(timezone.utc).isoformat()}",
        "",
        "## Konfiguration",
        "",
        f"- Ziele: {', '.join(f'`{t.normalized}` ({t.kind})' for t in targets)}",
        f"- Profile: {', '.join(f'`{p}`' for p in profiles)}",
        f"- Ports-Modus: `{ports_mode}`",
    ]

    if custom_ports:
        lines.append(f"- Custom Ports: `{custom_ports}`")

    lines.extend(
        [
            f"- Nmap XML: `{nmap_result.xml_path}`",
            f"- Nmap Command: `{' '.join(nmap_result.command)}`",
            "",
        ]
    )

    lines.extend(_host_section(nmap_result))
    lines.extend(_directory_section(dir_findings))

    report_path.write_text("\n".join(lines), encoding="utf-8")
    return report_path
