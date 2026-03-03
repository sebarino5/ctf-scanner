from __future__ import annotations

import re
import shutil
import subprocess
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Callable

LOG_FN = Callable[[str], None]


@dataclass
class ScanResult:
    domain: str
    timestamp: str = field(default_factory=lambda: datetime.now().strftime("%Y%m%d_%H%M%S"))
    dns_output: str = ""
    nmap_output: str = ""
    dirb_output: str = ""
    errors: list[str] = field(default_factory=list)
    xml_report_path: Path | None = None
    md_report_path: Path | None = None


class ScannerError(Exception):
    """Raised when user input is invalid."""


DOMAIN_PATTERN = re.compile(
    r"^(?=.{1,253}$)(?!-)(?:[a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,63}$"
)


class WebScanner:
    def __init__(self, output_dir: str = "outputs") -> None:
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def validate_domain(self, domain: str) -> str:
        normalized = domain.strip().lower()
        if normalized.startswith(("http://", "https://")):
            normalized = normalized.split("://", 1)[1]
        normalized = normalized.split("/", 1)[0]

        if not DOMAIN_PATTERN.match(normalized):
            raise ScannerError(
                "Ungültige Domain. Bitte nur eine gültige Webadresse wie example.com eingeben."
            )
        return normalized

    def run_scan(self, domain: str, log: LOG_FN) -> ScanResult:
        domain = self.validate_domain(domain)
        result = ScanResult(domain=domain)

        log(f"Starte Scan für {domain}")
        result.dns_output = self._run_nslookup(domain, log, result)

        xml_path = self.output_dir / f"nmap_{domain}_{result.timestamp}.xml"
        result.xml_report_path = xml_path
        result.nmap_output = self._run_nmap(domain, xml_path, log, result)

        result.dirb_output = self._run_dirb(domain, log, result)

        md_path = self.output_dir / f"report_{domain}_{result.timestamp}.md"
        result.md_report_path = md_path
        md_path.write_text(self._build_markdown(result), encoding="utf-8")
        log(f"Markdown Report gespeichert: {md_path}")

        return result

    def _run_nslookup(self, domain: str, log: LOG_FN, result: ScanResult) -> str:
        log("[1/3] DNS Auflösung mit nslookup...")
        return self._run_command(["nslookup", domain], log, result, "nslookup")

    def _run_nmap(self, domain: str, xml_path: Path, log: LOG_FN, result: ScanResult) -> str:
        log("[2/3] Portscan (80, 443) mit nmap Service Detection...")
        return self._run_command(
            ["nmap", "-sV", "-p", "80,443", "-oX", str(xml_path), domain],
            log,
            result,
            "nmap",
        )

    def _run_dirb(self, domain: str, log: LOG_FN, result: ScanResult) -> str:
        log("[3/3] Directory Scan mit dirb Standard Wordlist...")
        target_url = f"http://{domain}"
        return self._run_command(["dirb", target_url], log, result, "dirb")

    def _run_command(
        self,
        command: list[str],
        log: LOG_FN,
        result: ScanResult,
        tool_name: str,
    ) -> str:
        if shutil.which(tool_name) is None:
            message = f"Tool nicht gefunden: {tool_name}. Bitte installieren und erneut versuchen."
            result.errors.append(message)
            log(f"FEHLER: {message}")
            return message

        try:
            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                check=False,
            )
        except Exception as exc:  # defensive fallback around subprocess execution
            message = f"Fehler beim Ausführen von {' '.join(command)}: {exc}"
            result.errors.append(message)
            log(f"FEHLER: {message}")
            return message

        output = (completed.stdout or "") + ("\n" + completed.stderr if completed.stderr else "")
        if completed.returncode != 0:
            message = (
                f"Befehl fehlgeschlagen ({completed.returncode}): {' '.join(command)}\n{output}".strip()
            )
            result.errors.append(message)
            log(f"WARNUNG: {tool_name} lieferte Rückgabecode {completed.returncode}")
            return message

        log(f"OK: {tool_name} abgeschlossen")
        return output.strip()

    def _build_markdown(self, result: ScanResult) -> str:
        errors = "\n".join(f"- {e}" for e in result.errors) if result.errors else "- Keine"
        xml_path_str = str(result.xml_report_path) if result.xml_report_path else "Nicht vorhanden"

        return f"""# Web Scanner Report

- **Domain:** {result.domain}
- **Zeitpunkt:** {result.timestamp}
- **Nmap XML:** `{xml_path_str}`

## Fehler
{errors}

## DNS (nslookup)
```text
{result.dns_output}
```

## Portscan (nmap -sV -p 80,443)
```text
{result.nmap_output}
```

## Directory Scan (dirb Standard Wordlist)
```text
{result.dirb_output}
```
"""
