from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .directory_scan import run_directory_scan
from .port_scan import run_nmap_scan
from .report_md import write_markdown_report
from .target_normalization import normalize_targets, make_output_dir


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ctf-scanner",
        description=(
            "Automatisierter Scanner fuer autorisierte CTF-Ziele oder eigene Systeme. "
            "Keine Exploits, kein Brute Force."
        ),
    )

    parser.add_argument(
        "targets",
        nargs="+",
        help="Ziele als Domain, IP, URL oder CIDR",
    )
    parser.add_argument(
        "--profile",
        action="append",
        choices=["quick", "balanced", "deep"],
        help="Portscan-Profil (mehrfach kombinierbar)",
    )
    parser.add_argument(
        "--ports-mode",
        default="top1000",
        choices=["top100", "top1000", "full", "custom"],
        help="Port-Auswahl fuer Nmap",
    )
    parser.add_argument(
        "--ports",
        help="Custom Ports, z.B. '22,80,443,8000-8100' (nur mit --ports-mode custom)",
    )
    parser.add_argument(
        "--output-dir",
        default="outputs",
        help="Ausgabeordner fuer Markdown-Report und Nmap XML",
    )
    parser.add_argument(
        "--dir-timeout",
        type=float,
        default=5.0,
        help="Timeout pro HTTP Request beim Directory Scan in Sekunden",
    )

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    profiles = args.profile or ["balanced"]

    if args.ports_mode != "custom" and args.ports:
        parser.error("--ports darf nur zusammen mit --ports-mode custom verwendet werden")
    if args.ports_mode == "custom" and not args.ports:
        parser.error("--ports-mode custom benoetigt --ports")

    try:
        normalized_targets = normalize_targets(args.targets)
    except ValueError as exc:
        parser.error(str(exc))

    output_dir = make_output_dir(Path(args.output_dir), normalized_targets)

    try:
        nmap_result = run_nmap_scan(
            targets=[t.for_nmap for t in normalized_targets],
            profiles=profiles,
            ports_mode=args.ports_mode,
            custom_ports=args.ports,
            output_dir=output_dir,
        )

        dir_targets = [t.for_http for t in normalized_targets if t.for_http]
        dir_findings = run_directory_scan(dir_targets, timeout=args.dir_timeout)

        report_path = write_markdown_report(
            output_dir=output_dir,
            targets=normalized_targets,
            profiles=profiles,
            ports_mode=args.ports_mode,
            custom_ports=args.ports,
            nmap_result=nmap_result,
            dir_findings=dir_findings,
        )
    except Exception as exc:  # pragma: no cover
        print(f"Fehler: {exc}", file=sys.stderr)
        return 1

    print(f"Scan abgeschlossen. Markdown: {report_path}")
    print(f"Nmap XML: {nmap_result.xml_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
