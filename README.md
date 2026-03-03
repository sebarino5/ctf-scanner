# ctf-scanner

Python CLI Tool fuer automatisierte, defensive Scans auf **autorisierten CTF-Zielen oder eigenen Systemen**.

- Keine Exploits
- Kein Brute Force
- Nmap als Portscan-Wrapper
- Directory Scan mit fester Standard-Wordlist
- Ausgabe als Markdown + Nmap XML im Ordner `outputs/`

## Voraussetzungen

- Python 3.10+
- `nmap` installiert und im `PATH`

## Installation

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Nutzung

CLI kann via Modul gestartet werden:

```bash
PYTHONPATH=src python -m ctf_scanner --help
```

### Beispiele

1. Domain, Standardprofil (`balanced`) und `top1000` Ports:

```bash
PYTHONPATH=src python -m ctf_scanner example.com
```

2. Kombinierte Profile `quick` + `deep` auf URL und IP:

```bash
PYTHONPATH=src python -m ctf_scanner https://target.local 10.10.10.10 --profile quick --profile deep
```

3. CIDR mit Top 100 Ports:

```bash
PYTHONPATH=src python -m ctf_scanner 10.10.10.0/24 --ports-mode top100
```

4. Full Portscan:

```bash
PYTHONPATH=src python -m ctf_scanner target.internal --ports-mode full
```

5. Custom Ports:

```bash
PYTHONPATH=src python -m ctf_scanner 192.168.1.20 --ports-mode custom --ports 22,80,443,8000-8100
```

## CLI Optionen

- `targets` (Pflicht): Domain, IP, URL oder CIDR (mehrere Werte erlaubt)
- `--profile`: `quick`, `balanced`, `deep` (mehrfach kombinierbar)
- `--ports-mode`: `top100`, `top1000`, `full`, `custom`
- `--ports`: Portliste nur bei `--ports-mode custom`
- `--output-dir`: Ausgabeordner (Default: `outputs`)
- `--dir-timeout`: HTTP Timeout je Request fuer Directory Scan (Default: `5.0`)

## Output

Im Ausgabeordner entstehen pro Lauf:

- `nmap_YYYYMMDD_HHMMSS.xml`
- `report_YYYYMMDD_HHMMSS.md`

Der Markdown-Report enthaelt:

- eingesetzte Scan-Konfiguration
- offene Ports/Services pro Host
- Directory-Scan-Funde mit HTTP-Status
