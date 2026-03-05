# ctf-scanner

Python Tool fuer automatisierte, defensive Scans auf **autorisierten CTF-Zielen oder eigenen Systemen**.

- Keine Exploits
- Kein Brute Force
- Nmap als Portscan-Wrapper
- Directory Scan mit Standard-Wordlist
- Web-Oberflaeche im Browser
- Ausgabe als Markdown + Nmap XML im Ordner `outputs/`

## Voraussetzungen

- Python 3.10+
- `nmap` installiert und im `PATH`

## Installation

```bash
git clone https://github.com/sebarino5/ctf-scanner.git
cd ctf-scanner
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Starten

```bash
source .venv/bin/activate
python web_ui.py
```

Browser oeffnen: **http://127.0.0.1:5000**

## Benutzung

1. Ziel eingeben (IP, Domain oder URL)
2. Profil waehlen: `quick`, `balanced` oder `deep`
3. Port-Modus waehlen: `Top 100`, `Top 1000` oder `Full`
4. Scan starten → Ergebnisse erscheinen direkt im Browser

## Scan-Profile

| Profil | Beschreibung |
|--------|-------------|
| `quick` | Schnell, wenig Retries, kurzer Timeout |
| `balanced` | Standard, Service-Erkennung |
| `deep` | Ausfuehrlich, Scripts, Versionserkennung |

## Port-Modi

| Modus | Beschreibung |
|-------|-------------|
| `top100` | Top 100 haeufigste Ports |
| `top1000` | Top 1000 haeufigste Ports (Standard) |
| `full` | Alle Ports (1-65535) |

## Output

Im Ordner `outputs/` entstehen pro Scan:

- `nmap_YYYYMMDD_HHMMSS.xml`
- `report_YYYYMMDD_HHMMSS.md`

## CLI (optional)

Der Scanner kann auch direkt ueber die Kommandozeile genutzt werden:

```bash
PYTHONPATH=src python -m ctf_scanner --help
```

## Rechtliches

Dieses Tool darf **nur auf Systemen eingesetzt werden, fuer die eine ausdrückliche Genehmigung vorliegt** (eigene Systeme, CTF-Challenges). Jede andere Nutzung ist illegal.
