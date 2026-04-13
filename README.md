# ctf-scanner

Python tool for automated, defensive scans on **authorized CTF targets or own systems**.

- No exploits
- No brute force
- Nmap as port scan wrapper
- Directory scan with standard wordlist
- Web interface in the browser
- Output as Markdown + Nmap XML in the `outputs/` folder

## Requirements

- Python 3.10+
- `nmap` installed and in `PATH`

## Installation

```bash
git clone https://github.com/sebarino5/ctf-scanner.git
cd ctf-scanner
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Start

```bash
source .venv/bin/activate
python web_ui.py
```

Open browser: **http://127.0.0.1:5000**

## Usage

1. Enter target (IP, domain or URL)
2. Choose profile: `quick`, `balanced` or `deep`
3. Choose port mode: `Top 100`, `Top 1000` or `Full`
4. Start scan — results appear directly in the browser

## Scan Profiles

| Profile | Description |
|---------|-------------|
| `quick` | Fast, few retries, short timeout |
| `balanced` | Default, service detection |
| `deep` | Thorough, scripts, version detection |

## Port Modes

| Mode | Description |
|------|-------------|
| `top100` | Top 100 most common ports |
| `top1000` | Top 1000 most common ports (default) |
| `full` | All ports (1-65535) |

## Output

Each scan creates the following files in `outputs/`:

- `nmap_YYYYMMDD_HHMMSS.xml`
- `report_YYYYMMDD_HHMMSS.md`

## CLI (optional)

The scanner can also be used directly via the command line:

```bash
IYTHONPATH=src python -m ctf_scanner --help
```

## Legal

This tool may **only be used on systems for which explicit authorization exists** (own systems, CTF challenges). Any other use is illegal.
