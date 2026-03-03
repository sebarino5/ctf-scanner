# Minimal Web Scanner (Streamlit)

Diese Anwendung ist ein **minimaler Web Scanner mit GUI**.

## Funktionen

Es gibt genau **eine Eingabe**: eine Domain, z. B. `example.com`.

Beim Start des Scans werden nacheinander ausgeführt:

1. DNS-Auflösung mit `nslookup`
2. Portscan nur für `80` und `443` mit `nmap -sV`
3. Directory-Scan mit `dirb` (Standard-Wordlist)

Die GUI zeigt währenddessen ein Live-Log.

Zusätzlich werden automatisch gespeichert:

- Markdown-Report in `outputs/`
- Nmap XML-Datei in `outputs/`

## Projektstruktur

- `app/gui.py` – Streamlit GUI
- `app/scanner.py` – Scanner-Logik (Subprocess-Aufrufe)
- `requirements.txt`
- `README.md`

## Voraussetzungen

Installierte Tools im System:

- `nslookup`
- `nmap`
- `dirb`

Fehlende Tools werden erkannt und als Fehler im Log/Report ausgegeben.

## Start

```bash
pip install -r requirements.txt
streamlit run app/gui.py
```

Dann im Browser eine Domain eingeben und auf **Scan starten** klicken.

## Sicherheit / Scope

- Kein IP-Scan
- Kein CIDR
- Keine Profile
- Kein Exploiting
- Kein Brute Force
