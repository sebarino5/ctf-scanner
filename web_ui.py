from __future__ import annotations

import sys
import threading
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "src"))

from flask import Flask, render_template_string, request, jsonify

from ctf_scanner.directory_scan import run_directory_scan
from ctf_scanner.port_scan import run_nmap_scan
from ctf_scanner.report_md import write_markdown_report
from ctf_scanner.target_normalization import normalize_targets

app = Flask(__name__)

# Scan status storage (simple in-memory for prototype)
scan_state: dict = {"running": False, "result": None, "error": None}

HTML = """
<!DOCTYPE html>
<html lang="de">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>CTF Scanner</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background: #0d1117;
      color: #c9d1d9;
      font-family: 'Courier New', monospace;
      min-height: 100vh;
      padding: 2rem;
    }
    h1 {
      color: #58a6ff;
      font-size: 1.8rem;
      margin-bottom: 0.3rem;
    }
    .subtitle {
      color: #8b949e;
      font-size: 0.85rem;
      margin-bottom: 2rem;
    }
    .card {
      background: #161b22;
      border: 1px solid #30363d;
      border-radius: 8px;
      padding: 1.5rem;
      margin-bottom: 1.5rem;
      max-width: 800px;
    }
    label {
      display: block;
      color: #8b949e;
      font-size: 0.85rem;
      margin-bottom: 0.4rem;
    }
    input[type="text"] {
      width: 100%;
      background: #0d1117;
      border: 1px solid #30363d;
      border-radius: 6px;
      color: #c9d1d9;
      font-family: inherit;
      font-size: 1rem;
      padding: 0.6rem 0.8rem;
      margin-bottom: 1rem;
      outline: none;
      transition: border-color 0.2s;
    }
    input[type="text"]:focus { border-color: #58a6ff; }
    .row { display: flex; gap: 1rem; flex-wrap: wrap; margin-bottom: 1rem; }
    .group { flex: 1; min-width: 180px; }
    select {
      width: 100%;
      background: #0d1117;
      border: 1px solid #30363d;
      border-radius: 6px;
      color: #c9d1d9;
      font-family: inherit;
      font-size: 0.9rem;
      padding: 0.5rem 0.7rem;
      outline: none;
    }
    button {
      background: #238636;
      border: none;
      border-radius: 6px;
      color: #fff;
      cursor: pointer;
      font-family: inherit;
      font-size: 1rem;
      padding: 0.65rem 1.5rem;
      transition: background 0.2s;
    }
    button:hover { background: #2ea043; }
    button:disabled { background: #21262d; color: #484f58; cursor: not-allowed; }
    #status {
      color: #f0883e;
      font-size: 0.9rem;
      margin-top: 0.8rem;
      min-height: 1.2rem;
    }
    #results { display: none; }
    .section-title {
      color: #58a6ff;
      font-size: 1rem;
      margin-bottom: 0.8rem;
      border-bottom: 1px solid #30363d;
      padding-bottom: 0.4rem;
    }
    table {
      width: 100%;
      border-collapse: collapse;
      font-size: 0.875rem;
    }
    th {
      text-align: left;
      color: #8b949e;
      padding: 0.4rem 0.6rem;
      border-bottom: 1px solid #30363d;
    }
    td {
      padding: 0.4rem 0.6rem;
      border-bottom: 1px solid #21262d;
    }
    tr:last-child td { border-bottom: none; }
    .badge {
      display: inline-block;
      border-radius: 4px;
      font-size: 0.75rem;
      padding: 0.15rem 0.5rem;
    }
    .open { background: #1a4731; color: #3fb950; }
    .s200 { background: #1a4731; color: #3fb950; }
    .s301, .s302, .s307, .s308 { background: #2d2700; color: #d29922; }
    .s401, .s403 { background: #2d1414; color: #f85149; }
    .empty { color: #484f58; font-size: 0.85rem; padding: 0.5rem 0; }
    .host-header {
      color: #e3b341;
      margin: 1rem 0 0.5rem;
      font-size: 0.95rem;
    }
  </style>
</head>
<body>
  <h1>&#9760; CTF Scanner</h1>
  <p class="subtitle">Nur fuer autorisierte CTF-Ziele und eigene Systeme</p>

  <div class="card">
    <label>Ziel (IP, Domain oder URL)</label>
    <input type="text" id="target" placeholder="z.B. 10.10.10.10 oder example.com" />

    <div class="row">
      <div class="group">
        <label>Profil</label>
        <select id="profile">
          <option value="quick">quick</option>
          <option value="balanced" selected>balanced</option>
          <option value="deep">deep</option>
        </select>
      </div>
      <div class="group">
        <label>Ports</label>
        <select id="ports_mode">
          <option value="top100">Top 100</option>
          <option value="top1000" selected>Top 1000</option>
          <option value="full">Full (-p-)</option>
        </select>
      </div>
    </div>

    <button id="scanBtn" onclick="startScan()">Scan starten</button>
    <div id="status"></div>
  </div>

  <div class="card" id="results">
    <div class="section-title">Port Scan</div>
    <div id="portResults"></div>

    <div class="section-title" style="margin-top:1.2rem">Directory Scan</div>
    <div id="dirResults"></div>
  </div>

<script>
let pollInterval = null;

function startScan() {
  const target = document.getElementById('target').value.trim();
  if (!target) { setStatus('Bitte ein Ziel eingeben.'); return; }

  const profile = document.getElementById('profile').value;
  const ports_mode = document.getElementById('ports_mode').value;

  document.getElementById('scanBtn').disabled = true;
  document.getElementById('results').style.display = 'none';
  setStatus('Scan laeuft...');

  fetch('/scan', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({target, profile, ports_mode})
  }).then(r => r.json()).then(data => {
    if (data.error) { setStatus('Fehler: ' + data.error); re(); return; }
    pollInterval = setInterval(pollStatus, 2000);
  }).catch(e => { setStatus('Fehler: ' + e); re(); });
}

function pollStatus() {
  fetch('/status').then(r => r.json()).then(data => {
    if (data.running) { setStatus('Scan laeuft... (Nmap kann etwas dauern)'); return; }
    clearInterval(pollInterval);
    if (data.error) { setStatus('Fehler: ' + data.error); re(); return; }
    setStatus('Scan abgeschlossen.');
    renderResults(data.result);
    re();
  });
}

function renderResults(result) {
  // Port results
  let portHtml = '';
  if (!result.hosts || result.hosts.length === 0) {
    portHtml = '<p class="empty">Keine Hosts gefunden.</p>';
  } else {
    for (const host of result.hosts) {
      portHtml += `<p class="host-header">Host: ${host.host} <span class="badge open">${host.state}</span></p>`;
      if (!host.open_ports || host.open_ports.length === 0) {
        portHtml += '<p class="empty">Keine offenen Ports gefunden.</p>';
      } else {
        portHtml += '<table><tr><th>Port</th><th>Proto</th><th>Service</th><th>Produkt/Version</th></tr>';
        for (const p of host.open_ports) {
          const pv = [p.product, p.version].filter(Boolean).join(' ') || '-';
          portHtml += `<tr><td>${p.port}</td><td>${p.protocol}</td><td>${p.service}</td><td>${pv}</td></tr>`;
        }
        portHtml += '</table>';
      }
    }
  }
  document.getElementById('portResults').innerHTML = portHtml;

  // Directory results
  let dirHtml = '';
  if (!result.dir_findings || result.dir_findings.length === 0) {
    dirHtml = '<p class="empty">Keine auffaelligen Pfade gefunden.</p>';
  } else {
    dirHtml = '<table><tr><th>URL</th><th>Status</th><th>Redirect</th></tr>';
    for (const f of result.dir_findings) {
      const cls = 's' + f.status_code;
      dirHtml += `<tr><td>${f.url}</td><td><span class="badge ${cls}">${f.status_code}</span></td><td>${f.location || '-'}</td></tr>`;
    }
    dirHtml += '</table>';
  }
  document.getElementById('dirResults').innerHTML = dirHtml;
  document.getElementById('results').style.display = 'block';
}

function setStatus(msg) { document.getElementById('status').textContent = msg; }
function re() { document.getElementById('scanBtn').disabled = false; }
</script>
</body>
</html>
"""


def _do_scan(target: str, profile: str, ports_mode: str) -> None:
    try:
        normalized = normalize_targets([target])
        nmap_result = run_nmap_scan(
            targets=[t.for_nmap for t in normalized],
            profiles=[profile],
            ports_mode=ports_mode,
            custom_ports=None,
            output_dir=Path("outputs"),
        )
        dir_targets = [t.for_http for t in normalized if t.for_http]
        dir_findings = run_directory_scan(dir_targets, timeout=5.0)

        write_markdown_report(
            output_dir=Path("outputs"),
            targets=normalized,
            profiles=[profile],
            ports_mode=ports_mode,
            custom_ports=None,
            nmap_result=nmap_result,
            dir_findings=dir_findings,
        )

        scan_state["result"] = {
            "hosts": [
                {
                    "host": h.host,
                    "state": h.state,
                    "open_ports": [
                        {
                            "port": p.port,
                            "protocol": p.protocol,
                            "service": p.service,
                            "product": p.product,
                            "version": p.version,
                        }
                        for p in h.open_ports
                    ],
                }
                for h in nmap_result.hosts
            ],
            "dir_findings": [
                {
                    "url": f.url,
                    "status_code": f.status_code,
                    "location": f.location,
                }
                for f in dir_findings
            ],
        }
        scan_state["error"] = None
    except Exception as exc:
        scan_state["error"] = str(exc)
        scan_state["result"] = None
    finally:
        scan_state["running"] = False


@app.route("/")
def index():
    return render_template_string(HTML)


@app.route("/scan", methods=["POST"])
def scan():
    if scan_state["running"]:
        return jsonify({"error": "Scan laeuft bereits."})

    data = request.get_json()
    target = (data.get("target") or "").strip()
    profile = data.get("profile", "balanced")
    ports_mode = data.get("ports_mode", "top1000")

    if not target:
        return jsonify({"error": "Kein Ziel angegeben."})

    scan_state["running"] = True
    scan_state["result"] = None
    scan_state["error"] = None

    thread = threading.Thread(target=_do_scan, args=(target, profile, ports_mode), daemon=True)
    thread.start()

    return jsonify({"ok": True})


@app.route("/status")
def status():
    return jsonify({
        "running": scan_state["running"],
        "result": scan_state["result"],
        "error": scan_state["error"],
    })


if __name__ == "__main__":
    print("CTF Scanner UI: http://127.0.0.1:5000")
    app.run(debug=False, host="127.0.0.1", port=5000)
