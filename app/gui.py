from __future__ import annotations

import streamlit as st

from app.scanner import ScannerError, WebScanner


st.set_page_config(page_title="Minimal Web Scanner", layout="centered")
st.title("Minimal Web Scanner")
st.caption("DNS, Portscan (80/443) und Directory Scan für eine Domain")

scanner = WebScanner(output_dir="outputs")

if "logs" not in st.session_state:
    st.session_state.logs = []


def append_log(message: str) -> None:
    st.session_state.logs.append(message)
    log_box.code("\n".join(st.session_state.logs) or "Noch keine Logs", language="text")


domain_input = st.text_input("Webadresse", placeholder="example.com")
start = st.button("Scan starten", type="primary")
log_box = st.empty()
log_box.code("\n".join(st.session_state.logs) or "Noch keine Logs", language="text")

if start:
    st.session_state.logs = []
    log_box.code("", language="text")

    if not domain_input.strip():
        st.error("Bitte eine Domain eingeben.")
    else:
        with st.spinner("Scan läuft..."):
            try:
                result = scanner.run_scan(domain_input, append_log)
                st.success("Scan abgeschlossen.")
                if result.md_report_path:
                    st.info(f"Markdown Report: {result.md_report_path}")
                if result.xml_report_path:
                    st.info(f"Nmap XML: {result.xml_report_path}")
                if result.errors:
                    st.warning("Es sind Fehler aufgetreten. Details im Log und Report.")
            except ScannerError as exc:
                st.error(str(exc))
            except Exception as exc:
                st.error(f"Unerwarteter Fehler: {exc}")
