#!/usr/bin/env python3
"""
pgcrypto PQC Scanner - FastAPI Dashboard Server
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
HOW TO RUN:
    python3 server.py

HOW TO USE FROM ANY DEVICE (phone / tablet / PC):
    1. Run the command above on your Mac.
    2. A QR code will appear in the terminal — scan it with your phone.
       OR type the Network URL shown into any browser on the same Wi-Fi.
    3. Paste any GitHub repo URL into the Scanner tab, hit Scan.
    4. Watch live logs. When done, the dashboard auto-updates with results.
"""

from contextlib import asynccontextmanager
import json
import os
import socket
import subprocess
import sys
import io
from pathlib import Path
from typing import Optional

import qrcode

from fastapi import FastAPI, HTTPException, BackgroundTasks, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

# ── Paths ───────────────────────────────────────────────────────────────────
BASE_DIR       = Path(__file__).parent
DASHBOARD_DIR  = BASE_DIR / "dashboard"
CBOM_FILE      = BASE_DIR / "cbom.json"
SCORE_FILE     = BASE_DIR / "readiness_score.json"
SCANNER_SCRIPT = BASE_DIR / "pgcrypto_scanner.py"
OUTPUT_DIR     = BASE_DIR / "output"
PDF_REPORT     = BASE_DIR / "pqc_audit_report.pdf"
PRESENTATION   = BASE_DIR / "presentation_script.pdf"
GUIDE_PDF      = BASE_DIR / "pgcrypto_scanner_guide.pdf"
SERVER_PORT    = 8765

# ── Scan state ───────────────────────────────────────────────────────────────
_scan_running: bool       = False
_scan_log: list[str]      = []
_scan_exit_code: Optional[int] = None

# ── Helpers ───────────────────────────────────────────────────────────────────
def load_json(path: Path):
    if not path.exists():
        return None
    with open(path, encoding="utf-8") as f:
        return json.load(f)

def get_local_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

def print_banner():
    ip  = get_local_ip()
    url = f"http://{ip}:{SERVER_PORT}"

    print("\n" + "═" * 60)
    print("  🔐  pgcrypto PQC Scanner  ·  Dashboard Server")
    print("═" * 60)
    print(f"  Local    →  http://127.0.0.1:{SERVER_PORT}")
    print(f"  Network  →  {url}   ← open on phone / any device")
    print("═" * 60)

    try:
        qr = qrcode.QRCode(border=1)
        qr.add_data(url)
        qr.make(fit=True)
        buf = io.StringIO()
        qr.print_ascii(out=buf, invert=True)
        print("\n  📱  Scan with your phone camera:\n")
        for line in buf.getvalue().splitlines():
            print("  " + line)
    except Exception:
        pass

    print(f"\n  ▶  Paste any GitHub URL in the Scanner tab to analyse it.")
    print("  Press Ctrl+C to stop.\n")

# ── Lifespan (startup/shutdown) ───────────────────────────────────────────────
@asynccontextmanager
async def lifespan(_app):
    print_banner()
    yield

# ── App ────────────────────────────────────────────────────────────────────────
app = FastAPI(title="pgcrypto PQC Scanner", version="2.0.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], allow_methods=["*"], allow_headers=["*"],
)

app.mount("/static", StaticFiles(directory=str(DASHBOARD_DIR)), name="static")

# ── Dashboard ─────────────────────────────────────────────────────────────────
@app.get("/", response_class=HTMLResponse)
async def root():
    return HTMLResponse(content=(DASHBOARD_DIR / "index.html").read_text(encoding="utf-8"))

# ── Data APIs ─────────────────────────────────────────────────────────────────
@app.get("/api/score")
async def get_score():
    data = load_json(SCORE_FILE)
    if data is None:
        raise HTTPException(404, "No scan results yet. Run a scan first.")
    return JSONResponse(content=data)

@app.get("/api/cbom")
async def get_cbom():
    data = load_json(CBOM_FILE)
    if data is None:
        raise HTTPException(404, "No CBOM data yet. Run a scan first.")
    return JSONResponse(content=data)

@app.get("/api/status")
async def get_status():
    return {
        "score_file":        SCORE_FILE.exists(),
        "cbom_file":         CBOM_FILE.exists(),
        "scanner_available": SCANNER_SCRIPT.exists(),
        "pdf_report":        PDF_REPORT.exists(),
        "presentation_pdf":  PRESENTATION.exists(),
        "guide_pdf":         GUIDE_PDF.exists(),
        "scan_running":      _scan_running,
        "output_files":      [f.name for f in OUTPUT_DIR.glob("*")] if OUTPUT_DIR.exists() else [],
    }

# ── Scan API ──────────────────────────────────────────────────────────────────
@app.post("/api/scan")
async def trigger_scan(
    background_tasks: BackgroundTasks,
    github_url:  Optional[str] = Query(None, alias="github_url"),
    local_path:  Optional[str] = Query(None, alias="local_path"),
    project_name: Optional[str] = Query(None, alias="project_name"),
):
    global _scan_running, _scan_log, _scan_exit_code

    if _scan_running:
        raise HTTPException(409, "A scan is already running. Please wait for it to finish.")

    if not github_url and not local_path:
        raise HTTPException(400, "Provide either github_url or local_path query parameter.")

    _scan_log = []
    _scan_exit_code = None
    _scan_running = True

    def run_scan():
        global _scan_running, _scan_log, _scan_exit_code
        try:
            cmd = [sys.executable, str(SCANNER_SCRIPT)]

            if github_url:
                cmd += ["--github", github_url]
            else:
                cmd += ["--config", local_path]

            if project_name:
                cmd += ["--name", project_name]

            # Always output to BASE_DIR so the dashboard picks it up
            cmd += ["--output", str(BASE_DIR)]

            _scan_log.append(f"▶ Starting scan…")
            _scan_log.append(f"  Command : {' '.join(cmd)}")
            _scan_log.append(f"  Target  : {github_url or local_path}")
            _scan_log.append("─" * 52)

            proc = subprocess.Popen(
                cmd,
                cwd=str(BASE_DIR),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )

            for line in proc.stdout:
                stripped = line.rstrip()
                if stripped:
                    _scan_log.append(stripped)

            proc.wait()
            _scan_exit_code = proc.returncode
            _scan_log.append("─" * 52)

            if proc.returncode == 0:
                _scan_log.append("✅ Scan completed successfully!")
                _scan_log.append("   Dashboard will auto-refresh with new results.")
            else:
                _scan_log.append(f"❌ Scan exited with code {proc.returncode}")

        except FileNotFoundError:
            _scan_log.append("❌ ERROR: pgcrypto_scanner.py not found.")
        except Exception as e:
            _scan_log.append(f"❌ ERROR: {e}")
        finally:
            _scan_running = False

    background_tasks.add_task(run_scan)
    return {
        "status":  "started",
        "message": "Scan started. Poll /api/scan/log to follow progress.",
        "target":  github_url or local_path,
    }

@app.get("/api/scan/log")
async def get_scan_log():
    return {
        "running":   _scan_running,
        "exit_code": _scan_exit_code,
        "log":       _scan_log,
    }

@app.delete("/api/scan/log")
async def clear_scan_log():
    global _scan_log, _scan_exit_code
    if _scan_running:
        raise HTTPException(409, "Cannot clear log while scan is running.")
    _scan_log = []
    _scan_exit_code = None
    return {"cleared": True}

# ── Reports ────────────────────────────────────────────────────────────────────
_ALLOWED_REPORTS = {
    "pqc_audit_report.pdf":       PDF_REPORT,
    "presentation_script.pdf":    PRESENTATION,
    "pgcrypto_scanner_guide.pdf": GUIDE_PDF,
    "cbom.json":                  CBOM_FILE,
    "readiness_score.json":       SCORE_FILE,
}

@app.get("/api/reports/{filename}")
async def download_report(filename: str):
    if filename not in _ALLOWED_REPORTS:
        raise HTTPException(404, "Unknown file.")
    path = _ALLOWED_REPORTS[filename]
    if not path.exists():
        raise HTTPException(404, f"{filename} has not been generated yet.")
    return FileResponse(str(path), filename=filename)

# ── Entry Point ────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "server:app",
        host="0.0.0.0",
        port=SERVER_PORT,
        reload=False,
        log_level="warning",
    )
