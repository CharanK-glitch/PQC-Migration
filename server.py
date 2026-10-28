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
import re
import socket
import subprocess
import sys
import io
import csv
import urllib.parse
import shutil
import tarfile
import threading
import textwrap
import uuid
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import qrcode

from fastapi import FastAPI, HTTPException, BackgroundTasks, Query, Depends, Security, File, Form, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, FileResponse, JSONResponse, Response
from fastapi.security import APIKeyHeader
from fastapi.staticfiles import StaticFiles

# ── Paths ───────────────────────────────────────────────────────────────────
BASE_DIR       = Path(__file__).parent
DASHBOARD_DIR  = BASE_DIR / "dashboard"
CBOM_FILE      = BASE_DIR / "cbom.json"
SCORE_FILE     = BASE_DIR / "readiness_score.json"
SCANNER_SCRIPT = BASE_DIR / "pgcrypto_scanner.py"
OUTPUT_DIR     = BASE_DIR / "output"
PRESENTATION   = BASE_DIR / "presentation_script.pdf"
GUIDE_PDF      = BASE_DIR / "pgcrypto_scanner_guide.pdf"
SERVER_PORT    = 8765
HISTORY_FILE   = BASE_DIR / "scan_history.json"
UPLOAD_DIR     = BASE_DIR / "uploads"
WEB_SCAN_FILE  = BASE_DIR / "web_scan_result.json"
ASSESSMENT_FILE = BASE_DIR / "assessment_result.json"
MULTI_SCAN_STATE_FILE = BASE_DIR / "multi_scan_state.json"

# ── Auth ─────────────────────────────────────────────────────────────────────
API_KEY = os.environ.get("PQC_API_KEY", "")
API_KEY_HEADER = APIKeyHeader(name="X-API-Key", auto_error=False)

def verify_api_key(key: str = Security(API_KEY_HEADER)):
    if API_KEY and key != API_KEY:
        raise HTTPException(401, "Invalid or missing API key")
    return key

# ── Input validation ─────────────────────────────────────────────────────────
_GITHUB_URL_RE = re.compile(r'^https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$')

def _validate_github_url(url: str) -> bool:
    return bool(_GITHUB_URL_RE.match(url))

def _validate_local_path(path: str) -> bool:
    p = Path(path)
    return p.exists() and p.is_dir()

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

def load_multi_scan_state() -> dict:
    try:
        state = load_json(MULTI_SCAN_STATE_FILE)
    except (OSError, json.JSONDecodeError):
        return {}
    if not isinstance(state, dict) or state.get("status") != "completed":
        return {}
    results = state.get("results")
    state.update(multi_scan_score_summary(results if isinstance(results, list) else []))
    return state

def save_multi_scan_state(state: dict):
    if not isinstance(state, dict) or state.get("status") != "completed":
        return
    temporary_path = MULTI_SCAN_STATE_FILE.with_suffix(".tmp")
    try:
        with open(temporary_path, "w", encoding="utf-8") as f:
            json.dump(state, f, indent=2)
        os.replace(temporary_path, MULTI_SCAN_STATE_FILE)
    except OSError as exc:
        print(f"Warning: could not persist completed multi-scan state: {exc}")

def clear_saved_multi_scan_state():
    try:
        MULTI_SCAN_STATE_FILE.unlink(missing_ok=True)
    except OSError as exc:
        print(f"Warning: could not clear previous multi-scan state: {exc}")

def multi_scan_score_summary(results: list) -> dict:
    completed = [
        result for result in results
        if result.get("status") == "completed" and isinstance(result.get("score"), (int, float))
    ]
    if not completed:
        return {"score": None, "pqr_score": None, "grade": None, "label": None}

    score = round(sum(result["score"] for result in completed) / len(completed))
    if score >= 95:
        grade, label = "A+", "PQC Ready"
    elif score >= 85:
        grade, label = "A", "Nearly PQC Ready"
    elif score >= 70:
        grade, label = "B", "Partial PQC Coverage"
    elif score >= 50:
        grade, label = "C", "Significant PQC Gaps"
    elif score >= 30:
        grade, label = "D", "Major PQC Deficiencies"
    else:
        grade, label = "F", "PQC Non-Compliant"
    return {"score": score, "pqr_score": score, "grade": grade, "label": label}

# ── Scan history persistence ─────────────────────────────────────────────────
_history_lock = threading.Lock()

def load_history() -> list:
    if not HISTORY_FILE.exists():
        return []
    try:
        with open(HISTORY_FILE, encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, list) else []
    except Exception:
        return []

def _write_history(entries: list):
    with open(HISTORY_FILE, "w", encoding="utf-8") as f:
        json.dump(entries, f, indent=2)

def add_history_entry(entry: dict) -> dict:
    with _history_lock:
        entries = load_history()
        entries.insert(0, entry)
        entries = entries[:100]
        _write_history(entries)
    return entry

def update_history_entry(scan_id: str, **fields):
    with _history_lock:
        entries = load_history()
        for e in entries:
            if e.get("id") == scan_id:
                e.update(fields)
                break
        _write_history(entries)

def delete_history_entry(scan_id: str) -> bool:
    with _history_lock:
        entries = load_history()
        remaining = [e for e in entries if e.get("id") != scan_id]
        if len(remaining) == len(entries):
            return False
        _write_history(remaining)
    return True

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
    if ip == "127.0.0.1":
        print("  Network  →  No LAN IPv4 address detected; remote devices cannot connect")
    else:
        print(f"  Network  →  {url}   ← open on phone / any device")
    print("═" * 60)

    if ip != "127.0.0.1":
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
    else:
        print("\n  Phone access needs a reachable LAN IPv4 address.\n")

    print(f"\n  ▶  Paste any GitHub URL in the Scanner tab to analyse it.")
    print("  Press Ctrl+C to stop.\n")

# ── Lifespan (startup/shutdown) ───────────────────────────────────────────────
@asynccontextmanager
async def lifespan(_app):
    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    print_banner()
    yield

# ── App ────────────────────────────────────────────────────────────────────────
app = FastAPI(title="pgcrypto PQC Scanner", version="2.0.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], allow_methods=["*"], allow_headers=["*"],
)

from fastapi.staticfiles import StaticFiles
from starlette.responses import FileResponse

class NoCacheStaticFiles(StaticFiles):
    async def get_response(self, path: str, scope):
        response = await super().get_response(path, scope)
        response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
        return response

app.mount("/static", NoCacheStaticFiles(directory=str(DASHBOARD_DIR)), name="static")

# ── Dashboard ─────────────────────────────────────────────────────────────────
@app.api_route("/", methods=["GET", "HEAD"], response_class=HTMLResponse)
async def root():
    return HTMLResponse(
        content=(DASHBOARD_DIR / "index.html").read_text(encoding="utf-8"),
        headers={
            "Cache-Control": "no-cache, no-store, must-revalidate, max-age=0",
            "Pragma": "no-cache",
            "Expires": "0",
        }
    )

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

@app.get("/api/scan/web/result")
async def get_web_scan_result():
    data = load_json(WEB_SCAN_FILE)
    if data is None:
        raise HTTPException(404, "No web scan result yet. Run a web scan first.")
    return JSONResponse(content=data)

@app.get("/api/assessment/result")
async def get_assessment_result():
    data = load_json(ASSESSMENT_FILE)
    if data is None:
        raise HTTPException(404, "No assessment result yet. Submit an assessment first.")
    return JSONResponse(content=data)

@app.get("/api/status")
async def get_status():
    return {
        "score_file":        SCORE_FILE.exists(),
        "cbom_file":         CBOM_FILE.exists(),
        "web_scan_file":     WEB_SCAN_FILE.exists(),
        "assessment_file":   ASSESSMENT_FILE.exists(),
        "scanner_available": SCANNER_SCRIPT.exists(),
        "pdf_report":        SCORE_FILE.exists(),
        "presentation_pdf":  PRESENTATION.exists(),
        "guide_pdf":         GUIDE_PDF.exists(),
        "scan_running":      _scan_running,
        "output_files":      [f.name for f in OUTPUT_DIR.glob("*")] if OUTPUT_DIR.exists() else [],
    }

# ── Scan API ──────────────────────────────────────────────────────────────────
def _build_scan_cmd(github_url, local_path, project_name, host=None, port=None, user=None,
                    timeout=None, verbose=False) -> list:
    cmd = [sys.executable, str(SCANNER_SCRIPT)]
    if github_url:
        cmd += ["--github", github_url]
    elif host:
        cmd += ["--host", host]
        if port:
            cmd += ["--port", str(port)]
        if user:
            cmd += ["--user", user]
    else:
        cmd += ["--config", local_path]
    if project_name:
        cmd += ["--name", project_name]
    if timeout:
        cmd += ["--timeout", str(timeout)]
    if verbose:
        cmd += ["--verbose"]
    cmd += ["--output", str(BASE_DIR)]
    return cmd

def _record_scan_result(scan_id: str, exit_code: Optional[int]):
    score = load_json(SCORE_FILE)
    if exit_code == 0 and score:
        update_history_entry(
            scan_id,
            status="completed",
            completed_at=datetime.now(timezone.utc).isoformat(),
            score=score.get("score"),
            grade=score.get("grade"),
            project_name=score.get("project_name"),
            findings=score.get("total_occurrences"),
        )
    else:
        update_history_entry(
            scan_id,
            status="failed",
            completed_at=datetime.now(timezone.utc).isoformat(),
            error=f"exit code {exit_code}" if exit_code else "no results generated",
        )

def _start_scan(background_tasks: BackgroundTasks, cmd: list, target: str, mode: str, project_name: Optional[str]) -> dict:
    global _scan_running, _scan_log, _scan_exit_code

    if _scan_running:
        raise HTTPException(409, "A scan is already running. Please wait for it to finish.")

    _scan_log = []
    _scan_exit_code = None
    _scan_running = True

    scan_id = f"scan_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:6]}"
    entry = add_history_entry({
        "id":         scan_id,
        "timestamp":  datetime.now(timezone.utc).isoformat(),
        "target":     target,
        "mode":       mode,
        "project_name": project_name or target,
        "status":     "running",
    })

    def run_scan():
        global _scan_running, _scan_log, _scan_exit_code
        try:
            _scan_log.append(f"▶ Starting scan…")
            _scan_log.append(f"  Command : {' '.join(cmd)}")
            _scan_log.append(f"  Target  : {target}")
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

            proc.wait(timeout=300)
            _scan_exit_code = proc.returncode
            _scan_log.append("─" * 52)

            if proc.returncode == 0:
                _scan_log.append("✅ Scan completed successfully!")
                _scan_log.append("   Dashboard will auto-refresh with new results.")
            else:
                _scan_log.append(f"❌ Scan exited with code {proc.returncode}")

        except subprocess.TimeoutExpired:
            proc.kill()
            _scan_exit_code = -1
            _scan_log.append("❌ ERROR: Scan timed out after 5 minutes.")
        except FileNotFoundError:
            _scan_log.append("❌ ERROR: pgcrypto_scanner.py not found.")
        except Exception as e:
            _scan_log.append(f"❌ ERROR: {e}")
        finally:
            _scan_running = False
            _record_scan_result(scan_id, _scan_exit_code)

    background_tasks.add_task(run_scan)
    return entry

@app.post("/api/scan")
async def trigger_scan(
    background_tasks: BackgroundTasks,
    github_url:  Optional[str] = Query(None, alias="github_url"),
    local_path:  Optional[str] = Query(None, alias="local_path"),
    project_name: Optional[str] = Query(None, alias="project_name"),
    host:        Optional[str] = Query(None, alias="host"),
    port:        Optional[int] = Query(None, alias="port"),
    user:        Optional[str] = Query(None, alias="user"),
    timeout:     Optional[int] = Query(None, alias="timeout"),
    verbose:     bool         = Query(False, alias="verbose"),
    api_key: str = Depends(verify_api_key),
):
    if not github_url and not local_path and not host:
        raise HTTPException(400, "Provide github_url, local_path, or host query parameter.")

    if github_url and not _validate_github_url(github_url):
        raise HTTPException(400, "Invalid GitHub URL format. Expected: https://github.com/owner/repo")

    if local_path and not _validate_local_path(local_path):
        raise HTTPException(400, "Invalid local path. Path must exist and be a directory.")

    target = github_url or local_path or host
    mode = "github" if github_url else ("database" if host else "local")
    cmd = _build_scan_cmd(github_url, local_path, project_name, host, port, user, timeout, verbose)
    entry = _start_scan(background_tasks, cmd, target, mode, project_name)
    return {
        "status":   "started",
        "message":  "Scan started. Poll /api/scan/log to follow progress.",
        "target":   target,
        "scan_id":  entry["id"],
    }

# ── Upload API ─────────────────────────────────────────────────────────────────
@app.post("/api/upload")
async def upload_codebase(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    project_name: Optional[str] = Form(None),
    api_key: str = Depends(verify_api_key),
):
    filename = file.filename or "upload.zip"
    lower = filename.lower()
    is_zip = lower.endswith(".zip")
    is_tar = lower.endswith(".tar.gz") or lower.endswith(".tgz") or lower.endswith(".tar")
    if not (is_zip or is_tar):
        raise HTTPException(400, "Only .zip or .tar.gz files are accepted.")

    scan_id = f"scan_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:6]}"
    upload_dir = UPLOAD_DIR / scan_id
    upload_dir.mkdir(parents=True, exist_ok=True)
    dest = upload_dir / filename

    try:
        with open(dest, "wb") as f:
            shutil.copyfileobj(file.file, f)
    except Exception as e:
        raise HTTPException(500, f"Failed to save upload: {e}")
    finally:
        await file.close()

    extract_dir = upload_dir / "extracted"
    extract_dir.mkdir(exist_ok=True)
    try:
        if is_zip:
            with zipfile.ZipFile(dest) as zf:
                zf.extractall(extract_dir)
        else:
            with tarfile.open(dest) as tf:
                tf.extractall(extract_dir)
    except Exception as e:
        raise HTTPException(400, f"Could not extract archive: {e}")

    scan_root = extract_dir
    children = [c for c in extract_dir.iterdir() if not c.name.startswith(".")]
    if len(children) == 1 and children[0].is_dir():
        scan_root = children[0]

    name = project_name or re.sub(r"\.(zip|tar\.gz|tgz|tar)$", "", filename, flags=re.I)
    cmd = _build_scan_cmd(None, str(scan_root), name)
    entry = _start_scan(background_tasks, cmd, f"upload:{filename}", "upload", name)
    update_history_entry(scan_id, upload_path=str(dest))
    return {
        "status":  "started",
        "message": "Upload received. Scan started on the uploaded codebase.",
        "target":  f"upload:{filename}",
        "scan_id": scan_id,
    }

# ── Scan history API ───────────────────────────────────────────────────────────
@app.get("/api/scan/history")
async def get_scan_history(api_key: str = Depends(verify_api_key)):
    return {"scans": load_history()}

@app.delete("/api/scan/history/{scan_id}")
async def delete_scan_history_entry(scan_id: str, api_key: str = Depends(verify_api_key)):
    if not delete_history_entry(scan_id):
        raise HTTPException(404, "Scan not found in history.")
    return {"deleted": True, "id": scan_id}

# ── Export API ─────────────────────────────────────────────────────────────────
def _generate_simple_pdf(score: dict) -> bytes:
    def esc(s) -> str:
        return str(s).replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")

    target = score.get("repo_url") or score.get("scan_target") or score.get("project_name") or "Unknown"
    target_lines = textwrap.wrap(str(target), width=78, break_long_words=True, break_on_hyphens=False) or ["Unknown"]
    timestamp = score.get("timestamp") or "Not recorded"
    lines = [
        ("Post-Quantum Cryptography (PQC) Technical Audit Report", 16, True),
        ("", 11, False),
        (f"Project: {score.get('project_name', 'Unknown')}", 12, False),
        ("Target Audit:", 11, False),
        *[(f"  {line}", 10, False) for line in target_lines],
        (f"Scan mode: {score.get('scan_mode', 'local')}", 10, False),
        (f"Scan timestamp: {timestamp}", 10, False),
        (f"Grade: {score.get('grade', '-')}   Score: {score.get('score', '-')}/100", 12, False),
        (f"Label: {score.get('label', '-')}", 12, False),
        (f"Report generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}", 10, False),
        ("", 11, False),
        ("Summary", 14, True),
    ]
    for key, label in [
        ("total_assets", "Total assets"),
        ("total_occurrences", "Occurrences"),
        ("vulnerable_assets", "Vulnerable"),
        ("safe_assets", "Safe"),
        ("critical_assets", "Critical"),
        ("pqc_assets", "PQC ready"),
    ]:
        lines.append((f"  {label}: {score.get(key, '-')}", 11, False))

    tl = score.get("timeline") or {}
    lines.append(("", 11, False))
    lines.append(("Migration Timeline", 14, True))
    lines.append((f"  Estimated effort: {tl.get('weeks', '-')} weeks ({tl.get('label', '-')})", 11, False))
    lines.append((f"  {tl.get('description', '')}", 11, False))

    roadmap = score.get("migration_roadmap") or []
    if roadmap:
        lines.append(("", 11, False))
        lines.append(("Top Migration Items", 14, True))
        for item in roadmap[:10]:
            lines.append((f"  [{item.get('priority', '-')}] {item.get('algorithm', '-')} -> {item.get('replacement', '-')}", 11, False))

    parts = ["BT"]
    first = True
    for text, size, bold in lines:
        font = "F2" if bold else "F1"
        if first:
            parts.append(f"/{font} {size} Tf 50 760 Td ({esc(text)}) Tj")
            first = False
        else:
            parts.append(f"/{font} {size} Tf 0 -18 Td ({esc(text)}) Tj")
    parts.append("ET")
    stream = "\n".join(parts).encode("latin-1", "replace")

    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R /F2 6 0 R >> >> >>",
        b"<< /Length " + str(len(stream)).encode() + b" >>\nstream\n" + stream + b"\nendstream",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>",
    ]

    out = io.BytesIO()
    out.write(b"%PDF-1.4\n")
    offsets = []
    for i, obj in enumerate(objects, start=1):
        offsets.append(out.tell())
        out.write(f"{i} 0 obj\n".encode() + obj + b"\nendobj\n")
    xref_pos = out.tell()
    out.write(f"xref\n0 {len(objects) + 1}\n".encode())
    out.write(b"0000000000 65535 f \n")
    for off in offsets:
        out.write(f"{off:010d} 00000 n \n".encode())
    out.write(f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref_pos}\n%%EOF".encode())
    return out.getvalue()

@app.get("/api/export/{format}")
async def export_results(format: str, api_key: str = Depends(verify_api_key)):
    fmt = format.lower()
    if fmt not in ("pdf", "json", "csv"):
        raise HTTPException(400, "Unsupported format. Use: pdf, json, csv.")

    if fmt == "json":
        data = load_json(SCORE_FILE)
        if data is None:
            raise HTTPException(404, "No scan results yet. Run a scan first.")
        return JSONResponse(content=data)

    if fmt == "csv":
        cbom = load_json(CBOM_FILE)
        if cbom is None:
            raise HTTPException(404, "No CBOM data yet. Run a scan first.")
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["Algorithm", "Primitive", "Family", "Risk", "File", "Snippet", "Replacement"])
        for comp in (cbom.get("components") or []):
            ap = (comp.get("cryptoProperties") or {}).get("algorithmProperties") or {}
            props = {p.get("name"): p.get("value") for p in (comp.get("properties") or [])}
            occs = []
            try:
                occs = json.loads(props.get("occurrences") or "[]")
            except Exception:
                pass
            risk = {0: "Critical", 1: "High", 2: "Safe"}.get(ap.get("risk", 0), "Medium")
            if not occs:
                w.writerow([comp.get("name", ""), ap.get("primitive", ""), ap.get("algorithmFamily", ""),
                            risk, "", "", props.get("replacement", "")])
            for o in occs:
                w.writerow([comp.get("name", ""), ap.get("primitive", ""), ap.get("algorithmFamily", ""),
                            risk, o.get("file", ""), o.get("snippet", ""), props.get("replacement", "")])
        return Response(
            content=buf.getvalue(),
            media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=pqc_export.csv"},
        )

    score = load_json(SCORE_FILE)
    if score is None:
        raise HTTPException(404, "No scan results yet. Run a scan first.")
    pdf_bytes = _generate_simple_pdf(score)
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": "attachment; filename=pqc_audit_report.pdf",
            "Cache-Control": "no-store",
        },
    )

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
    "presentation_script.pdf":    PRESENTATION,
    "pgcrypto_scanner_guide.pdf": GUIDE_PDF,
    "cbom.json":                  CBOM_FILE,
    "readiness_score.json":       SCORE_FILE,
}

@app.get("/api/reports/{filename}")
async def download_report(filename: str):
    if filename == "pqc_audit_report.pdf":
        score = load_json(SCORE_FILE)
        if score is None:
            raise HTTPException(404, "No scan results yet. Run a scan first.")
        return Response(
            content=_generate_simple_pdf(score),
            media_type="application/pdf",
            headers={
                "Content-Disposition": "attachment; filename=pqc_audit_report.pdf",
                "Cache-Control": "no-store",
            },
        )
    if filename not in _ALLOWED_REPORTS:
        raise HTTPException(404, "Unknown file.")
    path = _ALLOWED_REPORTS[filename]
    if not path.exists():
        raise HTTPException(404, f"{filename} has not been generated yet.")
    return FileResponse(str(path), filename=filename)

# ══════════════════════════════════════════════════════════════════════════════
# Multi-Repo Scan State
# ══════════════════════════════════════════════════════════════════════════════
_multi_scan_running: bool = False
_multi_scan_state: dict = load_multi_scan_state()

# ══════════════════════════════════════════════════════════════════════════════
# NIST PQC Algorithm Inventory
# ══════════════════════════════════════════════════════════════════════════════
NIST_PQC_INVENTORY = [
    {"name": "ML-KEM-512", "standard": "FIPS 203", "category": "Key Encapsulation", "status": "Finalized", "round": "4", "security_level": 1, "classical_equivalent": "AES-128", "quantum_resistant": True, "adoption": "Recommended", "description": "Module-Lattice-based Key Encapsulation Mechanism (formerly Kyber)"},
    {"name": "ML-KEM-768", "standard": "FIPS 203", "category": "Key Encapsulation", "status": "Finalized", "round": 4, "security_level": 2, "classical_equivalent": "AES-192", "quantum_resistant": True, "adoption": "Recommended", "description": "Module-Lattice-based KEM, most widely deployed variant"},
    {"name": "ML-KEM-1024", "standard": "FIPS 203", "category": "Key Encapsulation", "status": "Finalized", "round": 4, "security_level": 3, "classical_equivalent": "AES-256", "quantum_resistant": True, "adoption": "Recommended", "description": "Highest security level ML-KEM variant"},
    {"name": "ML-DSA-44", "standard": "FIPS 204", "category": "Digital Signature", "status": "Finalized", "round": 4, "security_level": 2, "classical_equivalent": "RSA-2048", "quantum_resistant": True, "adoption": "Recommended", "description": "Module-Lattice-based Digital Signature Algorithm (formerly Dilithium)"},
    {"name": "ML-DSA-65", "standard": "FIPS 204", "category": "Digital Signature", "status": "Finalized", "round": 4, "security_level": 3, "classical_equivalent": "RSA-3072", "quantum_resistant": True, "adoption": "Recommended", "description": "Balanced security/performance ML-DSA variant"},
    {"name": "ML-DSA-87", "standard": "FIPS 204", "category": "Digital Signature", "status": "Finalized", "round": 4, "security_level": 5, "classical_equivalent": "RSA-4096", "quantum_resistant": True, "adoption": "Recommended", "description": "Highest security level ML-DSA variant"},
    {"name": "SLH-DSA-SHA2-128s", "standard": "FIPS 205", "category": "Digital Signature", "status": "Finalized", "round": 4, "security_level": 1, "classical_equivalent": "SHA-256", "quantum_resistant": True, "adoption": "Optional", "description": "Stateless Hash-based Digital Signature (SPHINCS+), small signatures"},
    {"name": "SLH-DSA-SHA2-128f", "standard": "FIPS 205", "category": "Digital Signature", "status": "Finalized", "round": 4, "security_level": 1, "classical_equivalent": "SHA-256", "quantum_resistant": True, "adoption": "Optional", "description": "Fast variant of SLH-DSA with larger signatures"},
    {"name": "SLH-DSA-SHA2-192s", "standard": "FIPS 205", "category": "Digital Signature", "status": "Finalized", "round": 4, "security_level": 3, "classical_equivalent": "SHA-256", "quantum_resistant": True, "adoption": "Optional", "description": "Medium security SLH-DSA variant"},
    {"name": "SLH-DSA-SHA2-256s", "standard": "FIPS 205", "category": "Digital Signature", "status": "Finalized", "round": 4, "security_level": 5, "classical_equivalent": "SHA-256", "quantum_resistant": True, "adoption": "Optional", "description": "Highest security SLH-DSA variant"},
    {"name": "RSA-2048", "standard": "FIPS 186-5", "category": "Digital Signature", "status": "Deprecated", "round": 0, "security_level": 0, "classical_equivalent": "—", "quantum_resistant": False, "adoption": "Migrate Away", "description": "RSA signature, vulnerable to Shor's algorithm"},
    {"name": "RSA-3072", "standard": "FIPS 186-5", "category": "Digital Signature", "status": "Deprecated", "round": 0, "security_level": 0, "classical_equivalent": "—", "quantum_resistant": False, "adoption": "Migrate Away", "description": "RSA signature, vulnerable to Shor's algorithm"},
    {"name": "ECDSA-P256", "standard": "FIPS 186-5", "category": "Digital Signature", "status": "Deprecated", "round": 0, "security_level": 0, "classical_equivalent": "—", "quantum_resistant": False, "adoption": "Migrate Away", "description": "Elliptic curve signature, vulnerable to Shor's algorithm"},
    {"name": "ECDSA-P384", "standard": "FIPS 186-5", "category": "Digital Signature", "status": "Deprecated", "round": 0, "security_level": 0, "classical_equivalent": "—", "quantum_resistant": False, "adoption": "Migrate Away", "description": "Elliptic curve signature, vulnerable to Shor's algorithm"},
    {"name": "Diffie-Hellman-2048", "standard": "NIST SP 800-56A", "category": "Key Exchange", "status": "Deprecated", "round": 0, "security_level": 0, "classical_equivalent": "—", "quantum_resistant": False, "adoption": "Migrate Away", "description": "Finite-field DH key exchange, vulnerable to Shor's algorithm"},
    {"name": "ECDH-P256", "standard": "NIST SP 800-56A", "category": "Key Exchange", "status": "Deprecated", "round": 0, "security_level": 0, "classical_equivalent": "—", "quantum_resistant": False, "adoption": "Migrate Away", "description": "ECDH key exchange, vulnerable to Shor's algorithm"},
    {"name": "AES-128-GCM", "standard": "FIPS 197", "category": "Symmetric Encryption", "status": "Approved", "round": 0, "security_level": 1, "classical_equivalent": "—", "quantum_resistant": True, "adoption": "Safe", "description": "AES with 128-bit key, quantum-safe via Grover's algorithm halving"},
    {"name": "AES-256-GCM", "standard": "FIPS 197", "category": "Symmetric Encryption", "status": "Approved", "round": 0, "security_level": 3, "classical_equivalent": "—", "quantum_resistant": True, "adoption": "Safe", "description": "AES with 256-bit key, fully quantum-resistant"},
    {"name": "SHA-256", "standard": "FIPS 180-4", "category": "Hash Function", "status": "Approved", "round": 0, "security_level": 2, "classical_equivalent": "—", "quantum_resistant": True, "adoption": "Safe", "description": "SHA-2 family hash, quantum-safe"},
    {"name": "SHA-384", "standard": "FIPS 180-4", "category": "Hash Function", "status": "Approved", "round": 0, "security_level": 3, "classical_equivalent": "—", "quantum_resistant": True, "adoption": "Safe", "description": "SHA-2 family hash, quantum-safe"},
    {"name": "SHA-512", "standard": "FIPS 180-4", "category": "Hash Function", "status": "Approved", "round": 0, "security_level": 5, "classical_equivalent": "—", "quantum_resistant": True, "adoption": "Safe", "description": "SHA-2 family hash, quantum-safe"},
    {"name": "SHA3-256", "standard": "FIPS 202", "category": "Hash Function", "status": "Approved", "round": 0, "security_level": 2, "classical_equivalent": "—", "quantum_resistant": True, "adoption": "Safe", "description": "Keccak-based hash, quantum-safe"},
    {"name": "SHA3-512", "standard": "FIPS 202", "category": "Hash Function", "status": "Approved", "round": 0, "security_level": 5, "classical_equivalent": "—", "quantum_resistant": True, "adoption": "Safe", "description": "Keccak-based hash, quantum-safe"},
    {"name": "MD5", "standard": "—", "category": "Hash Function", "status": "Broken", "round": 0, "security_level": 0, "classical_equivalent": "—", "quantum_resistant": False, "adoption": "Remove Immediately", "description": "Cryptographically broken hash function"},
    {"name": "SHA-1", "standard": "—", "category": "Hash Function", "status": "Deprecated", "round": 0, "security_level": 0, "classical_equivalent": "—", "quantum_resistant": False, "adoption": "Remove Immediately", "description": "Deprecated hash function with known collisions"},
    {"name": "DES", "standard": "—", "category": "Symmetric Encryption", "status": "Broken", "round": 0, "security_level": 0, "classical_equivalent": "—", "quantum_resistant": False, "adoption": "Remove Immediately", "description": "56-bit key, brute-forceable"},
    {"name": "3DES", "standard": "NIST SP 800-67", "category": "Symmetric Encryption", "status": "Deprecated", "round": 0, "security_level": 0, "classical_equivalent": "—", "quantum_resistant": False, "adoption": "Migrate Away", "description": "Triple DES, deprecated by NIST"},
    {"name": "RC4", "standard": "—", "category": "Symmetric Encryption", "status": "Broken", "round": 0, "security_level": 0, "classical_equivalent": "—", "quantum_resistant": False, "adoption": "Remove Immediately", "description": "Stream cipher with known biases"},
]

# ══════════════════════════════════════════════════════════════════════════════
# Assessment Questionnaire
# ══════════════════════════════════════════════════════════════════════════════
ASSESSMENT_QUESTIONS = [
    {"id": "infra_tls_versions", "category": "Infrastructure", "question": "What TLS versions do you support?", "weight": 1.5, "answers": [
        {"text": "TLS 1.3 only", "score": 10}, {"text": "TLS 1.2 and 1.3", "score": 8},
        {"text": "TLS 1.0, 1.1, 1.2, 1.3", "score": 3}, {"text": "Below TLS 1.0", "score": 0}
    ]},
    {"id": "infra_cert_types", "category": "Infrastructure", "question": "What certificate types do you use?", "weight": 1.2, "answers": [
        {"text": "ECDSA P-256/P-384", "score": 8}, {"text": "RSA 2048/3072", "score": 6},
        {"text": "RSA 1024 or smaller", "score": 1}, {"text": "Self-signed certificates", "score": 0}
    ]},
    {"id": "infra_hsts", "category": "Infrastructure", "question": "Do you use HSTS (HTTP Strict Transport Security)?", "weight": 1.0, "answers": [
        {"text": "Yes, with includeSubDomains and preload", "score": 10}, {"text": "Yes, basic HSTS", "score": 7},
        {"text": "No", "score": 0}
    ]},
    {"id": "infra_cipher_suites", "category": "Infrastructure", "question": "What cipher suites are enabled?", "weight": 1.3, "answers": [
        {"text": "AEAD only (AES-GCM, ChaCha20-Poly1305)", "score": 10}, {"text": "AEAD + CBC with encrypt-then-MAC", "score": 6},
        {"text": "CBC mode ciphers", "score": 2}, {"text": "RC4, DES, or 3DES", "score": 0}
    ]},
    {"id": "infra_pfs", "category": "Infrastructure", "question": "Do you have Perfect Forward Secrecy?", "weight": 1.4, "answers": [
        {"text": "Yes, ECDHE with X25519/P-256", "score": 10}, {"text": "Yes, DHE with 2048-bit+", "score": 7},
        {"text": "No, static RSA key exchange", "score": 0}
    ]},
    {"id": "infra_cert_validity", "category": "Infrastructure", "question": "What is your certificate validity period?", "weight": 0.8, "answers": [
        {"text": "90 days or less (ACME/automated)", "score": 10}, {"text": "1 year", "score": 7},
        {"text": "2-3 years", "score": 4}, {"text": "More than 3 years", "score": 1}
    ]},
    {"id": "infra_cert_transparency", "category": "Infrastructure", "question": "Do you use Certificate Transparency?", "weight": 0.7, "answers": [
        {"text": "Yes, SCTs embedded and monitored", "score": 10}, {"text": "Yes, SCTs embedded", "score": 7},
        {"text": "No", "score": 2}
    ]},
    {"id": "infra_ocsp", "category": "Infrastructure", "question": "Do you use OCSP stapling?", "weight": 0.7, "answers": [
        {"text": "Yes, with must-staple", "score": 10}, {"text": "Yes, OCSP stapling enabled", "score": 7},
        {"text": "No", "score": 2}
    ]},
    {"id": "infra_tls_inspection", "category": "Infrastructure", "question": "How do you handle TLS inspection at the perimeter?", "weight": 0.8, "answers": [
        {"text": "TLS 1.3 with PQC hybrid (X25519+ML-KEM)", "score": 10}, {"text": "TLS 1.3 with ECDHE", "score": 7},
        {"text": "TLS 1.2 with RSA", "score": 2}, {"text": "No TLS inspection", "score": 5}
    ]},
    {"id": "infra_key_pinning", "category": "Infrastructure", "question": "Do you implement certificate or key pinning?", "weight": 0.6, "answers": [
        {"text": "Yes, HPKP or static pinning", "score": 8}, {"text": "Yes, for critical endpoints only", "score": 6},
        {"text": "No", "score": 2}
    ]},
    {"id": "app_crypto_libs", "category": "Application Layer", "question": "What cryptographic libraries do you use?", "weight": 1.5, "answers": [
        {"text": "Liboqs / OQS-OpenSSL with PQC", "score": 10}, {"text": "OpenSSL 3.x with provider model", "score": 7},
        {"text": "BoringSSL or similar modern library", "score": 6}, {"text": "Legacy OpenSSL 1.0.x or custom crypto", "score": 0}
    ]},
    {"id": "app_key_management", "category": "Application Layer", "question": "How do you handle key management?", "weight": 1.4, "answers": [
        {"text": "HSM-backed with automated rotation", "score": 10}, {"text": "KMS (AWS/GCP/Azure) with rotation", "score": 8},
        {"text": "Manual key management", "score": 3}, {"text": "Hardcoded keys in source", "score": 0}
    ]},
    {"id": "app_password_hash", "category": "Application Layer", "question": "What hash functions do you use for passwords?", "weight": 1.3, "answers": [
        {"text": "Argon2id", "score": 10}, {"text": "bcrypt with appropriate cost", "score": 8},
        {"text": "PBKDF2 with 100k+ iterations", "score": 6}, {"text": "MD5/SHA-1 (unsalted)", "score": 0}
    ]},
    {"id": "app_encryption_type", "category": "Application Layer", "question": "Do you use symmetric or asymmetric encryption more?", "weight": 0.8, "answers": [
        {"text": "Hybrid (asymmetric for key exchange, symmetric for data)", "score": 10}, {"text": "Mostly symmetric (AES-GCM)", "score": 7},
        {"text": "Mostly asymmetric (RSA/ECC)", "score": 4}, {"text": "No encryption", "score": 0}
    ]},
    {"id": "app_key_rotation", "category": "Application Layer", "question": "How often do you rotate keys?", "weight": 1.2, "answers": [
        {"text": "Automated, every 90 days or less", "score": 10}, {"text": "Automated, annually", "score": 7},
        {"text": "Manual, every 1-2 years", "score": 3}, {"text": "Never rotated", "score": 0}
    ]},
    {"id": "app_random_source", "category": "Application Layer", "question": "What random number generator do you use?", "weight": 1.0, "answers": [
        {"text": "CSPRNG (os.urandom, /dev/urandom, getrandom)", "score": 10}, {"text": "CSPRNG with proper seeding", "score": 8},
        {"text": "Standard PRNG (rand(), Math.random)", "score": 1}, {"text": "Custom RNG", "score": 0}
    ]},
    {"id": "app_side_channel", "category": "Application Layer", "question": "Do you implement side-channel protections?", "weight": 0.9, "answers": [
        {"text": "Constant-time implementations + blinding", "score": 10}, {"text": "Constant-time for critical operations", "score": 7},
        {"text": "No specific protections", "score": 2}
    ]},
    {"id": "app_crypto_agility", "category": "Application Layer", "question": "Do you support cryptographic agility (algorithm negotiation)?", "weight": 1.1, "answers": [
        {"text": "Full agility with versioned algorithms", "score": 10}, {"text": "Partial agility (TLS cipher suites)", "score": 6},
        {"text": "No agility, hardcoded algorithms", "score": 1}
    ]},
    {"id": "app_secure_enclave", "category": "Application Layer", "question": "Do you use hardware security modules or secure enclaves?", "weight": 0.7, "answers": [
        {"text": "HSM for all key operations", "score": 10}, {"text": "Secure enclave (SGX/TrustZone) for sensitive ops", "score": 7},
        {"text": "TPM-backed key storage", "score": 6}, {"text": "Software-only key storage", "score": 2}
    ]},
    {"id": "app_dependency_scan", "category": "Application Layer", "question": "Do you scan dependencies for vulnerable crypto?", "weight": 0.8, "answers": [
        {"text": "Automated in CI/CD with policy enforcement", "score": 10}, {"text": "Automated scanning, manual review", "score": 7},
        {"text": "Manual review only", "score": 3}, {"text": "No scanning", "score": 0}
    ]},
    {"id": "data_at_rest", "category": "Data Protection", "question": "How is data encrypted at rest?", "weight": 1.4, "answers": [
        {"text": "AES-256-GCM with per-tenant keys", "score": 10}, {"text": "AES-256-CBC with HMAC", "score": 7},
        {"text": "Database-level encryption (TDE)", "score": 5}, {"text": "No encryption at rest", "score": 0}
    ]},
    {"id": "data_in_transit", "category": "Data Protection", "question": "How is data encrypted in transit?", "weight": 1.3, "answers": [
        {"text": "TLS 1.3 with PQC hybrid key exchange", "score": 10}, {"text": "TLS 1.3 with ECDHE", "score": 8},
        {"text": "TLS 1.2 with RSA", "score": 2}, {"text": "No encryption in transit", "score": 0}
    ]},
    {"id": "data_db_encryption", "category": "Data Protection", "question": "Do you use database-level encryption?", "weight": 1.0, "answers": [
        {"text": "Column-level + TDE with separate key hierarchy", "score": 10}, {"text": "TDE only", "score": 6},
        {"text": "Application-level encryption only", "score": 5}, {"text": "No database encryption", "score": 0}
    ]},
    {"id": "data_backup_encryption", "category": "Data Protection", "question": "How are backups encrypted?", "weight": 1.1, "answers": [
        {"text": "AES-256 with keys stored in HSM/KMS", "score": 10}, {"text": "AES-256 with keys in separate KMS", "score": 8},
        {"text": "Encrypted with shared password", "score": 3}, {"text": "Unencrypted backups", "score": 0}
    ]},
    {"id": "data_key_separation", "category": "Data Protection", "question": "Do you separate encryption keys by environment?", "weight": 0.9, "answers": [
        {"text": "Full separation with distinct key hierarchies", "score": 10}, {"text": "Separate keys per environment", "score": 7},
        {"text": "Shared keys across environments", "score": 1}
    ]},
    {"id": "data_data_classification", "category": "Data Protection", "question": "Do you classify data by sensitivity for crypto controls?", "weight": 0.8, "answers": [
        {"text": "Full classification with tiered encryption", "score": 10}, {"text": "Partial classification", "score": 5},
        {"text": "No classification", "score": 1}
    ]},
    {"id": "data_tokenization", "category": "Data Protection", "question": "Do you use tokenization for sensitive data?", "weight": 0.7, "answers": [
        {"text": "Full tokenization with vault", "score": 10}, {"text": "Partial tokenization for PII", "score": 7},
        {"text": "No tokenization", "score": 2}
    ]},
    {"id": "data_retention", "category": "Data Protection", "question": "Do you have crypto-aware data retention policies?", "weight": 0.6, "answers": [
        {"text": "Automated crypto-shredding on expiry", "score": 10}, {"text": "Manual deletion with audit trail", "score": 6},
        {"text": "No retention policy", "score": 1}
    ]},
    {"id": "gov_compliance", "category": "Compliance & Governance", "question": "Are you subject to any compliance requirements?", "weight": 1.0, "answers": [
        {"text": "FIPS 140-3 / Common Criteria", "score": 10}, {"text": "PCI-DSS, HIPAA, or SOC 2", "score": 8},
        {"text": "GDPR only", "score": 5}, {"text": "No compliance requirements", "score": 3}
    ]},
    {"id": "gov_crypto_inventory", "category": "Compliance & Governance", "question": "Do you have a crypto inventory?", "weight": 1.3, "answers": [
        {"text": "Automated CBOM with continuous updates", "score": 10}, {"text": "Manual inventory, updated quarterly", "score": 6},
        {"text": "Partial inventory", "score": 3}, {"text": "No inventory", "score": 0}
    ]},
    {"id": "gov_asset_tracking", "category": "Compliance & Governance", "question": "How do you track cryptographic assets?", "weight": 1.1, "answers": [
        {"text": "Automated scanning integrated in CI/CD", "score": 10}, {"text": "Automated scanning, manual review", "score": 7},
        {"text": "Manual tracking in spreadsheets", "score": 2}, {"text": "No tracking", "score": 0}
    ]},
    {"id": "gov_migration_plan", "category": "Compliance & Governance", "question": "Do you have a migration plan for PQC?", "weight": 1.5, "answers": [
        {"text": "Detailed plan with timeline and milestones", "score": 10}, {"text": "High-level plan, not yet detailed", "score": 6},
        {"text": "Aware of need, no plan yet", "score": 2}, {"text": "No awareness or plan", "score": 0}
    ]},
    {"id": "gov_risk_assessment", "category": "Compliance & Governance", "question": "Have you performed a quantum risk assessment?", "weight": 1.0, "answers": [
        {"text": "Full assessment with harvest-now-decrypt-later analysis", "score": 10}, {"text": "Basic assessment completed", "score": 6},
        {"text": "In progress", "score": 3}, {"text": "Not started", "score": 0}
    ]},
    {"id": "gov_training", "category": "Compliance & Governance", "question": "Is your team trained on PQC migration?", "weight": 0.7, "answers": [
        {"text": "Certified training + hands-on PQC implementation", "score": 10}, {"text": "Workshops and self-study", "score": 6},
        {"text": "Awareness only", "score": 3}, {"text": "No training", "score": 0}
    ]},
    {"id": "gov_vendor_management", "category": "Compliance & Governance", "question": "Do you assess vendors for PQC readiness?", "weight": 0.8, "answers": [
        {"text": "Formal PQC readiness assessment for all vendors", "score": 10}, {"text": "Assessment for critical vendors only", "score": 6},
        {"text": "Informal awareness", "score": 2}, {"text": "No vendor assessment", "score": 0}
    ]},
]

# ══════════════════════════════════════════════════════════════════════════════
# Web Scan Analysis
# ══════════════════════════════════════════════════════════════════════════════
_WEB_CRYPTO_LIBS = {
    "crypto-js": {"name": "CryptoJS", "quantum_safe": False, "risk": "high"},
    "sjcl": {"name": "Stanford JavaScript Crypto Library", "quantum_safe": False, "risk": "high"},
    "forge": {"name": "node-forge", "quantum_safe": False, "risk": "medium"},
    "tweetnacl": {"name": "TweetNaCl", "quantum_safe": False, "risk": "medium"},
    "libsodium": {"name": "libsodium.js", "quantum_safe": False, "risk": "medium"},
    "bcrypt": {"name": "bcrypt.js", "quantum_safe": True, "risk": "low"},
    "argon2": {"name": "argon2-browser", "quantum_safe": True, "risk": "low"},
    "webcrypto": {"name": "Web Crypto API", "quantum_safe": True, "risk": "low"},
    "subtlecrypto": {"name": "Web Crypto SubtleCrypto", "quantum_safe": True, "risk": "low"},
    "elliptic": {"name": "elliptic.js", "quantum_safe": False, "risk": "high"},
    "jsrsasign": {"name": "jsrsasign", "quantum_safe": False, "risk": "high"},
    "node-rsa": {"name": "node-rsa", "quantum_safe": False, "risk": "high"},
    "crypto-browserify": {"name": "crypto-browserify", "quantum_safe": False, "risk": "medium"},
    "aes-js": {"name": "aes-js", "quantum_safe": True, "risk": "low"},
    "sha.js": {"name": "sha.js", "quantum_safe": True, "risk": "low"},
    "md5": {"name": "MD5.js", "quantum_safe": False, "risk": "critical"},
    "sha1": {"name": "SHA-1.js", "quantum_safe": False, "risk": "high"},
}

_SECURITY_HEADERS = {
    "strict-transport-security": {"name": "HSTS", "weight": 10, "description": "HTTP Strict Transport Security"},
    "content-security-policy": {"name": "CSP", "weight": 8, "description": "Content Security Policy"},
    "x-frame-options": {"name": "X-Frame-Options", "weight": 6, "description": "Clickjacking protection"},
    "x-content-type-options": {"name": "X-Content-Type-Options", "weight": 6, "description": "MIME sniffing protection"},
    "referrer-policy": {"name": "Referrer-Policy", "weight": 4, "description": "Referrer information control"},
    "permissions-policy": {"name": "Permissions-Policy", "weight": 4, "description": "Feature permissions control"},
    "cross-origin-opener-policy": {"name": "COOP", "weight": 3, "description": "Cross-Origin Opener Policy"},
    "cross-origin-resource-policy": {"name": "CORP", "weight": 3, "description": "Cross-Origin Resource Policy"},
}


def _analyze_website(url: str) -> dict:
    """Analyze a website for cryptographic readiness."""
    import ssl
    import urllib.request
    import urllib.error
    from html.parser import HTMLParser

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    result = {
        "url": url,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "tls": {},
        "headers": {},
        "crypto_libs": [],
        "forms": [],
        "cookies": [],
        "score": 0,
        "grade": "F",
        "label": "Unknown",
        "recommendations": [],
    }

    # ── TLS Analysis ──────────────────────────────────────────────────
    tls_score = 0
    tls_max = 30
    try:
        parsed = urllib.parse.urlparse(url)
        hostname = parsed.hostname
        port = parsed.port or 443

        ctx = ssl.create_default_context()
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED

        with socket.create_connection((hostname, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                version = ssock.version()

                result["tls"]["version"] = version
                result["tls"]["cipher"] = cipher[0] if cipher else "Unknown"
                result["tls"]["protocol"] = cipher[1] if cipher else "Unknown"
                result["tls"]["bits"] = cipher[2] if cipher else 0

                if cert:
                    subject = dict(x[0] for x in cert.get("subject", []))
                    issuer = dict(x[0] for x in cert.get("issuer", []))
                    result["tls"]["subject"] = subject.get("commonName", "Unknown")
                    result["tls"]["issuer"] = issuer.get("organizationName", "Unknown")
                    result["tls"]["not_before"] = cert.get("notBefore", "")
                    result["tls"]["not_after"] = cert.get("notAfter", "")

                    # Check cert type
                    cert_type = "RSA"
                    if "ec" in str(cert.get("subject", [])).lower() or "EC" in str(cert):
                        cert_type = "ECDSA"
                    result["tls"]["cert_type"] = cert_type

                # TLS version scoring
                if version == "TLSv1.3":
                    tls_score += 15
                    result["tls"]["version_rating"] = "excellent"
                elif version == "TLSv1.2":
                    tls_score += 10
                    result["tls"]["version_rating"] = "good"
                else:
                    tls_score += 2
                    result["tls"]["version_rating"] = "poor"
                    result["recommendations"].append("Upgrade to TLS 1.3 immediately")

                # Cipher scoring
                cipher_name = result["tls"]["cipher"]
                if "AES" in cipher_name and "GCM" in cipher_name:
                    tls_score += 10
                elif "CHACHA20" in cipher_name:
                    tls_score += 10
                elif "CBC" in cipher_name:
                    tls_score += 4
                    result["recommendations"].append("Replace CBC mode ciphers with AEAD (AES-GCM or ChaCha20-Poly1305)")
                else:
                    tls_score += 1
                    result["recommendations"].append("Use modern AEAD cipher suites")

                # Key exchange
                if "ECDHE" in cipher_name or "DHE" in cipher_name:
                    tls_score += 5
                else:
                    result["recommendations"].append("Enable Perfect Forward Secrecy with ECDHE key exchange")

    except Exception as e:
        result["tls"]["error"] = str(e)
        result["recommendations"].append(f"TLS analysis failed: {e}")

    result["tls"]["score"] = tls_score
    result["tls"]["max_score"] = tls_max

    # ── HTTP Headers Analysis ─────────────────────────────────────────
    header_score = 0
    header_max = 25
    try:
        req = urllib.request.Request(url, method="HEAD")
        req.add_header("User-Agent", "PQC-Scanner/2.0")
        with urllib.request.urlopen(req, timeout=10) as resp:
            raw_headers = {}
            for key, value in resp.headers.items():
                raw_headers[key.lower()] = value
            result["headers"]["raw"] = raw_headers

            for header_name, info in _SECURITY_HEADERS.items():
                if header_name in raw_headers:
                    result["headers"][header_name] = {
                        "present": True,
                        "value": raw_headers[header_name],
                        "name": info["name"],
                    }
                    header_score += info["weight"]
                else:
                    result["headers"][header_name] = {
                        "present": False,
                        "name": info["name"],
                        "description": info["description"],
                    }
                    result["recommendations"].append(f"Add {info['name']} header: {info['description']}")

    except Exception as e:
        result["headers"]["error"] = str(e)

    result["headers"]["score"] = header_score
    result["headers"]["max_score"] = header_max

    # ── HTML Content Analysis ─────────────────────────────────────────
    content_score = 0
    content_max = 25
    try:
        req = urllib.request.Request(url)
        req.add_header("User-Agent", "Mozilla/5.0 PQC-Scanner/2.0")
        with urllib.request.urlopen(req, timeout=10) as resp:
            html = resp.read().decode("utf-8", errors="ignore")
            result["headers"]["final_url"] = resp.geturl()

            # Detect crypto libraries
            for pattern, info in _WEB_CRYPTO_LIBS.items():
                if pattern.lower() in html.lower():
                    result["crypto_libs"].append({
                        "name": info["name"],
                        "pattern": pattern,
                        "quantum_safe": info["quantum_safe"],
                        "risk": info["risk"],
                    })
                    if not info["quantum_safe"]:
                        content_score -= 3
                        result["recommendations"].append(
                            f"Replace {info['name']} with a quantum-resistant alternative"
                        )
                    else:
                        content_score += 2

            # Analyze forms
            class FormParser(HTMLParser):
                def __init__(self):
                    super().__init__()
                    self.forms = []
                    self._in_form = False
                    self._current_form = {}

                def handle_starttag(self, tag, attrs):
                    attrs_dict = dict(attrs)
                    if tag == "form":
                        self._in_form = True
                        self._current_form = {
                            "action": attrs_dict.get("action", ""),
                            "method": attrs_dict.get("method", "get").upper(),
                            "has_password": False,
                            "has_encryption": False,
                        }
                    elif self._in_form and tag == "input":
                        input_type = attrs_dict.get("type", "text").lower()
                        if input_type == "password":
                            self._current_form["has_password"] = True

                def handle_endtag(self, tag):
                    if tag == "form" and self._in_form:
                        self.forms.append(self._current_form)
                        self._in_form = False

            parser = FormParser()
            parser.feed(html)
            result["forms"] = parser.forms

            for form in parser.forms:
                if form["has_password"]:
                    action = form["action"]
                    if action.startswith("https://") or (not action.startswith("http://") and url.startswith("https://")):
                        content_score += 3
                    else:
                        content_score -= 5
                        result["recommendations"].append("Ensure all password forms submit over HTTPS")

            # Check for mixed content indicators
            if "http://" in html and "https://" in html:
                content_score -= 3
                result["recommendations"].append("Eliminate mixed content (HTTP resources on HTTPS pages)")

    except Exception as e:
        result["content_error"] = str(e)

    result["content_score"] = max(0, content_score)
    result["content_max_score"] = content_max

    # ── Cookie Analysis ───────────────────────────────────────────────
    cookie_score = 0
    cookie_max = 20
    try:
        req = urllib.request.Request(url, method="HEAD")
        req.add_header("User-Agent", "PQC-Scanner/2.0")
        with urllib.request.urlopen(req, timeout=10) as resp:
            cookies = resp.headers.get_all("Set-Cookie") or []
            for cookie_str in cookies:
                cookie_info = {"raw": cookie_str.split(";")[0], "flags": []}
                flags = [f.strip().lower() for f in cookie_str.split(";")[1:]]
                if "secure" in flags:
                    cookie_info["flags"].append("Secure")
                    cookie_score += 3
                else:
                    result["recommendations"].append("Set Secure flag on all cookies")
                if "httponly" in flags:
                    cookie_info["flags"].append("HttpOnly")
                    cookie_score += 3
                else:
                    result["recommendations"].append("Set HttpOnly flag on session cookies")
                if "samesite" in " ".join(flags):
                    cookie_info["flags"].append("SameSite")
                    cookie_score += 2
                result["cookies"].append(cookie_info)
    except Exception:
        pass

    result["cookie_score"] = cookie_score
    result["cookie_max_score"] = cookie_max

    # ── Calculate Total Score ─────────────────────────────────────────
    total_score = tls_score + header_score + max(0, content_score) + cookie_score
    total_max = tls_max + header_max + content_max + cookie_max
    pqr_score = round((total_score / total_max) * 100) if total_max > 0 else 0

    # Bonus for TLS 1.3 (quantum-resistant key exchange)
    if result["tls"].get("version") == "TLSv1.3":
        pqr_score = min(100, pqr_score + 10)

    result["score"] = pqr_score
    if pqr_score >= 80:
        result["grade"] = "A"
        result["label"] = "PQC Ready"
    elif pqr_score >= 60:
        result["grade"] = "B"
        result["label"] = "Partially Ready"
    elif pqr_score >= 40:
        result["grade"] = "C"
        result["label"] = "Needs Improvement"
    elif pqr_score >= 20:
        result["grade"] = "D"
        result["label"] = "At Risk"
    else:
        result["grade"] = "F"
        result["label"] = "Critical Risk"

    return result


# ══════════════════════════════════════════════════════════════════════════════
# Assessment Scoring
# ══════════════════════════════════════════════════════════════════════════════
def _calculate_assessment(answers: dict) -> dict:
    """Calculate PQR score from questionnaire answers."""
    category_scores = {}
    category_max = {}
    total_score = 0
    total_weight = 0
    answered = 0

    for q in ASSESSMENT_QUESTIONS:
        qid = q["id"]
        cat = q["category"]
        weight = q["weight"]

        if cat not in category_scores:
            category_scores[cat] = 0
            category_max[cat] = 0

        category_max[cat] += weight * 10
        total_weight += weight

        answer_idx = answers.get(qid)
        if answer_idx is not None:
            try:
                idx = int(answer_idx)
                if 0 <= idx < len(q["answers"]):
                    answer = q["answers"][idx]
                    category_scores[cat] += answer["score"] * weight
                    total_score += answer["score"] * weight
                    answered += 1
            except (ValueError, TypeError):
                pass
        else:
            pass

    pqr_score = round((total_score / (total_weight * 10)) * 100) if total_weight > 0 else 0

    # Partial score: only considers answered questions
    answered_weight = 0
    for q in ASSESSMENT_QUESTIONS:
        qid = q["id"]
        answer_idx = answers.get(qid)
        if answer_idx is not None:
            try:
                idx = int(answer_idx)
                if 0 <= idx < len(q["answers"]):
                    answered_weight += q["weight"]
            except (ValueError, TypeError):
                pass

    partial_score = round((total_score / (answered_weight * 10)) * 100) if answered_weight > 0 else 0

    category_results = {}
    for cat in category_max:
        cat_pct = round((category_scores[cat] / category_max[cat]) * 100) if category_max[cat] > 0 else 0
        category_results[cat] = {
            "score": round(category_scores[cat], 1),
            "max_score": round(category_max[cat], 1),
            "percentage": cat_pct,
        }

    if pqr_score >= 80:
        grade, label = "A", "PQC Ready"
    elif pqr_score >= 60:
        grade, label = "B", "Partially Ready"
    elif pqr_score >= 40:
        grade, label = "C", "Needs Improvement"
    elif pqr_score >= 20:
        grade, label = "D", "At Risk"
    else:
        grade, label = "F", "Critical Risk"

    return {
        "score": pqr_score,
        "partial_score": partial_score,
        "grade": grade,
        "label": label,
        "answered": answered,
        "total_questions": len(ASSESSMENT_QUESTIONS),
        "categories": category_results,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


# ══════════════════════════════════════════════════════════════════════════════
# Risk Calculator
# ══════════════════════════════════════════════════════════════════════════════
def _calculate_risk(params: dict) -> dict:
    """Calculate detailed risk score with weights and formulas."""
    findings = params.get("findings", [])
    weights = params.get("weights", {})

    default_weights = {
        "critical": 10.0,
        "high": 5.0,
        "medium": 2.0,
        "low": 0.5,
    }
    w = {**default_weights, **weights}

    total_risk = 0.0
    weighted_findings = []

    for f in findings:
        severity = f.get("severity", "medium").lower()
        occurrences = int(f.get("occurrences", 1))
        weight = w.get(severity, 2.0)
        risk = weight * occurrences
        total_risk += risk
        weighted_findings.append({
            "algorithm": f.get("algorithm", "Unknown"),
            "severity": severity,
            "occurrences": occurrences,
            "weight": weight,
            "risk_contribution": round(risk, 2),
        })

    # Normalize to 0-100 scale
    max_risk = 1000.0
    normalized = min(100, (total_risk / max_risk) * 100)

    if normalized >= 75:
        level, color = "Critical", "#ef4444"
    elif normalized >= 50:
        level, color = "High", "#f59e0b"
    elif normalized >= 25:
        level, color = "Medium", "#f97316"
    else:
        level, color = "Low", "#10b981"

    return {
        "total_risk_score": round(normalized, 1),
        "raw_risk": round(total_risk, 2),
        "risk_level": level,
        "risk_color": color,
        "formula": "risk = sum(severity_weight * occurrences), normalized to 0-100",
        "weights_used": w,
        "findings_count": len(findings),
        "weighted_findings": sorted(weighted_findings, key=lambda x: -x["risk_contribution"])[:20],
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


# ══════════════════════════════════════════════════════════════════════════════
# New API Endpoints
# ══════════════════════════════════════════════════════════════════════════════

@app.post("/api/scan/multi")
async def trigger_multi_scan(
    background_tasks: BackgroundTasks,
    body: dict,
    api_key: str = Depends(verify_api_key),
):
    global _multi_scan_running, _multi_scan_state

    if _multi_scan_running:
        raise HTTPException(409, "A multi-repo scan is already running.")

    urls = body.get("urls", [])
    if not urls or not isinstance(urls, list):
        raise HTTPException(400, "Provide a non-empty 'urls' array.")
    if len(urls) > 20:
        raise HTTPException(400, "Maximum 20 URLs per multi-scan.")

    valid_urls = []
    for u in urls:
        u = str(u).strip()
        if _validate_github_url(u):
            valid_urls.append(u)
        else:
            raise HTTPException(400, f"Invalid GitHub URL: {u}")

    scan_id = f"multi_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:6]}"
    clear_saved_multi_scan_state()
    _multi_scan_running = True
    _multi_scan_state = {
        "scan_id": scan_id,
        "status": "running",
        "total": len(valid_urls),
        "completed": 0,
        "urls": valid_urls,
        "current_url": None,
        "current_index": 0,
        "results": [],
        **multi_scan_score_summary([]),
        "started_at": datetime.now(timezone.utc).isoformat(),
        "completed_at": None,
    }

    def run_multi():
        global _multi_scan_running, _multi_scan_state
        try:
            for i, url in enumerate(valid_urls):
                _multi_scan_state["current_url"] = url
                _multi_scan_state["current_index"] = i + 1
                _multi_scan_state["status"] = "running"

                repo_name = url.rstrip("/").split("/")[-1].replace(".git", "")
                cmd = _build_scan_cmd(url, None, repo_name)

                repo_output = BASE_DIR / "output" / f"multi_{repo_name}"
                repo_output.mkdir(parents=True, exist_ok=True)
                try:
                    proc = subprocess.Popen(
                        cmd + ["--output", str(repo_output)],
                        cwd=str(BASE_DIR),
                        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                        text=True, bufsize=1,
                    )
                    proc.wait(timeout=600)

                    score = load_json(repo_output / "readiness_score.json")
                    cbom = load_json(repo_output / "cbom.json")
                    if proc.returncode == 0 and score:
                        _multi_scan_state["results"].append({
                            "url": url,
                            "repo_name": repo_name,
                            "status": "completed",
                            "score": score.get("score", 0),
                            "grade": score.get("grade", "—"),
                            "label": score.get("label", "—"),
                            "total_assets": score.get("total_assets", 0),
                            "vulnerable_assets": score.get("vulnerable_assets", 0),
                            "critical_assets": score.get("critical_assets", 0),
                            "total_occurrences": score.get("total_occurrences", 0),
                            "findings": len(cbom.get("components", [])) if cbom else 0,
                        })
                    else:
                        _multi_scan_state["results"].append({
                            "url": url,
                            "repo_name": repo_name,
                            "status": "failed",
                            "error": f"exit code {proc.returncode}",
                        })
                except subprocess.TimeoutExpired:
                    proc.kill()
                    _multi_scan_state["results"].append({
                        "url": url, "repo_name": repo_name,
                        "status": "failed", "error": "timeout",
                    })
                except Exception as e:
                    _multi_scan_state["results"].append({
                        "url": url, "repo_name": repo_name,
                        "status": "failed", "error": str(e),
                    })

                _multi_scan_state["completed"] = i + 1
                _multi_scan_state.update(multi_scan_score_summary(_multi_scan_state["results"]))

            _multi_scan_state["status"] = "completed"
            _multi_scan_state["completed_at"] = datetime.now(timezone.utc).isoformat()

            # Record in history
            completed = [r for r in _multi_scan_state["results"] if r["status"] == "completed"]
            if completed:
                add_history_entry({
                    "id": scan_id,
                    "timestamp": _multi_scan_state["started_at"],
                    "target": f"multi:{len(valid_urls)} repos",
                    "mode": "multi",
                    "project_name": f"Multi-Repo Scan ({len(valid_urls)} repos)",
                    "status": "completed",
                    "score": _multi_scan_state["score"],
                    "grade": _multi_scan_state["grade"],
                    "label": _multi_scan_state["label"],
                    "findings": sum(r.get("total_occurrences", 0) for r in completed),
                })

        finally:
            if _multi_scan_state.get("status") == "completed":
                save_multi_scan_state(_multi_scan_state)
            _multi_scan_running = False

    background_tasks.add_task(run_multi)
    return {
        "status": "started",
        "scan_id": scan_id,
        "total": len(valid_urls),
        "message": "Multi-repo scan started. Poll /api/scan/multi/status for progress.",
    }


@app.get("/api/scan/multi/status")
async def get_multi_scan_status():
    return _multi_scan_state if _multi_scan_state else {"status": "idle"}


@app.post("/api/scan/web")
async def scan_website(body: dict, api_key: str = Depends(verify_api_key)):
    url = body.get("url", "").strip()
    if not url:
        raise HTTPException(400, "Provide a 'url' field.")
    if not re.match(r'^[a-zA-Z0-9][-a-zA-Z0-9.]*\.[a-zA-Z]{2,}', url.replace("https://", "").replace("http://", "").split("/")[0]):
        raise HTTPException(400, "Invalid URL format.")
    result = _analyze_website(url)
    with open(WEB_SCAN_FILE, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2)
    return result


@app.post("/api/assessment")
async def submit_assessment(body: dict, api_key: str = Depends(verify_api_key)):
    answers = body.get("answers", {})
    if not answers:
        raise HTTPException(400, "Provide 'answers' object mapping question IDs to answer indices.")
    result = _calculate_assessment(answers)
    with open(ASSESSMENT_FILE, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2)
    return result


@app.get("/api/assessment/questions")
async def get_assessment_questions():
    return {"questions": ASSESSMENT_QUESTIONS, "total": len(ASSESSMENT_QUESTIONS)}


@app.get("/api/crypto/inventory")
async def get_crypto_inventory():
    return {
        "algorithms": NIST_PQC_INVENTORY,
        "total": len(NIST_PQC_INVENTORY),
        "quantum_resistant": sum(1 for a in NIST_PQC_INVENTORY if a["quantum_resistant"]),
        "deprecated": sum(1 for a in NIST_PQC_INVENTORY if a["status"] in ("Deprecated", "Broken")),
    }


@app.get("/api/risk/calculate")
async def calculate_risk(
    findings: Optional[str] = Query(None, alias="findings"),
    weights: Optional[str] = Query(None, alias="weights"),
    api_key: str = Depends(verify_api_key),
):
    finding_list = []
    weight_dict = {}
    if findings:
        try:
            finding_list = json.loads(findings)
        except json.JSONDecodeError:
            raise HTTPException(400, "Invalid 'findings' JSON.")
    if weights:
        try:
            weight_dict = json.loads(weights)
        except json.JSONDecodeError:
            raise HTTPException(400, "Invalid 'weights' JSON.")
    return _calculate_risk({"findings": finding_list, "weights": weight_dict})


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
