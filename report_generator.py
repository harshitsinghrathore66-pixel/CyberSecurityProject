"""
report_generator.py
--------------------
Generates two types of security reports from scan results:

  1. JSON report  — machine-readable, saved to reports/<domain>_<timestamp>.json
  2. HTML report  — human-readable styled page, saved to reports/<domain>_<timestamp>.html

Both files are written to the 'reports/' folder (created automatically if absent).
"""

import json
import html as html_module
import datetime
from pathlib import Path


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

REPORTS_DIR = Path("reports")   # Folder where all reports are saved

# Severity → badge colour mapping used in the HTML report
SEVERITY_COLORS = {
    "Critical": "#dc2626",   # red
    "High":     "#ea580c",   # orange-red
    "Medium":   "#d97706",   # amber
    "Low":      "#ca8a04",   # yellow
    "Pass":     "#16a34a",   # green
    "Info":     "#2563eb",   # blue
}


# ---------------------------------------------------------------------------
# Public functions
# ---------------------------------------------------------------------------

def save_json_report(scan_result: dict) -> str:
    """
    Write the scan result to a JSON file.

    Parameters
    ----------
    scan_result : dict
        The dict returned by security_scanner.scan_website().

    Returns
    -------
    str
        The file path of the saved JSON report.
    """
    _ensure_reports_dir()
    filename = _build_filename(scan_result, "json")
    filepath = REPORTS_DIR / filename

    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(scan_result, f, indent=4, ensure_ascii=False)

    return str(filepath)


def save_html_report(scan_result: dict) -> str:
    """
    Write a styled HTML report to a file.

    Parameters
    ----------
    scan_result : dict
        The dict returned by security_scanner.scan_website().

    Returns
    -------
    str
        The file path of the saved HTML report.
    """
    _ensure_reports_dir()
    filename = _build_filename(scan_result, "html")
    filepath = REPORTS_DIR / filename

    html_content = _build_html(scan_result)
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(html_content)

    return str(filepath)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _ensure_reports_dir():
    """Create the reports/ directory if it does not already exist."""
    REPORTS_DIR.mkdir(exist_ok=True)


def _build_filename(scan_result: dict, extension: str) -> str:
    """
    Build a safe filename like: example_com_20240601_143022.json
    """
    from urllib.parse import urlparse
    url   = scan_result.get("url", "unknown")
    host  = urlparse(url).netloc.replace(".", "_").replace(":", "_") or "unknown"
    ts    = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d_%H%M%S")
    return f"{host}_{ts}.{extension}"


def _severity_badge(severity: str) -> str:
    """Return an HTML <span> badge coloured by severity."""
    color = SEVERITY_COLORS.get(severity, "#6b7280")
    return (
        f'<span style="background:{color};color:#fff;padding:2px 10px;'
        f'border-radius:12px;font-size:0.78rem;font-weight:600;">{severity}</span>'
    )


def _build_html(result: dict) -> str:
    """Build the full HTML report as a string."""

    # html_module.escape() converts <, >, &, " to safe HTML entities,
    # preventing broken markup when a URL or error message contains special chars.
    url         = html_module.escape(str(result.get("url", "N/A")))
    timestamp   = html_module.escape(str(result.get("timestamp", "N/A")))
    score       = result.get("overall_score", "N/A")
    grade       = result.get("overall_grade", "N/A")
    error_raw   = result.get("error")
    error       = html_module.escape(str(error_raw)) if error_raw else None
    status_code = html_module.escape(str(result.get("status_code", "N/A")))

    # Grade colour
    grade_colors = {"A": "#16a34a", "B": "#65a30d", "C": "#d97706",
                    "D": "#ea580c", "F": "#dc2626"}
    grade_color = grade_colors.get(grade, "#6b7280")

    # --- Error state ---
    if error:
        body_content = f"""
        <div class="card error-card">
            <h2>&#9888; Scan Failed</h2>
            <p>{error}</p>
        </div>
        """
    else:
        body_content = _build_results_html(result, grade_color, grade, score)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Security Report — {url}</title>
  <style>
    /* ---- Base ---- */
    *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
      font-family: -apple-system, "Segoe UI", system-ui, sans-serif;
      background: #0f172a;
      color: #e2e8f0;
      line-height: 1.6;
      padding: 2rem 1rem;
    }}
    a {{ color: #60a5fa; }}
    /* ---- Layout ---- */
    .container {{ max-width: 800px; margin: 0 auto; }}
    .header {{
      background: linear-gradient(135deg, #1e3a8a, #312e81);
      border-radius: 12px;
      padding: 2rem;
      margin-bottom: 1.5rem;
      border: 1px solid #334155;
    }}
    .header h1 {{ font-size: 1.5rem; color: #93c5fd; margin-bottom: 0.4rem; }}
    .header .meta {{ color: #94a3b8; font-size: 0.85rem; }}
    .card {{
      background: #1e293b;
      border: 1px solid #334155;
      border-radius: 10px;
      padding: 1.4rem;
      margin-bottom: 1.2rem;
    }}
    .card h2 {{ font-size: 1.1rem; color: #93c5fd; margin-bottom: 1rem; border-bottom: 1px solid #334155; padding-bottom: 0.5rem; }}
    .error-card {{ border-color: #dc2626; }}
    .error-card h2 {{ color: #fca5a5; }}
    /* ---- Score ---- */
    .score-row {{ display: flex; align-items: center; gap: 1.5rem; }}
    .grade-circle {{
      width: 72px; height: 72px;
      border-radius: 50%;
      display: flex; align-items: center; justify-content: center;
      font-size: 2rem; font-weight: 800;
      border: 3px solid;
      flex-shrink: 0;
    }}
    .score-bar-wrap {{ flex: 1; }}
    .score-bar-bg {{ background: #334155; border-radius: 6px; height: 12px; overflow: hidden; }}
    .score-bar-fill {{ height: 100%; border-radius: 6px; transition: width 0.4s; }}
    /* ---- Findings table ---- */
    .finding-row {{
      display: flex; align-items: flex-start;
      gap: 1rem; padding: 0.8rem 0;
      border-bottom: 1px solid #1e293b;
    }}
    .finding-row:last-child {{ border-bottom: none; }}
    .finding-meta {{ flex: 1; min-width: 0; }}
    .finding-name {{ font-weight: 600; color: #cbd5e1; word-break: break-all; }}
    .finding-detail {{ font-size: 0.83rem; color: #94a3b8; margin-top: 0.2rem; }}
    .finding-rec {{
      font-size: 0.8rem; color: #fbbf24;
      background: #1c1917; border-left: 3px solid #d97706;
      padding: 0.4rem 0.6rem; margin-top: 0.4rem; border-radius: 0 4px 4px 0;
    }}
    /* ---- Footer ---- */
    .footer {{
      text-align: center; font-size: 0.75rem;
      color: #475569; margin-top: 2rem;
      border-top: 1px solid #334155; padding-top: 1rem;
    }}
  </style>
</head>
<body>
<div class="container">
  <div class="header">
    <h1>🔒 Web Security Scan Report</h1>
    <p class="meta"><strong>Target:</strong> {url}</p>
    <p class="meta"><strong>Scanned at:</strong> {timestamp} (UTC) &nbsp;|&nbsp; <strong>HTTP Status:</strong> {status_code}</p>
  </div>
  {body_content}
  <div class="footer">
    Generated by Automated Web Security Scanner &nbsp;|&nbsp; BhartCare Cybersecurity Bootcamp Project
  </div>
</div>
</body>
</html>"""


def _build_results_html(result: dict, grade_color: str, grade: str, score: int) -> str:
    """Build the results section of the HTML report."""

    # Escape dynamic text values before embedding in HTML
    safe_final_url  = html_module.escape(str(result.get("final_url", result.get("url", "N/A"))))
    safe_timestamp  = html_module.escape(str(result.get("timestamp", "N/A")))

    # ---- Score card ----
    score_html = f"""
    <div class="card">
      <h2>Overall Security Score</h2>
      <div class="score-row">
        <div class="grade-circle" style="color:{grade_color};border-color:{grade_color};">{html_module.escape(str(grade))}</div>
        <div class="score-bar-wrap">
          <p style="color:#94a3b8;font-size:0.85rem;margin-bottom:0.5rem;">{score} / 100 points</p>
          <div class="score-bar-bg">
            <div class="score-bar-fill" style="width:{score}%;background:{grade_color};"></div>
          </div>
        </div>
      </div>
      <p style="color:#94a3b8;font-size:0.8rem;margin-top:0.8rem;">
        <strong>Target:</strong> {safe_final_url} &nbsp;|&nbsp;
        <strong>Scanned:</strong> {safe_timestamp} (UTC)
      </p>
    </div>"""

    # ---- HTTPS card ----
    https = result.get("https_check", {})
    https_rows = _finding_row(
        name    = "HTTPS Encryption",
        severity= https.get("severity", "Info"),
        detail  = https.get("detail", ""),
        rec     = https.get("recommendation"),
        value   = None,
    )
    https_html = f"""
    <div class="card">
      <h2>HTTPS Check</h2>
      {https_rows}
    </div>"""

    # ---- Security headers card ----
    header_rows = ""
    for h in result.get("headers_check", []):
        header_rows += _finding_row(
            name    = h.get("header", ""),
            severity= h.get("severity", "Info"),
            detail  = h.get("detail", ""),
            rec     = h.get("recommendation"),
            value   = h.get("value"),
        )
    headers_html = f"""
    <div class="card">
      <h2>Security Headers</h2>
      {header_rows}
    </div>"""

    # ---- CORS card ----
    cors_rows = ""
    for f in result.get("cors_check", {}).get("findings", []):
        cors_rows += _finding_row(
            name    = f.get("header", ""),
            severity= f.get("severity", "Info"),
            detail  = f.get("detail", ""),
            rec     = f.get("recommendation"),
            value   = f.get("value"),
        )
    cors_html = f"""
    <div class="card">
      <h2>CORS Headers</h2>
      {cors_rows if cors_rows else '<p style="color:#94a3b8;">No CORS headers detected on this response.</p>'}
    </div>"""

    return score_html + https_html + headers_html + cors_html


def _finding_row(name: str, severity: str, detail: str, rec: str | None, value: str | None) -> str:
    """Render a single finding row as HTML."""
    # Escape all user-controlled strings before inserting into HTML
    safe_name   = html_module.escape(str(name))
    safe_detail = html_module.escape(str(detail))

    value_html = ""
    if value:
        safe_val  = html_module.escape(str(value))
        short_val = safe_val[:80] + "…" if len(safe_val) > 80 else safe_val
        value_html = f'<span style="color:#64748b;font-size:0.78rem;"> — {short_val}</span>'

    rec_html = ""
    if rec:
        safe_rec = html_module.escape(str(rec))
        rec_html = f'<div class="finding-rec">&#128161; {safe_rec}</div>'

    return f"""
    <div class="finding-row">
      <div>{_severity_badge(severity)}</div>
      <div class="finding-meta">
        <div class="finding-name">{safe_name}{value_html}</div>
        <div class="finding-detail">{safe_detail}</div>
        {rec_html}
      </div>
    </div>"""
