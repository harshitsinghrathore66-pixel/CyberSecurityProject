"""
app.py
------
Flask web application for the Automated Web Security Scanner.

Routes:
  GET  /           — Home page (scan form)
  POST /scan        — Run a scan and return results as JSON
  GET  /download/json  — Download the latest JSON report
  GET  /download/html  — Download the latest HTML report

Run this file directly:
  python app.py

Then open your browser at:  http://127.0.0.1:5000
"""

from flask import Flask, render_template, request, jsonify, send_file, abort
import security_scanner
import report_generator
import os

# ---------------------------------------------------------------------------
# App setup
# ---------------------------------------------------------------------------

app = Flask(__name__)

# Holds the most-recently generated report paths so the download buttons work.
# In a real multi-user app you would use sessions or a database instead.
_latest_json_path = None
_latest_html_path = None


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    """Serve the home page with the scan form."""
    return render_template("index.html")


@app.route("/scan", methods=["POST"])
def scan():
    """
    Accept a URL from the form, run the scanner, save reports,
    and return the results as a JSON response.
    """
    global _latest_json_path, _latest_html_path

    # Read the URL submitted by the user
    data = request.get_json(silent=True) or {}
    url  = data.get("url", "").strip()

    if not url:
        return jsonify({"error": "No URL provided. Please enter a website address."}), 400

    # Run the scan (all error handling is inside scan_website)
    result = security_scanner.scan_website(url)

    # Save reports (even if the scan returned an error, we still save)
    try:
        _latest_json_path = report_generator.save_json_report(result)
        _latest_html_path = report_generator.save_html_report(result)
    except Exception as exc:
        # Report saving failure should not crash the API response
        result["report_save_error"] = str(exc)

    # Add the report paths to the response so the UI can show them
    result["json_report_saved"] = _latest_json_path
    result["html_report_saved"] = _latest_html_path

    return jsonify(result)


@app.route("/download/json")
def download_json():
    """Download the most recently generated JSON report."""
    if not _latest_json_path or not os.path.exists(_latest_json_path):
        abort(404, description="No JSON report available yet. Run a scan first.")
    return send_file(
        _latest_json_path,
        as_attachment=True,
        download_name="security_report.json",
        mimetype="application/json",
    )


@app.route("/download/html")
def download_html():
    """Download the most recently generated HTML report."""
    if not _latest_html_path or not os.path.exists(_latest_html_path):
        abort(404, description="No HTML report available yet. Run a scan first.")
    return send_file(
        _latest_html_path,
        as_attachment=True,
        download_name="security_report.html",
        mimetype="text/html",
    )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("=" * 55)
    print("  Automated Web Security Scanner")
    print("  BhartCare Cybersecurity Bootcamp Project")
    print("=" * 55)
    print("  Open your browser and go to:  http://127.0.0.1:5000")
    print("  Press Ctrl+C to stop the server.")
    print("=" * 55)
    # debug=True gives helpful error messages during development.
    # Set debug=False before deploying to production.
    app.run(debug=True, host="127.0.0.1", port=5000)
