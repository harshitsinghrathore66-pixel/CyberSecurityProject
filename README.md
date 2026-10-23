# 🔒 Automated Web Security Scanner

**BhartCare Cybersecurity Bootcamp — First-Year BCA Project**

A Python + Flask tool that audits websites for security headers and CORS
misconfigurations. Entirely passive (read-only HTTP requests) — no exploitation,
no attacks, no port scanning.

---

## 📁 Project Structure

```
CyberSecurityProject/
├── app.py                  ← Flask web application (run this)
├── security_scanner.py     ← Core scanner logic
├── report_generator.py     ← JSON + HTML report generator
├── requirements.txt        ← Python dependencies
├── README.md               ← This file
├── PROJECT_REPORT.md       ← Bootcamp project write-up
├── templates/
│   └── index.html          ← Web UI template
├── static/
│   └── style.css           ← Stylesheet
└── reports/                ← Auto-created; scan reports saved here
```

---

## ✅ What It Checks

| Check | Details |
|---|---|
| **HTTPS** | Is the site served over HTTPS? |
| **Content-Security-Policy** | Prevents XSS and data injection |
| **Strict-Transport-Security** | Forces HTTPS-only connections |
| **X-Content-Type-Options** | Prevents MIME-sniffing |
| **X-Frame-Options** | Prevents clickjacking |
| **Referrer-Policy** | Controls referrer information leakage |
| **CORS headers** | Checks for wildcard origins and credential misconfigurations |

---

## 💻 Installation & Setup on Windows (VS Code)

### Prerequisites
- Python 3.10 or newer → [python.org/downloads](https://www.python.org/downloads/)
- VS Code → [code.visualstudio.com](https://code.visualstudio.com/)
- Python extension for VS Code (search "Python" in the Extensions panel)

---

### Step 1 — Open the project in VS Code

1. Open VS Code.
2. Click **File → Open Folder…**
3. Select the `CyberSecurityProject` folder.

---

### Step 2 — Open the integrated terminal

Press `` Ctrl + ` `` (backtick) — a PowerShell terminal opens at the bottom.

---

### Step 3 — Create a virtual environment

```powershell
python -m venv venv
```

Activate it:

```powershell
.\venv\Scripts\Activate.ps1
```

> **Tip:** If you see an error about script execution, run this once:
> ```powershell
> Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
> ```
> Then repeat the `Activate.ps1` command.

You should now see `(venv)` at the start of the prompt.

---

### Step 4 — Install dependencies

```powershell
pip install -r requirements.txt
```

---

### Step 5 — Run the application

```powershell
python app.py
```

You'll see:

```
=======================================================
  Automated Web Security Scanner
  BhartCare Cybersecurity Bootcamp Project
=======================================================
  Open your browser and go to:  http://127.0.0.1:5000
  Press Ctrl+C to stop the server.
=======================================================
```

---

### Step 6 — Use the scanner

1. Open **http://127.0.0.1:5000** in your browser.
2. Type any URL (e.g. `https://example.com`) in the input box.
3. Click **Scan Now**.
4. View the colour-coded results on screen.
5. Click **Download JSON Report** or **Download HTML Report** to save a copy.

Reports are also automatically saved to the `reports/` folder.

---

## 🧪 Testing the Scanner

### Running the automated tests (recommended — no internet needed)

The project includes `test_scanner.py`, which tests all scanner logic using
**mocked HTTP responses**. No real website is contacted.

```powershell
python -m unittest test_scanner.py -v
```

You should see 21 tests pass.

### Testing with your own website (optional)

If you own a website or have a local development server running, you can scan it
through the web UI at `http://127.0.0.1:5000`.

> ⚠️ **Only scan websites you own or have explicit written permission to test.**
> Do not scan websites belonging to other people or organisations.
> Unauthorised scanning may be illegal in your jurisdiction.

### What NOT to do

Do **not** enter URLs like `google.com`, `github.com`, or other third-party sites
you do not own. Even though the checks are passive (read-only), testing without
permission is ethically wrong and potentially illegal.

---

## ⚠️ Known Limitations

| Limitation | Details |
|---|---|
| **Single-threaded server** | Flask's built-in dev server handles one request at a time. Do not use it in production. |
| **No TLS/SSL certificate check** | The scanner checks for HTTPS in the URL but does not verify the certificate is valid or unexpired. |
| **No cookie security checks** | Cookie flags (`HttpOnly`, `Secure`, `SameSite`) are not inspected. |
| **Single GET request only** | Some headers (e.g. CORS) may only appear on specific endpoints or in response to preflight OPTIONS requests. |
| **Rate limiting** | Some servers may block or throttle repeated requests from the same IP address. |
| **No authentication** | The scanner cannot inspect pages that require a login. |
| **Windows path for reports** | The `reports/` folder uses relative paths; ensure you run `app.py` from the project root. |

---

## 📄 Reports

After each scan, two files are saved in the `reports/` folder:

- `<domain>_<timestamp>.json` — machine-readable data
- `<domain>_<timestamp>.html` — open in any browser for a styled report

---

## 🛑 Stopping the Server

Press `Ctrl + C` in the terminal.

---

## ⚖️ Ethical & Legal Notice

This tool performs **read-only HTTP GET requests** — it never writes data,
modifies anything, or attempts authentication. All checks are passive.

- **Only scan websites you own or have written permission to test.**
- Using this tool against websites without permission may be illegal in your
  jurisdiction (e.g. under the Computer Misuse Act or similar laws).
- This project is for **educational purposes only**.
