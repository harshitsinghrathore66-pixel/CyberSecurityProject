# PROJECT REPORT
## Automated Web Security Scanner
### BhartCare Cybersecurity Bootcamp — First-Year BCA Project

---

## 1. Project Overview

**Project Title:** Automated Web Security Scanner  
**Topic Assigned:** Programmed a Python script to audit websites for secure headers and CORS flaws.  
**Technology Stack:** Python 3, Flask, Requests library, HTML/CSS, JavaScript  
**Type:** Web Application (local server)

This project builds a fully functional, non-invasive web security audit tool. It
inspects HTTP response headers to check whether a website implements recommended
security controls. All checks are passive — the tool only reads headers returned
by the target server and never modifies anything.

---

## 2. Objectives

1. Learn how HTTP security headers protect websites from common attacks.
2. Understand CORS (Cross-Origin Resource Sharing) and its security implications.
3. Build a practical Python tool that performs automated security checks.
4. Present findings in a clear, colour-coded interface for non-technical users.
5. Generate downloadable JSON and HTML reports.

---

## 3. Background — Why Security Headers Matter

When a browser visits a website, the server returns HTTP response headers along
with the page content. Some headers are purely technical (content type, cookies),
but several headers exist specifically to protect users from attacks:

| Header | Attack Prevented |
|---|---|
| Content-Security-Policy | XSS (Cross-Site Scripting), data injection |
| Strict-Transport-Security (HSTS) | Protocol-downgrade attacks, SSL-stripping |
| X-Content-Type-Options | MIME-type confusion attacks |
| X-Frame-Options | Clickjacking (embedding in iframes) |
| Referrer-Policy | Sensitive URL leakage in referrer data |

When these headers are missing or misconfigured, attackers may exploit the gap.
According to the OWASP Secure Headers Project, a significant proportion of
production websites are still missing one or more of these headers.

---

## 4. CORS — What It Is and Why It Can Be Dangerous

CORS (Cross-Origin Resource Sharing) is a browser mechanism that controls which
websites can read responses from a different origin.

**Key headers:**

- `Access-Control-Allow-Origin` — which origins are permitted
- `Access-Control-Allow-Methods` — which HTTP methods are allowed
- `Access-Control-Allow-Credentials` — whether cookies/auth are included

**Common dangerous misconfigurations:**

| Misconfiguration | Risk |
|---|---|
| `Access-Control-Allow-Origin: *` | Any website on the internet can read the response |
| `Allow-Origin: *` + `Allow-Credentials: true` | **Critical** — browsers block this, but misconfigurations at the server level can still expose APIs |
| Reflected `Origin` without validation | Allows any domain to make credentialed requests |

---

## 5. Project Architecture

```
User Browser
     │
     ▼
Flask Web Server (app.py)
     │
     ├──► security_scanner.py  ← HTTP GET request → target website
     │         └── Returns structured result dict
     │
     └──► report_generator.py  ← Converts result → JSON file + HTML file
```

**Data Flow:**
1. User enters URL in browser form.
2. Browser sends POST `/scan` to Flask.
3. Flask calls `security_scanner.scan_website(url)`.
4. Scanner makes one HTTP GET request and inspects response headers.
5. Results are returned as JSON to the browser and also saved to disk.
6. The UI renders colour-coded findings; user can download reports.

---

## 6. Checks Performed

### 6.1 HTTPS Check
- Confirms the final URL (after any redirects) uses `https://`.
- Severity if missing: **Critical** (all data transmitted in plain text).

### 6.2 Security Header Checks

| Header | Severity if Missing |
|---|---|
| Content-Security-Policy | High |
| Strict-Transport-Security | High |
| X-Content-Type-Options | Medium |
| X-Frame-Options | Medium |
| Referrer-Policy | Low |

The scanner also inspects present headers for weak values (e.g.
`X-Content-Type-Options: something` instead of `nosniff`).

### 6.3 CORS Checks
- Missing `Access-Control-Allow-Origin` → **Info** (safe default)
- Wildcard `*` origin → **High**
- Wildcard `*` + `Allow-Credentials: true` → **Critical**
- Restricted specific origin → **Pass**

### 6.4 Scoring
Each scan produces a 0–100 score:
- HTTPS present: 25 points
- Each of 5 security headers present: 10 points each (50 total)
- No critical CORS flaw: up to 25 points

Grades: A (≥90), B (≥75), C (≥60), D (≥40), F (<40)

---

## 7. Sample Scan Results *(These are illustrative examples — not real scan data)*

> **NOTE:** The results below are **example illustrations only**. Actual results
> will vary depending on each website's current configuration at the time of
> scanning. Do not treat these as current or factual statements about any website.

### Example A — Website with good security posture
```
URL: https://[example-good-site].com
Score: 90 / 100   Grade: A

✔ HTTPS: Pass
✔ Content-Security-Policy: Present
✔ Strict-Transport-Security: Present — max-age=31536000; includeSubDomains
✔ X-Content-Type-Options: nosniff
✔ X-Frame-Options: DENY
✔ Referrer-Policy: strict-origin-when-cross-origin
ℹ CORS: No CORS headers (safe default)
```

### Example B — Website with missing headers
```
URL: https://[example-basic-site].com
Score: 55 / 100   Grade: D

Scoring breakdown:
  HTTPS present          : +25 pts
  Content-Security-Policy: +0  pts (missing)
  Strict-Transport-Security: +0 pts (missing)
  X-Content-Type-Options : +0  pts (missing)
  X-Frame-Options        : +0  pts (missing)
  Referrer-Policy        : +10 pts (present)
  CORS (Info — no headers): +20 pts
  Total                  : 55 pts  →  Grade D

✔ HTTPS: Pass
✗ Content-Security-Policy: MISSING (High)
✗ Strict-Transport-Security: MISSING (High)
✗ X-Content-Type-Options: MISSING (Medium)
✗ X-Frame-Options: MISSING (Medium)
✔ Referrer-Policy: no-referrer
ℹ CORS: No CORS headers (safe default)
```

### Example C — Website with CORS misconfiguration
```
URL: https://[example-api].com
Score: 60 / 100   Grade: C

✔ HTTPS: Pass
✗ Content-Security-Policy: MISSING (High)
✔ Strict-Transport-Security: Present
✔ X-Content-Type-Options: nosniff
✔ X-Frame-Options: SAMEORIGIN
✔ Referrer-Policy: Present
⚠ Access-Control-Allow-Origin: * (High — wildcard allows any origin)
   Recommendation: Restrict to specific trusted origins
```

---

## 8. Testing

### 8.1 Testing Approach

All core scanner logic is tested using Python's built-in `unittest` framework with
**mocked HTTP responses**. This means no real websites are contacted during testing —
the tests are completely offline and safe to run at any time.

The mock library (`unittest.mock`) replaces `requests.get` with a fake response
object whose headers are set by each test case. This lets us test every code path
— including CORS misconfigurations and missing headers — without scanning any
external server.

### 8.2 Test File

Test file: `test_scanner.py`
Run command: `python -m unittest test_scanner.py -v`

### 8.3 Test Cases

| Test Name | What It Verifies |
|---|---|
| `test_https_pass` | HTTPS URL correctly marked as Pass |
| `test_https_fail` | HTTP (non-HTTPS) URL correctly marked as Critical |
| `test_all_headers_present` | All 5 security headers present — all findings Pass |
| `test_missing_all_headers` | No security headers — each finding has correct severity |
| `test_csp_severity_high` | Missing CSP → severity is High |
| `test_hsts_severity_high` | Missing HSTS → severity is High |
| `test_x_content_type_severity_medium` | Missing X-Content-Type-Options → severity is Medium |
| `test_x_frame_severity_medium` | Missing X-Frame-Options → severity is Medium |
| `test_referrer_policy_severity_low` | Missing Referrer-Policy → severity is Low |
| `test_weak_x_content_type` | `X-Content-Type-Options: badvalue` → Low severity, fix-value recommendation |
| `test_weak_x_frame_allow_from` | Deprecated `ALLOW-FROM` value → warning mentions deprecation |
| `test_hsts_max_age_zero` | `max-age=0` → warning about disabled HSTS |
| `test_cors_wildcard_origin` | `ACAO: *` → severity High |
| `test_cors_wildcard_plus_credentials` | `ACAO: *` + `ACAC: true` → Critical finding |
| `test_cors_restricted_origin` | Specific origin → severity Pass |
| `test_cors_no_headers` | No CORS headers → Info (safe default) |
| `test_score_perfect` | All headers + HTTPS + good CORS → score 100, grade A |
| `test_score_no_https` | No HTTPS, no headers → score 20, grade F |
| `test_invalid_url` | Blank/garbage URL → error key in result, no crash |
| `test_connection_error` | Simulated network failure → friendly error message |
| `test_timeout` | Simulated timeout → friendly timeout message |

### 8.4 Test Results

All 21 tests pass. Run `python -m unittest test_scanner.py -v` to verify.

---

## 9. Error Handling

| Scenario | How It Is Handled |
|---|---|
| Invalid URL (no domain) | Returns a clear message before making any request |
| Connection refused / DNS failure | Catches `ConnectionError`, returns friendly message |
| Server timeout | Catches `Timeout`, reports the timeout duration |
| HTTP error codes (4xx, 5xx) | Still inspects headers; status code is shown |
| Missing CORS headers | Shown as "Info" (not a flaw — safe default) |

---

## 10. Tools and Libraries Used

| Library | Purpose |
|---|---|
| `flask` | Lightweight Python web framework |
| `requests` | Sending HTTP GET requests |
| `json` (built-in) | Serialising results to JSON |
| `pathlib` (built-in) | Cross-platform file path handling |
| `datetime` (built-in) | Timestamping reports |
| `urllib.parse` (built-in) | Parsing and validating URLs |

---

## 11. Key Learning Outcomes

1. **HTTP Headers:** Learned the purpose and importance of security-specific
   response headers.
2. **CORS:** Understood how the Same-Origin Policy and CORS work in browsers.
3. **Python networking:** Used the `requests` library to make and inspect HTTP
   responses programmatically.
4. **Flask:** Built a working REST API and served dynamic HTML with Jinja2
   templates.
5. **Report generation:** Programmatically created JSON and styled HTML files
   from structured data.
6. **Error handling:** Gracefully managed network errors, invalid inputs, and
   timeouts.
7. **Automated testing:** Used `unittest` and `unittest.mock` to write offline
   tests covering all scanner logic without scanning real websites.
8. **Ethical considerations:** Understood the legal and ethical boundaries of
   security testing.

---

## 12. Ethical and Legal Considerations

- All checks are **read-only** (HTTP GET only).
- The tool does **not** attempt authentication, send payloads, or exploit
  vulnerabilities.
- It is intended for **educational purposes** and for testing websites the user
  owns or has permission to test.
- Unauthorised security scanning of third-party websites may be illegal under
  laws such as the Computer Fraud and Abuse Act (USA), the Computer Misuse Act
  (UK), or equivalent legislation in India and other countries.

---

## 13. Future Improvements

- Add cookie security flag checking (`HttpOnly`, `Secure`, `SameSite`).
- Check TLS/SSL certificate validity and expiry date.
- Support for scanning multiple URLs in a batch (CSV input).
- Historical comparison — track header changes over time.
- Email report delivery.

---

## 14. References

- OWASP Secure Headers Project: https://owasp.org/www-project-secure-headers/
- MDN Web Docs — HTTP Headers: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers
- Flask Documentation: https://flask.palletsprojects.com/
- Requests Library: https://docs.python-requests.org/
- MDN — CORS: https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS

---

*Report prepared by: First-Year BCA Student*  
*Bootcamp: BhartCare Cybersecurity Bootcamp*  
*Project: Automated Web Security Scanner*
