"""
security_scanner.py
--------------------
Core scanning module for the Automated Web Security Scanner.
Performs non-invasive, read-only HTTP header checks on a target URL.

Checks performed:
  1. HTTPS usage
  2. Security headers: Content-Security-Policy, Strict-Transport-Security,
     X-Content-Type-Options, X-Frame-Options, Referrer-Policy
  3. CORS headers: Access-Control-Allow-Origin, Access-Control-Allow-Methods,
     Access-Control-Allow-Headers, Access-Control-Allow-Credentials

IMPORTANT: Only test websites you own or have permission to audit.
           These checks are fully passive (read-only HTTP GET requests).
"""

import requests
import datetime
from urllib.parse import urlparse


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Request timeout in seconds (connect + read)
REQUEST_TIMEOUT = 10

# Security headers we look for, with a short description for each
SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "Defines which content sources are trusted. "
        "Prevents XSS and data-injection attacks."
    ),
    "Strict-Transport-Security": (
        "Forces browsers to use HTTPS only. "
        "Protects against protocol-downgrade attacks."
    ),
    "X-Content-Type-Options": (
        "Prevents browsers from MIME-sniffing a response. "
        "Should be set to 'nosniff'."
    ),
    "X-Frame-Options": (
        "Controls whether the page can be embedded in an iframe. "
        "Prevents clickjacking attacks."
    ),
    "Referrer-Policy": (
        "Controls how much referrer information is sent with requests. "
        "Protects user privacy."
    ),
}

# Severity levels used throughout the project
SEVERITY_CRITICAL = "Critical"
SEVERITY_HIGH     = "High"
SEVERITY_MEDIUM   = "Medium"
SEVERITY_LOW      = "Low"
SEVERITY_INFO     = "Info"
SEVERITY_PASS     = "Pass"


# ---------------------------------------------------------------------------
# Helper utilities
# ---------------------------------------------------------------------------

def normalize_url(url: str) -> str:
    """
    Ensure the URL has a scheme (http:// or https://).
    If the user typed 'example.com' we prepend 'https://'.
    """
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url


def is_valid_url(url: str) -> bool:
    """
    Return True if the URL has both a scheme and a network location (host).
    """
    try:
        parsed = urlparse(url)
        return bool(parsed.scheme and parsed.netloc)
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Main scanner function
# ---------------------------------------------------------------------------

def scan_website(url: str) -> dict:
    """
    Perform a full security scan on the given URL.

    Parameters
    ----------
    url : str
        The target URL (e.g. 'https://example.com').

    Returns
    -------
    dict
        A structured result dictionary with keys:
        - url, timestamp, error (if any)
        - https_check, headers_check, cors_check
        - overall_score (0-100), overall_grade (A-F)
    """
    url = normalize_url(url)

    # Validate the URL before making any network request
    if not is_valid_url(url):
        return {
            "url": url,
            "timestamp": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "error": f"'{url}' is not a valid URL. Please include a domain (e.g. https://example.com).",
        }

    # Attempt to fetch the page headers
    try:
        response = requests.get(
            url,
            timeout=REQUEST_TIMEOUT,
            # Follow redirects so we land on the final page
            allow_redirects=True,
            # Send a realistic User-Agent to avoid being blocked
            headers={"User-Agent": "AutoWebScanner/1.0 (Security Audit; Educational)"},
        )
        final_url   = response.url          # URL after any redirects
        status_code = response.status_code
        resp_headers = response.headers     # CaseInsensitiveDict

    except requests.exceptions.ConnectionError:
        return {
            "url": url,
            "timestamp": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "error": "Connection error: Could not reach the server. Check the URL or your internet connection.",
        }
    except requests.exceptions.Timeout:
        return {
            "url": url,
            "timestamp": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "error": f"Timeout: The server did not respond within {REQUEST_TIMEOUT} seconds.",
        }
    except requests.exceptions.RequestException as exc:
        return {
            "url": url,
            "timestamp": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "error": f"Request error: {str(exc)}",
        }

    # ----- Build the result dictionary -----
    result = {
        "url":        url,
        "final_url":  final_url,
        "timestamp":  datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "status_code": status_code,
        "error":      None,
    }

    # 1. HTTPS check
    result["https_check"] = _check_https(final_url)

    # 2. Security headers check
    result["headers_check"] = _check_security_headers(resp_headers)

    # 3. CORS check
    result["cors_check"] = _check_cors(resp_headers)

    # 4. Compute an overall score and grade
    score, grade = _compute_score(result)
    result["overall_score"] = score
    result["overall_grade"] = grade

    return result


# ---------------------------------------------------------------------------
# Individual check functions
# ---------------------------------------------------------------------------

def _check_https(final_url: str) -> dict:
    """Check whether the final (post-redirect) URL uses HTTPS."""
    uses_https = final_url.startswith("https://")
    return {
        "passed":   uses_https,
        "severity": SEVERITY_PASS if uses_https else SEVERITY_CRITICAL,
        "detail":   "Site is served over HTTPS. ✔" if uses_https
                    else "Site is NOT using HTTPS. All data is transmitted in plain text.",
        "recommendation": None if uses_https
                    else "Obtain a TLS/SSL certificate (e.g. via Let's Encrypt) and redirect HTTP → HTTPS.",
    }


def _check_security_headers(headers) -> list:
    """
    Check each expected security header.
    Returns a list of finding dicts, one per header.
    """
    findings = []

    for header_name, description in SECURITY_HEADERS.items():
        value = headers.get(header_name)  # None if missing

        if value is None:
            # Header is completely absent
            severity = _missing_header_severity(header_name)
            finding = {
                "header":         header_name,
                "present":        False,
                "value":          None,
                "severity":       severity,
                "description":    description,
                "detail":         f"'{header_name}' header is missing.",
                "recommendation": _missing_header_recommendation(header_name),
            }
        else:
            # Header is present — check for weak values
            warning = _check_header_value(header_name, value)
            finding = {
                "header":         header_name,
                "present":        True,
                "value":          value,
                "severity":       SEVERITY_LOW if warning else SEVERITY_PASS,
                "description":    description,
                "detail":         warning if warning else f"'{header_name}' is set correctly. ✔",
                # Use a "fix the value" recommendation, not the "add the header" one,
                # because the header IS present — it just has a weak value.
                "recommendation": _weak_value_recommendation(header_name) if warning else None,
            }

        findings.append(finding)

    return findings


def _check_cors(headers) -> dict:
    """
    Inspect CORS response headers for potentially unsafe configurations.
    Returns a dict with a list of findings and an overall CORS severity.
    """
    acao  = headers.get("Access-Control-Allow-Origin")
    acam  = headers.get("Access-Control-Allow-Methods")
    acah  = headers.get("Access-Control-Allow-Headers")
    acac  = headers.get("Access-Control-Allow-Credentials")

    findings = []

    # --- Access-Control-Allow-Origin ---
    if acao is None:
        findings.append({
            "header":   "Access-Control-Allow-Origin",
            "value":    None,
            "severity": SEVERITY_INFO,
            "detail":   "Not set. CORS is not explicitly enabled (this is safe by default).",
        })
    elif acao == "*":
        findings.append({
            "header":   "Access-Control-Allow-Origin",
            "value":    acao,
            "severity": SEVERITY_HIGH,
            # Clarify that wildcard may be intentional for public APIs/CDNs,
            # so the student understands context rather than always treating it as wrong.
            "detail":   (
                "Set to wildcard '*' — any website can read responses from this server. "
                "This is acceptable for fully public resources (e.g. public APIs or CDNs) "
                "but is a security risk for pages that handle authentication or sensitive data."
            ),
            "recommendation": (
                "If this endpoint serves authenticated or sensitive data, restrict to specific "
                "trusted origins (e.g. 'https://yourdomain.com'). "
                "If it is a public read-only API, wildcard is intentional and acceptable."
            ),
        })
    else:
        findings.append({
            "header":   "Access-Control-Allow-Origin",
            "value":    acao,
            "severity": SEVERITY_PASS,
            "detail":   f"Restricted to: {acao}. ✔",
        })

    # --- Access-Control-Allow-Credentials ---
    if acac and acac.lower() == "true":
        if acao == "*":
            findings.append({
                "header":   "Access-Control-Allow-Credentials",
                "value":    acac,
                "severity": SEVERITY_CRITICAL,
                "detail":   "Credentials are allowed with a wildcard origin — this is a critical misconfiguration.",
                "recommendation": "Never combine 'Access-Control-Allow-Credentials: true' with 'Access-Control-Allow-Origin: *'.",
            })
        else:
            findings.append({
                "header":   "Access-Control-Allow-Credentials",
                "value":    acac,
                "severity": SEVERITY_PASS,
                "detail":   "Credentials flag is true but origin is restricted. ✔",
            })

    # --- Access-Control-Allow-Methods (informational) ---
    if acam:
        findings.append({
            "header":   "Access-Control-Allow-Methods",
            "value":    acam,
            "severity": SEVERITY_INFO,
            "detail":   f"Allowed methods: {acam}",
        })

    # --- Access-Control-Allow-Headers (informational) ---
    if acah:
        findings.append({
            "header":   "Access-Control-Allow-Headers",
            "value":    acah,
            "severity": SEVERITY_INFO,
            "detail":   f"Allowed headers: {acah}",
        })

    # Determine overall CORS severity
    severities = [f["severity"] for f in findings]
    if SEVERITY_CRITICAL in severities:
        overall = SEVERITY_CRITICAL
    elif SEVERITY_HIGH in severities:
        overall = SEVERITY_HIGH
    elif SEVERITY_MEDIUM in severities:
        overall = SEVERITY_MEDIUM
    elif SEVERITY_PASS in severities:
        overall = SEVERITY_PASS
    else:
        overall = SEVERITY_INFO

    return {"findings": findings, "overall_severity": overall}


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------

def _compute_score(result: dict) -> tuple:
    """
    Compute a 0-100 security score and an A-F grade.

    Points awarded:
      HTTPS present        : 25 pts
      Each of 5 headers    : 10 pts each  (50 pts total)
      No critical CORS flaw: 25 pts
    """
    score = 0

    # HTTPS (25 pts)
    if result.get("https_check", {}).get("passed"):
        score += 25

    # Security headers (10 pts each)
    for finding in result.get("headers_check", []):
        if finding.get("present"):
            score += 10

    # CORS (25 pts — deduct for critical/high)
    cors_severity = result.get("cors_check", {}).get("overall_severity", SEVERITY_INFO)
    if cors_severity == SEVERITY_PASS:
        score += 25
    elif cors_severity in (SEVERITY_INFO, SEVERITY_LOW):
        score += 20
    elif cors_severity == SEVERITY_MEDIUM:
        score += 10
    elif cors_severity == SEVERITY_HIGH:
        score += 5
    # CRITICAL → 0 pts

    # Map score to grade
    if score >= 90:
        grade = "A"
    elif score >= 75:
        grade = "B"
    elif score >= 60:
        grade = "C"
    elif score >= 40:
        grade = "D"
    else:
        grade = "F"

    return score, grade


# ---------------------------------------------------------------------------
# Lookup tables for header severity and recommendations
# ---------------------------------------------------------------------------

def _missing_header_severity(header_name: str) -> str:
    table = {
        "Content-Security-Policy":   SEVERITY_HIGH,
        "Strict-Transport-Security": SEVERITY_HIGH,
        "X-Content-Type-Options":    SEVERITY_MEDIUM,
        "X-Frame-Options":           SEVERITY_MEDIUM,
        "Referrer-Policy":           SEVERITY_LOW,
    }
    return table.get(header_name, SEVERITY_MEDIUM)


def _missing_header_recommendation(header_name: str) -> str:
    table = {
        "Content-Security-Policy":
            "Add a CSP header, e.g.: Content-Security-Policy: default-src 'self'",
        "Strict-Transport-Security":
            "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains",
        "X-Content-Type-Options":
            "Add: X-Content-Type-Options: nosniff",
        "X-Frame-Options":
            "Add: X-Frame-Options: DENY  (or SAMEORIGIN if you embed your own iframes)",
        "Referrer-Policy":
            "Add: Referrer-Policy: no-referrer-when-downgrade  (or 'strict-origin')",
    }
    return table.get(header_name, "Consult OWASP Secure Headers Project for guidance.")


def _check_header_value(header_name: str, value: str) -> str | None:
    """
    Return a warning string if the header value is known to be weak,
    or None if the value looks acceptable.
    """
    v = value.strip().lower()

    if header_name == "X-Content-Type-Options" and v != "nosniff":
        return f"Value '{value}' is non-standard. Expected 'nosniff'."

    if header_name == "X-Frame-Options" and v not in ("deny", "sameorigin"):
        # ALLOW-FROM <uri> is a real but deprecated value — be specific about why.
        if v.startswith("allow-from"):
            return (
                f"Value '{value}' uses the deprecated ALLOW-FROM directive. "
                "Modern browsers ignore it. Use 'DENY' or 'SAMEORIGIN' instead, "
                "and control embedding with a Content-Security-Policy frame-ancestors directive."
            )
        return (
            f"Value '{value}' is not recognised. "
            "Expected 'DENY' (blocks all framing) or 'SAMEORIGIN' (allows same site only)."
        )

    if header_name == "Strict-Transport-Security":
        if "max-age=0" in v:
            return "max-age=0 effectively disables HSTS. Use a value of at least 31536000 (1 year)."

    # No issues found
    return None


def _weak_value_recommendation(header_name: str) -> str:
    """
    Return a recommendation for fixing a header that IS present but has a weak value.
    This is distinct from _missing_header_recommendation(), which tells the user to
    add a header that is completely absent.
    """
    table = {
        "X-Content-Type-Options":
            "Change the value to 'nosniff': X-Content-Type-Options: nosniff",
        "X-Frame-Options":
            "Use 'DENY' to block all framing, or 'SAMEORIGIN' to allow your own site only. "
            "Remove any deprecated ALLOW-FROM directive.",
        "Strict-Transport-Security":
            "Set max-age to at least 31536000 (one year): "
            "Strict-Transport-Security: max-age=31536000; includeSubDomains",
        "Content-Security-Policy":
            "Review and tighten your CSP policy. Avoid 'unsafe-inline' and 'unsafe-eval'.",
        "Referrer-Policy":
            "Use a stricter value such as 'strict-origin' or 'no-referrer-when-downgrade'.",
    }
    return table.get(
        header_name,
        "Review the header value against the OWASP Secure Headers Project guidelines."
    )
