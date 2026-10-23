"""
test_scanner.py
---------------
Automated tests for the Automated Web Security Scanner.

HOW TO RUN:
    python -m unittest test_scanner.py -v

All tests use unittest.mock to simulate HTTP responses.
NO real websites are contacted — tests run completely offline.

This file covers:
  - HTTPS detection (pass and fail)
  - All 5 security headers (present, missing, weak values)
  - CORS header scenarios (missing, wildcard, credentials, restricted)
  - Scoring and grading
  - Error handling (invalid URL, connection error, timeout)

BhartCare Cybersecurity Bootcamp — First-Year BCA Project
"""

import unittest
from unittest.mock import patch, MagicMock
import requests

import security_scanner


# ---------------------------------------------------------------------------
# Helper: build a fake requests.Response object
# ---------------------------------------------------------------------------

def _make_mock_response(url="https://example.com", status_code=200, headers=None):
    """
    Return a MagicMock that behaves like a requests.Response.

    Parameters
    ----------
    url : str
        The value of response.url (simulates the final URL after redirects).
    status_code : int
        HTTP status code returned by the fake server.
    headers : dict, optional
        Response headers. Use a plain dict — requests normally returns a
        CaseInsensitiveDict, but security_scanner.py uses .get() which
        works the same on a plain dict for our test purposes.
    """
    mock_resp = MagicMock()
    mock_resp.url         = url
    mock_resp.status_code = status_code
    mock_resp.headers     = headers or {}
    return mock_resp


# ---------------------------------------------------------------------------
# Test class
# ---------------------------------------------------------------------------

class TestHTTPSCheck(unittest.TestCase):
    """Tests for the HTTPS detection logic."""

    @patch("security_scanner.requests.get")
    def test_https_pass(self, mock_get):
        """A URL that stays on HTTPS after redirects should be marked Pass."""
        mock_get.return_value = _make_mock_response(url="https://example.com")
        result = security_scanner.scan_website("https://example.com")
        self.assertIsNone(result.get("error"))
        self.assertTrue(result["https_check"]["passed"])
        self.assertEqual(result["https_check"]["severity"], "Pass")

    @patch("security_scanner.requests.get")
    def test_https_fail(self, mock_get):
        """A URL that ends on plain HTTP should be marked Critical."""
        # Simulate a server that redirected to HTTP (unusual but possible)
        mock_get.return_value = _make_mock_response(url="http://example.com")
        result = security_scanner.scan_website("http://example.com")
        self.assertIsNone(result.get("error"))
        self.assertFalse(result["https_check"]["passed"])
        self.assertEqual(result["https_check"]["severity"], "Critical")


class TestSecurityHeaders(unittest.TestCase):
    """Tests for the five required security headers."""

    # ---- Helper method ----
    def _scan_with_headers(self, headers: dict) -> list:
        """Run a scan with the given headers dict and return headers_check list."""
        with patch("security_scanner.requests.get") as mock_get:
            mock_get.return_value = _make_mock_response(headers=headers)
            result = security_scanner.scan_website("https://example.com")
        return result["headers_check"]

    def _finding_for(self, headers_check: list, header_name: str) -> dict:
        """Find a specific header finding by name."""
        for f in headers_check:
            if f["header"] == header_name:
                return f
        self.fail(f"Header '{header_name}' not found in findings.")

    # ---- All present ----
    def test_all_headers_present(self):
        """All 5 security headers present → every finding should be Pass."""
        all_headers = {
            "Content-Security-Policy":   "default-src 'self'",
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "X-Content-Type-Options":    "nosniff",
            "X-Frame-Options":           "DENY",
            "Referrer-Policy":           "strict-origin-when-cross-origin",
        }
        findings = self._scan_with_headers(all_headers)
        for f in findings:
            with self.subTest(header=f["header"]):
                self.assertTrue(f["present"], f"{f['header']} should be present")
                self.assertEqual(f["severity"], "Pass",
                                 f"{f['header']} should be Pass when set correctly")

    # ---- All missing ----
    def test_missing_all_headers(self):
        """No security headers at all → findings should have expected severities."""
        findings = self._scan_with_headers({})
        expected_severities = {
            "Content-Security-Policy":   "High",
            "Strict-Transport-Security": "High",
            "X-Content-Type-Options":    "Medium",
            "X-Frame-Options":           "Medium",
            "Referrer-Policy":           "Low",
        }
        for f in findings:
            with self.subTest(header=f["header"]):
                self.assertFalse(f["present"])
                self.assertEqual(f["severity"], expected_severities[f["header"]],
                    f"{f['header']}: expected {expected_severities[f['header']]}, "
                    f"got {f['severity']}")

    # ---- Individual severity checks ----
    def test_csp_severity_high(self):
        """Missing Content-Security-Policy → High severity."""
        findings = self._scan_with_headers({})
        f = self._finding_for(findings, "Content-Security-Policy")
        self.assertEqual(f["severity"], "High")

    def test_hsts_severity_high(self):
        """Missing Strict-Transport-Security → High severity."""
        findings = self._scan_with_headers({})
        f = self._finding_for(findings, "Strict-Transport-Security")
        self.assertEqual(f["severity"], "High")

    def test_x_content_type_severity_medium(self):
        """Missing X-Content-Type-Options → Medium severity."""
        findings = self._scan_with_headers({})
        f = self._finding_for(findings, "X-Content-Type-Options")
        self.assertEqual(f["severity"], "Medium")

    def test_x_frame_severity_medium(self):
        """Missing X-Frame-Options → Medium severity."""
        findings = self._scan_with_headers({})
        f = self._finding_for(findings, "X-Frame-Options")
        self.assertEqual(f["severity"], "Medium")

    def test_referrer_policy_severity_low(self):
        """Missing Referrer-Policy → Low severity."""
        findings = self._scan_with_headers({})
        f = self._finding_for(findings, "Referrer-Policy")
        self.assertEqual(f["severity"], "Low")

    # ---- Weak value checks ----
    def test_weak_x_content_type(self):
        """
        X-Content-Type-Options with a non-'nosniff' value should:
          - be marked present=True
          - have severity Low (not High/Medium — the header IS there)
          - have a recommendation that says "Change" (fix the value), not "Add"
        """
        findings = self._scan_with_headers({"X-Content-Type-Options": "badvalue"})
        f = self._finding_for(findings, "X-Content-Type-Options")
        self.assertTrue(f["present"])
        self.assertEqual(f["severity"], "Low")
        # Recommendation should say how to fix the existing value, not "Add:"
        self.assertIsNotNone(f["recommendation"])
        self.assertNotIn("Add:", f["recommendation"],
            "Recommendation for a weak-value header should not say 'Add:' — the header is already present.")
        self.assertIn("nosniff", f["recommendation"].lower(),
            "Recommendation should mention the correct value 'nosniff'.")

    def test_weak_x_frame_allow_from(self):
        """
        X-Frame-Options with deprecated ALLOW-FROM should warn about deprecation.
        """
        findings = self._scan_with_headers({"X-Frame-Options": "ALLOW-FROM https://trusted.com"})
        f = self._finding_for(findings, "X-Frame-Options")
        self.assertTrue(f["present"])
        self.assertEqual(f["severity"], "Low")
        # The detail should mention that ALLOW-FROM is deprecated
        detail_lower = f["detail"].lower()
        self.assertIn("deprecated", detail_lower,
            "Detail for ALLOW-FROM should mention that the directive is deprecated.")

    def test_hsts_max_age_zero(self):
        """HSTS with max-age=0 effectively disables HSTS — should warn."""
        findings = self._scan_with_headers({"Strict-Transport-Security": "max-age=0"})
        f = self._finding_for(findings, "Strict-Transport-Security")
        self.assertTrue(f["present"])
        self.assertEqual(f["severity"], "Low")
        self.assertIn("max-age=0", f["detail"].lower())


class TestCORSCheck(unittest.TestCase):
    """Tests for CORS header inspection."""

    def _scan_cors(self, headers: dict) -> dict:
        """Run a scan and return the cors_check dict."""
        with patch("security_scanner.requests.get") as mock_get:
            mock_get.return_value = _make_mock_response(headers=headers)
            result = security_scanner.scan_website("https://example.com")
        return result["cors_check"]

    def _finding_for(self, cors_check: dict, header_name: str) -> dict | None:
        """Return the first CORS finding matching the given header name, or None."""
        for f in cors_check.get("findings", []):
            if f["header"] == header_name:
                return f
        return None

    def test_cors_no_headers(self):
        """No CORS headers at all → overall severity Info (safe default)."""
        cors = self._scan_cors({})
        self.assertEqual(cors["overall_severity"], "Info")
        f = self._finding_for(cors, "Access-Control-Allow-Origin")
        self.assertIsNotNone(f)
        self.assertEqual(f["severity"], "Info")

    def test_cors_wildcard_origin(self):
        """Wildcard ACAO → High severity."""
        cors = self._scan_cors({"Access-Control-Allow-Origin": "*"})
        f = self._finding_for(cors, "Access-Control-Allow-Origin")
        self.assertIsNotNone(f)
        self.assertEqual(f["severity"], "High")
        self.assertEqual(cors["overall_severity"], "High")

    def test_cors_wildcard_plus_credentials(self):
        """
        Wildcard ACAO + Allow-Credentials: true → Critical finding.
        This is the most dangerous CORS misconfiguration.
        """
        cors = self._scan_cors({
            "Access-Control-Allow-Origin":      "*",
            "Access-Control-Allow-Credentials": "true",
        })
        cred_finding = self._finding_for(cors, "Access-Control-Allow-Credentials")
        self.assertIsNotNone(cred_finding,
            "Expected a finding for Access-Control-Allow-Credentials.")
        self.assertEqual(cred_finding["severity"], "Critical")
        self.assertEqual(cors["overall_severity"], "Critical")

    def test_cors_restricted_origin(self):
        """Specific (non-wildcard) origin → Pass severity."""
        cors = self._scan_cors({"Access-Control-Allow-Origin": "https://trusted.com"})
        f = self._finding_for(cors, "Access-Control-Allow-Origin")
        self.assertIsNotNone(f)
        self.assertEqual(f["severity"], "Pass")

    def test_cors_credentials_with_restricted_origin(self):
        """Allow-Credentials: true with a restricted origin is acceptable → Pass."""
        cors = self._scan_cors({
            "Access-Control-Allow-Origin":      "https://trusted.com",
            "Access-Control-Allow-Credentials": "true",
        })
        cred_finding = self._finding_for(cors, "Access-Control-Allow-Credentials")
        self.assertIsNotNone(cred_finding)
        self.assertEqual(cred_finding["severity"], "Pass")


class TestScoring(unittest.TestCase):
    """Tests for the overall score and grade calculation."""

    def _scan(self, url="https://example.com", headers=None) -> dict:
        with patch("security_scanner.requests.get") as mock_get:
            mock_get.return_value = _make_mock_response(url=url, headers=headers or {})
            return security_scanner.scan_website(url)

    def test_score_perfect(self):
        """All checks pass → score should be 100, grade A."""
        all_headers = {
            "Content-Security-Policy":   "default-src 'self'",
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "X-Content-Type-Options":    "nosniff",
            "X-Frame-Options":           "DENY",
            "Referrer-Policy":           "strict-origin",
        }
        result = self._scan(headers=all_headers)
        # HTTPS (25) + 5 headers x10 (50) + CORS Info (20) = 95 ... but no CORS
        # headers means overall_severity=Info → +20, total = 95
        # With CORS Pass (a specific origin) it would be 100.
        # Here: no CORS headers → Info → 20pts → 25+50+20 = 95, grade A
        self.assertGreaterEqual(result["overall_score"], 90)
        self.assertEqual(result["overall_grade"], "A")

    def test_score_all_headers_plus_cors_pass(self):
        """All security headers + restricted CORS origin → score 100, grade A."""
        all_headers = {
            "Content-Security-Policy":   "default-src 'self'",
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "X-Content-Type-Options":    "nosniff",
            "X-Frame-Options":           "DENY",
            "Referrer-Policy":           "strict-origin",
            "Access-Control-Allow-Origin": "https://trusted.com",
        }
        result = self._scan(headers=all_headers)
        self.assertEqual(result["overall_score"], 100)
        self.assertEqual(result["overall_grade"], "A")

    def test_score_no_https(self):
        """
        No HTTPS (HTTP response), no security headers, no CORS → score 20, grade F.
        Breakdown: HTTPS=0, headers=0, CORS Info=+20 → 20.
        """
        result = self._scan(url="http://example.com", headers={})
        self.assertEqual(result["overall_score"], 20)
        self.assertEqual(result["overall_grade"], "F")


class TestErrorHandling(unittest.TestCase):
    """Tests for graceful handling of bad inputs and network errors."""

    def test_invalid_url_empty(self):
        """Empty string → error in result, no crash, no network call made."""
        result = security_scanner.scan_website("")
        self.assertIsNotNone(result.get("error"),
            "Empty URL should produce an error message.")
        self.assertNotIn("https_check", result,
            "https_check should not be present when URL is invalid.")

    def test_invalid_url_garbage(self):
        """Garbage text that can't be a URL → error in result."""
        result = security_scanner.scan_website("not a url at all!!!")
        self.assertIsNotNone(result.get("error"))
        self.assertNotIn("https_check", result)

    @patch("security_scanner.requests.get",
           side_effect=requests.exceptions.ConnectionError("refused"))
    def test_connection_error(self, mock_get):
        """Simulated connection error → friendly error message in result."""
        result = security_scanner.scan_website("https://unreachable.example.com")
        self.assertIsNotNone(result.get("error"))
        self.assertIn("connection", result["error"].lower(),
            "Error message should mention 'connection'.")
        self.assertNotIn("https_check", result)

    @patch("security_scanner.requests.get",
           side_effect=requests.exceptions.Timeout("timed out"))
    def test_timeout(self, mock_get):
        """Simulated timeout → friendly timeout message in result."""
        result = security_scanner.scan_website("https://slow.example.com")
        self.assertIsNotNone(result.get("error"))
        self.assertIn("timeout", result["error"].lower(),
            "Error message should mention 'timeout'.")
        self.assertNotIn("https_check", result)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    unittest.main(verbosity=2)
