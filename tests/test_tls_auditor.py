"""Tests for tls-auditor: cert parsing, checks, audit flow, and CLI.

TLS handshakes are not performed; a fake connector supplies certificate dicts
in the exact shape ssl.getpeercert() returns, so the checks run against
deterministic data without touching the network.
"""
from __future__ import annotations

import datetime as _dt
import json
import unittest

import tls_auditor
from tls_auditor import (AuditError, FAIL, PASS, WARN, audit, check_expiry,
                         check_hostname, check_protocol)
from tests.support.fakes import capture_cli

UTC = _dt.timezone.utc
NOW = _dt.datetime(2026, 6, 1, 12, 0, 0, tzinfo=UTC)


def cert(not_before="May  1 00:00:00 2026 GMT",
         not_after="Dec  1 00:00:00 2026 GMT"):
    return {"notBefore": not_before, "notAfter": not_after,
            "subject": ((("commonName", "example.com"),),)}


def fake_connector(cert_dict, protocol="TLSv1.3", verified=True,
                   verify_error=None):
    def connector(host, port, server_hostname, timeout):
        result = {"cert": cert_dict, "protocol": protocol,
                  "hostname_verified": verified}
        if verify_error:
            result["verify_error"] = verify_error
        return result
    return connector


class ProtocolCheckTests(unittest.TestCase):
    def test_tls13_passes(self):
        self.assertEqual(check_protocol("TLSv1.3")["status"], PASS)

    def test_tls12_passes(self):
        self.assertEqual(check_protocol("TLSv1.2")["status"], PASS)

    def test_tls10_fails(self):
        self.assertEqual(check_protocol("TLSv1")["status"], FAIL)

    def test_sslv3_fails(self):
        self.assertEqual(check_protocol("SSLv3")["status"], FAIL)

    def test_unknown_warns(self):
        self.assertEqual(check_protocol(None)["status"], WARN)


class HostnameCheckTests(unittest.TestCase):
    def test_verified_passes(self):
        result = {"hostname_verified": True}
        self.assertEqual(check_hostname(result, "example.com")["status"], PASS)

    def test_unverified_fails(self):
        result = {"hostname_verified": False,
                  "verify_error": "hostname mismatch"}
        check = check_hostname(result, "example.com")
        self.assertEqual(check["status"], FAIL)
        self.assertIn("hostname mismatch", check["detail"])


class ExpiryCheckTests(unittest.TestCase):
    def test_valid_cert_passes(self):
        self.assertEqual(check_expiry(cert(), now=NOW)["status"], PASS)

    def test_expired_cert_fails(self):
        c = cert(not_after="Jan  1 00:00:00 2026 GMT")
        self.assertEqual(check_expiry(c, now=NOW)["status"], FAIL)

    def test_not_yet_valid_fails(self):
        c = cert(not_before="Dec  1 00:00:00 2026 GMT",
                 not_after="Dec  1 00:00:00 2027 GMT")
        self.assertEqual(check_expiry(c, now=NOW)["status"], FAIL)

    def test_expiring_soon_warns(self):
        c = cert(not_after="Jun 20 00:00:00 2026 GMT")  # 19 days from NOW
        self.assertEqual(check_expiry(c, now=NOW)["status"], WARN)

    def test_missing_expiry_warns(self):
        self.assertEqual(check_expiry({}, now=NOW)["status"], WARN)


class AuditFlowTests(unittest.TestCase):
    def test_healthy_cert_overall_pass(self):
        report = audit("example.com", now=NOW,
                       connector=fake_connector(cert()))
        self.assertEqual(report["overall"], PASS)
        self.assertEqual(report["protocol"], "TLSv1.3")

    def test_expired_cert_overall_fail(self):
        c = cert(not_after="Jan  1 00:00:00 2026 GMT")
        report = audit("example.com", now=NOW,
                       connector=fake_connector(c))
        self.assertEqual(report["overall"], FAIL)

    def test_obsolete_protocol_overall_fail(self):
        report = audit("example.com", now=NOW,
                       connector=fake_connector(cert(), protocol="TLSv1"))
        self.assertEqual(report["overall"], FAIL)

    def test_unverified_hostname_overall_fail(self):
        report = audit("example.com", now=NOW,
                       connector=fake_connector(
                           cert(), verified=False,
                           verify_error="self-signed"))
        self.assertEqual(report["overall"], FAIL)


class CertTimeParsingTests(unittest.TestCase):
    def test_parses_openssl_format(self):
        parsed = tls_auditor._parse_cert_time("Jun  1 12:00:00 2026 GMT")
        self.assertEqual(parsed.year, 2026)
        self.assertEqual(parsed.tzinfo, UTC)


class FetchCertificateTests(unittest.TestCase):
    def test_connector_path_used(self):
        result = tls_auditor.fetch_certificate(
            "example.com", 443,
            connector=fake_connector(cert(), protocol="TLSv1.3"))
        self.assertEqual(result["protocol"], "TLSv1.3")
        self.assertTrue(result["hostname_verified"])

    def test_decode_der_returns_length(self):
        self.assertEqual(tls_auditor._decode_der(b"abcd"), {"_der_len": 4})


class CLITests(unittest.TestCase):
    def test_report_output(self):
        report = {"host": "example.com", "port": 443, "protocol": "TLSv1.3",
                  "overall": PASS,
                  "checks": [{"check": "protocol", "status": PASS,
                              "detail": "negotiated TLSv1.3."}]}
        import unittest.mock as mock
        with mock.patch("tls_auditor.audit", return_value=report):
            code, out = capture_cli(tls_auditor.main, ["example.com"])
        self.assertEqual(code, 0)
        self.assertIn("overall: PASS", out)

    def test_json_output(self):
        report = {"host": "x", "port": 443, "protocol": "TLSv1.3",
                  "overall": PASS, "checks": []}
        import unittest.mock as mock
        with mock.patch("tls_auditor.audit", return_value=report):
            code, out = capture_cli(tls_auditor.main, ["x", "--json"])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["overall"], "PASS")

    def test_fail_exit_one(self):
        report = {"host": "x", "port": 443, "protocol": "TLSv1",
                  "overall": FAIL, "checks": []}
        import unittest.mock as mock
        with mock.patch("tls_auditor.audit", return_value=report):
            code, _out = capture_cli(tls_auditor.main, ["x"])
        self.assertEqual(code, 1)

    def test_audit_error_exit_two(self):
        import unittest.mock as mock
        with mock.patch("tls_auditor.audit",
                        side_effect=AuditError("unreachable")):
            code, err = capture_cli(tls_auditor.main, ["x"])
        self.assertEqual(code, 2)
        self.assertIn("error", err)


if __name__ == "__main__":
    unittest.main()
