#!/usr/bin/env python3
"""tls-auditor - inspect a server's TLS certificate and connection posture.

Connects to a host:port over TLS, reads the negotiated protocol version and the
presented certificate, and reports the things that cause real outages and real
findings: an expired or not-yet-valid certificate, a hostname that does not
match, an expiry that is dangerously close, and an obsolete protocol version
(TLS 1.0/1.1). Each check returns PASS, WARN, or FAIL with a plain reason.

It is read-only: it makes one outbound TLS handshake to the target you name and
reports what the server presented. Audit hosts you own or are authorized to
assess.
"""
from __future__ import annotations

import argparse
import datetime as _dt
import json
import socket
import ssl
import sys

PASS, WARN, FAIL = "PASS", "WARN", "FAIL"
_RANK = {FAIL: 0, WARN: 1, PASS: 2}

# Protocol versions considered obsolete; anything below TLS 1.2 is a finding.
_OBSOLETE_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}

_WARN_DAYS = 30  # warn when a certificate expires within this many days.

# Certificate timestamps use this fixed C locale format: "Jun  1 12:00:00 2026 GMT".
_CERT_TIME_FMT = "%b %d %H:%M:%S %Y %Z"


class AuditError(RuntimeError):
    """Raised when the target cannot be reached or the handshake fails."""


def _parse_cert_time(value: str) -> _dt.datetime:
    """Parse an OpenSSL certificate timestamp into an aware UTC datetime."""
    parsed = _dt.datetime.strptime(value, _CERT_TIME_FMT)
    return parsed.replace(tzinfo=_dt.timezone.utc)


def fetch_certificate(host: str, port: int = 443, timeout: float = 10.0,
                      server_hostname: str | None = None,
                      connector=None) -> dict:
    """Open a TLS connection and return the peer certificate + protocol.

    ``connector`` is injectable for tests; it must yield an SSL socket whose
    ``getpeercert()`` and ``version()`` behave like the stdlib's.
    """
    server_hostname = server_hostname or host
    if connector is not None:
        return connector(host, port, server_hostname, timeout)

    context = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(
                    sock, server_hostname=server_hostname) as tls:
                return {"cert": tls.getpeercert(),
                        "protocol": tls.version(),
                        "hostname_verified": True}
    except ssl.SSLCertVerificationError as exc:
        # Verification failed (bad hostname, expired, untrusted chain). Retry
        # without verification so we can still read and report the cert detail.
        return _fetch_unverified(host, port, server_hostname, timeout, exc)
    except (socket.timeout, TimeoutError) as exc:
        raise AuditError(f"timed out connecting to {host}:{port}") from exc
    except (ssl.SSLError, OSError) as exc:
        raise AuditError(f"TLS handshake with {host}:{port} failed: "
                         f"{exc}") from exc


def _fetch_unverified(host, port, server_hostname, timeout, reason) -> dict:
    """Read the certificate even when verification failed, to report why."""
    context = ssl._create_unverified_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(
                    sock, server_hostname=server_hostname) as tls:
                # An unverified context returns the cert only in binary form,
                # so decode it back into the dict shape via get_unverified.
                cert_bin = tls.getpeercert(binary_form=True)
                return {"cert": _decode_der(cert_bin),
                        "protocol": tls.version(),
                        "hostname_verified": False,
                        "verify_error": str(reason)}
    except (ssl.SSLError, OSError) as exc:
        raise AuditError(f"TLS handshake with {host}:{port} failed: "
                         f"{exc}") from exc


def _decode_der(cert_bin: bytes) -> dict:
    """Best-effort decode of a DER certificate into the getpeercert() shape.

    The stdlib has no public DER->dict parser, so when verification fails we
    expose the raw bytes' length and leave detailed field checks to the caller,
    which still has the protocol and the verify error to report on.
    """
    return {"_der_len": len(cert_bin)}


# ----------------------------------------------------------------------------
# Checks
# ----------------------------------------------------------------------------

def check_expiry(cert: dict, now: _dt.datetime | None = None) -> dict:
    """Check notBefore / notAfter against the current time."""
    now = now or _dt.datetime.now(tz=_dt.timezone.utc)
    not_after = cert.get("notAfter")
    not_before = cert.get("notBefore")
    if not not_after:
        return _result("expiry", WARN,
                       "certificate expiry not available (verification may "
                       "have failed; see the hostname check).")
    expires = _parse_cert_time(not_after)
    if not_before:
        starts = _parse_cert_time(not_before)
        if now < starts:
            return _result("expiry", FAIL,
                           f"certificate is not valid until {starts.date()}.")
    if expires < now:
        return _result("expiry", FAIL,
                       f"certificate expired on {expires.date()}.")
    days_left = (expires - now).days
    detail = f"valid until {expires.date()} ({days_left} days left)."
    if days_left <= _WARN_DAYS:
        return _result("expiry", WARN,
                       f"certificate expires soon: {detail}")
    return _result("expiry", PASS, detail)


def check_hostname(result: dict, expected: str) -> dict:
    """Report whether the certificate matched the expected hostname."""
    if result.get("hostname_verified"):
        return _result("hostname", PASS,
                       f"certificate is valid for {expected}.")
    reason = result.get("verify_error", "verification failed")
    return _result("hostname", FAIL,
                   f"certificate did NOT verify for {expected}: {reason}")


def check_protocol(protocol: str | None) -> dict:
    """Check the negotiated TLS protocol version."""
    if not protocol:
        return _result("protocol", WARN, "negotiated protocol unknown.")
    if protocol in _OBSOLETE_PROTOCOLS:
        return _result("protocol", FAIL,
                       f"negotiated {protocol}, which is obsolete and insecure; "
                       "require TLS 1.2 or higher.")
    if protocol == "TLSv1.2":
        return _result("protocol", PASS,
                       "negotiated TLS 1.2 (acceptable; TLS 1.3 preferred).")
    return _result("protocol", PASS, f"negotiated {protocol}.")


def _result(name: str, status: str, detail: str) -> dict:
    return {"check": name, "status": status, "detail": detail}


def audit(host: str, port: int = 443, now: _dt.datetime | None = None,
          connector=None, timeout: float = 10.0) -> dict:
    """Run the full TLS audit for one host:port."""
    result = fetch_certificate(host, port, timeout=timeout, connector=connector)
    cert = result.get("cert") or {}
    checks = [
        check_protocol(result.get("protocol")),
        check_hostname(result, host),
        check_expiry(cert, now=now),
    ]
    worst = min((c["status"] for c in checks), key=lambda s: _RANK.get(s, 9))
    return {
        "host": host,
        "port": port,
        "protocol": result.get("protocol"),
        "overall": worst,
        "checks": checks,
    }


# ----------------------------------------------------------------------------
# CLI
# ----------------------------------------------------------------------------

def _print_report(report: dict) -> None:
    print(f"tls-auditor  {report['host']}:{report['port']}  "
          f"({report['protocol']})")
    print(f"overall: {report['overall']}\n")
    for check in report["checks"]:
        print(f"  [{check['status']}] {check['check']}: {check['detail']}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="tls-auditor",
        description="Inspect a server's TLS certificate and protocol "
                    "(read-only; authorized hosts only).")
    parser.add_argument("host", help="hostname to audit")
    parser.add_argument("-p", "--port", type=int, default=443,
                        help="port (default: 443)")
    parser.add_argument("--json", action="store_true",
                        help="emit the report as JSON")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        report = audit(args.host, args.port)
    except AuditError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        _print_report(report)

    return 1 if report["overall"] == FAIL else 0


if __name__ == "__main__":
    raise SystemExit(main())
