# tls-auditor

Inspect a server's TLS certificate and connection posture in one command.
`tls-auditor` connects over TLS, reads the negotiated protocol and the presented
certificate, and reports the problems that cause outages and findings: an
expired or not-yet-valid certificate, a hostname mismatch, an expiry that is
about to lapse, and an obsolete protocol version.

## Why

Two of the most common production incidents are a certificate that quietly
expired and a service still accepting TLS 1.0/1.1. Both are a 10-second check
you should run before a report or a deploy — but only if you have a tool that
does it without a browser. `tls-auditor` is that tool, on the standard library
alone.

It is read-only: a single outbound TLS handshake to the host you name.

## Checks

| Check | PASS / WARN / FAIL |
| --- | --- |
| **protocol** | TLS 1.3/1.2 pass; TLS 1.0/1.1 and SSLv2/3 FAIL |
| **hostname** | the certificate verifies for the host, or FAIL with the reason |
| **expiry** | FAIL if expired or not-yet-valid; WARN within 30 days; otherwise PASS |

When verification fails (self-signed, wrong host, untrusted chain), the tool
still completes the handshake without verification so it can report *why* the
certificate was rejected, rather than just erroring out.

## Requirements

Python 3.10 or newer. No packages to install.

## Usage

```bash
# Audit the default HTTPS port
python3 tls_auditor.py example.com

# A different port (e.g. SMTPS, IMAPS, a custom service)
python3 tls_auditor.py mail.example.com -p 993

# Machine-readable
python3 tls_auditor.py example.com --json
```

### Options

| Flag | Description | Default |
| --- | --- | --- |
| `host` | Hostname to audit | required |
| `-p`, `--port` | Port to connect to | `443` |
| `--json` | Emit the report as JSON | off |

## Example

```
$ python3 tls_auditor.py example.com
tls-auditor  example.com:443  (TLSv1.3)
overall: PASS

  [PASS] protocol: negotiated TLSv1.3.
  [PASS] hostname: certificate is valid for example.com.
  [PASS] expiry: valid until 2026-12-25 (67 days left).
```

Exits non-zero when any check **FAILs**, so a monitoring job can alert on a
genuinely broken certificate or an obsolete protocol.

## Tests

```bash
python3 -m unittest discover -s tests -v
```

Standard-library `unittest`. TLS handshakes are replaced by a fake connector
that supplies certificate data in the exact `ssl.getpeercert()` shape, so the
suite is deterministic and never touches the network.

## Scope

Audit hosts you own or are explicitly authorized to assess. The tool makes one
outbound TLS connection and changes nothing on the target.

## License

MIT — see [LICENSE](LICENSE).
