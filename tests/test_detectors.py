from datetime import datetime, timedelta, timezone

from xwllz import detectors
from xwllz.engines import dns as dns_engine
from xwllz.engines import http as http_engine
from xwllz.engines.tls import TlsResult


def _tls(days_left):
    now = datetime.now(timezone.utc)
    return TlsResult(
        host="www.example.com",
        port=443,
        not_before=now - timedelta(days=30),
        not_after=now + timedelta(days=days_left),
        days_left=days_left,
        san=["www.example.com"],
    )


def test_tls_expiry_ok():
    assert detectors.tls_expiry(_tls(30)) == []


def test_tls_expiry_soon():
    findings = detectors.tls_expiry(_tls(5))
    assert len(findings) == 1
    assert findings[0].severity == "medium"
    assert findings[0].kind == "tls_expiry"


def test_tls_expired():
    findings = detectors.tls_expiry(_tls(-3))
    assert findings[0].severity == "high"
    assert findings[0].kind == "tls_expired"


def test_tls_hostname_mismatch():
    tls = _tls(60)
    tls.san = ["other.example.com"]
    findings = detectors.tls_hostname_mismatch(tls, "www.example.com")
    assert len(findings) == 1
    assert findings[0].kind == "tls_mismatch"


def test_tls_hostname_wildcard_match():
    tls = _tls(60)
    tls.san = ["*.example.com"]
    assert detectors.tls_hostname_mismatch(tls, "www.example.com") == []


def test_email_posture_missing_everything():
    result = dns_engine.DnsResult(domain="example.com")
    findings = detectors.email_posture(result)
    kinds = {f.kind for f in findings}
    assert {"spf", "dmarc", "dkim"} <= kinds


def test_email_posture_present():
    result = dns_engine.DnsResult(
        domain="example.com", has_spf=True, spf_record="v=spf1 -all",
        has_dmarc=True, dmarc_record="v=DMARC1; p=reject", has_dkim=True,
    )
    assert detectors.email_posture(result) == []


def test_security_headers_missing():
    h = http_engine.HttpResult(host="x", port=443, scheme="https", status=200, headers={})
    findings = detectors.security_headers(h)
    kinds = {f.kind for f in findings}
    assert {"hsts", "nosniff", "clickjack", "csp"} <= kinds


def test_security_headers_present():
    h = http_engine.HttpResult(
        host="x", port=443, scheme="https", status=200,
        headers={
            "Strict-Transport-Security": "max-age=31536000",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Content-Security-Policy": "default-src 'self'",
        },
    )
    assert detectors.security_headers(h) == []


def test_exposed_ports():
    findings = detectors.exposed_ports([22, 3389, 8080, 445])
    kinds = {f.kind for f in findings}
    assert kinds == {"exposed_port"}
    titles = {f.title for f in findings}
    assert "RDP exposed" in titles
    assert "SMB exposed" in titles