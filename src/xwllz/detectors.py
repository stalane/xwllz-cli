"""Passive blue-team detectors that turn collected data into findings."""

from __future__ import annotations

from dataclasses import dataclass

from xwllz.engines import dns as dns_engine
from xwllz.engines import http as http_engine
from xwllz.engines.tls import TlsResult


@dataclass
class Finding:
    severity: str
    kind: str
    title: str
    detail: str | None = None


def tls_expiry(tls: TlsResult) -> list[Finding]:
    """Cert expiring soon -> high; already expired -> high; none -> skip."""
    if tls.error or tls.not_after is None or tls.days_left is None:
        return []
    if tls.days_left < 0:
        return [Finding("high", "tls_expired", "Certificate expired", f"{tls.host}:{tls.port} cert expired {abs(tls.days_left)}d ago")]
    if tls.days_left < 14:
        return [Finding("medium", "tls_expiry", "Certificate expiring soon", f"{tls.host}:{tls.port} cert expires in {tls.days_left}d")]
    return []


def tls_hostname_mismatch(tls: TlsResult, host: str) -> list[Finding]:
    """Cert SAN not covering the probed hostname."""
    if tls.error or not tls.san:
        return []
    sans = {s.lower() for s in tls.san}
    if host.lower() not in sans and not any(s.startswith("*.") and host.lower().endswith(s[2:]) for s in sans):
        return [Finding("medium", "tls_mismatch", "Certificate hostname mismatch", f"cert for {host} does not cover {host}")]
    return []


def email_posture(dns: dns_engine.DnsResult) -> list[Finding]:
    """Missing SPF/DMARC/DKIM posture findings."""
    out: list[Finding] = []
    if not dns.has_spf:
        out.append(Finding("medium", "spf", "Missing SPF record", f"{dns.domain} has no SPF TXT record — spoofing risk"))
    if not dns.has_dmarc:
        out.append(Finding("medium", "dmarc", "Missing DMARC record", f"{dns.domain} has no _dmarc TXT record"))
    elif dns.dmarc_record and "p=none" in dns.dmarc_record.lower():
        out.append(Finding("low", "dmarc_policy", "DMARC policy is p=none", f"{dns.domain} DMARC only monitors, does not reject"))
    if not dns.has_dkim:
        out.append(Finding("low", "dkim", "No DKIM selector found", f"{dns.domain} has no default._domainkey record"))
    return out


def security_headers(http: http_engine.HttpResult) -> list[Finding]:
    """Missing hardening headers on HTTP responses."""
    if http.status is None or http.status >= 500:
        return []
    out: list[Finding] = []
    h = {k.lower(): v for k, v in http.headers.items()}
    if "strict-transport-security" not in h and http.scheme == "https":
        out.append(Finding("low", "hsts", "Missing HSTS header", f"{http.host}:{http.port} serves HTTPS without Strict-Transport-Security"))
    if "x-content-type-options" not in h:
        out.append(Finding("low", "nosniff", "Missing X-Content-Type-Options", f"{http.host}:{http.port} does not send X-Content-Type-Options"))
    if "x-frame-options" not in h and "content-security-policy" not in h:
        out.append(Finding("low", "clickjack", "No clickjacking protection", f"{http.host}:{http.port} has no X-Frame-Options or CSP"))
    if "content-security-policy" not in h:
        out.append(Finding("low", "csp", "Missing CSP header", f"{http.host}:{http.port} has no Content-Security-Policy"))
    return out


def exposed_ports(ports: list[int]) -> list[Finding]:
    """Ports commonly abused when exposed publicly."""
    map = {
        21: ("FTP exposed", "anonymous/login over cleartext"),
        23: ("Telnet exposed", "cleartext admin protocol"),
        3389: ("RDP exposed", "remote desktop on the internet"),
        445: ("SMB exposed", "SMB on the public internet"),
        1433: ("MSSQL exposed", "database listener exposed"),
        3306: ("MySQL exposed", "database listener exposed"),
        5432: ("PostgreSQL exposed", "database listener exposed"),
        6379: ("Redis exposed", "often misconfigured open"),
        9200: ("Elasticsearch exposed", "no-auth data leak risk"),
        27017: ("MongoDB exposed", "often misconfigured open"),
    }
    out: list[Finding] = []
    for port in ports:
        if port in map:
            title, detail = map[port]
            out.append(Finding("high", "exposed_port", title, f"{detail} (port {port})"))
    return out