"""DNS posture checks and resolution via dnspython (pure Python)."""

from __future__ import annotations

from dataclasses import dataclass, field

import dns.resolver


@dataclass
class DnsResult:
    domain: str
    ips: list[str] = field(default_factory=list)
    mx: list[str] = field(default_factory=list)
    ns: list[str] = field(default_factory=list)
    has_spf: bool = False
    spf_record: str | None = None
    has_dmarc: bool = False
    dmarc_record: str | None = None
    has_dkim: bool = False


def _query(domain: str, rtype: str, timeout: float = 5.0) -> list[str]:
    """Query a record type; return values or [] on any failure."""
    resolver = dns.resolver.Resolver(configure=True)
    resolver.lifetime = timeout
    resolver.timeout = timeout
    try:
        answers = resolver.resolve(domain, rtype)
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.exception.DNSException):
        return []
    values = [str(r).rstrip(".") for r in answers]
    if rtype == "TXT":
        # dnspython renders TXT values with surrounding double quotes.
        values = [v.strip('"') for v in values]
    return values


def resolve_ips(domain: str, timeout: float = 5.0) -> list[str]:
    """A/AAAA records for a domain, deduped."""
    seen: list[str] = []
    for rtype in ("A", "AAAA"):
        for value in _query(domain, rtype, timeout):
            if value not in seen:
                seen.append(value)
    return seen


def check_posture(domain: str, timeout: float = 5.0) -> DnsResult:
    """Gather DNS records and email-security posture (SPF/DMARC/DKIM)."""
    result = DnsResult(domain=domain)
    result.ips = resolve_ips(domain, timeout)
    result.mx = _query(domain, "MX", timeout)
    result.ns = _query(domain, "NS", timeout)

    spf = _query(domain, "TXT", timeout)
    spf = [t for t in spf if t.startswith("v=spf1")]
    if spf:
        result.has_spf = True
        result.spf_record = spf[0]

    dmarc = _query(f"_dmarc.{domain}", "TXT", timeout)
    dmarc = [t for t in dmarc if t.startswith("v=DMARC1")]
    if dmarc:
        result.has_dmarc = True
        result.dmarc_record = dmarc[0]

    dkim = _query(f"default._domainkey.{domain}", "TXT", timeout)
    if dkim:
        result.has_dkim = True

    return result