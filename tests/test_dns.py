"""DNS posture engine tests — quote stripping, no live network."""

from xwllz.engines import dns


class _Rec:
    def __init__(self, s: str):
        self._s = s

    def __str__(self) -> str:
        return self._s


def _install_fake_resolver(monkeypatch, mapping):
    """Make dns.resolver.Resolver().resolve() return canned answers by rtype."""
    class FakeResolver:
        lifetime = 5.0
        timeout = 5.0

        def resolve(self, domain, rtype):
            import dns.resolver as dr
            vals = mapping.get(rtype, [])
            if not vals:
                raise dr.NoAnswer
            return [_Rec(v) for v in vals]

    monkeypatch.setattr(
        "xwllz.engines.dns.dns.resolver.Resolver",
        lambda configure=True: FakeResolver(),
    )


def test_query_strips_txt_quotes(monkeypatch):
    _install_fake_resolver(monkeypatch, {"TXT": ['"v=spf1 -all"']})
    assert dns._query("example.com", "TXT") == ["v=spf1 -all"]


def test_query_does_not_strip_non_txt(monkeypatch):
    _install_fake_resolver(monkeypatch, {"A": ["1.2.3.4."]})
    assert dns._query("example.com", "A") == ["1.2.3.4"]


def test_check_posture_detects_unquoted_records(monkeypatch):
    monkeypatch.setattr("xwllz.engines.dns.resolve_ips", lambda domain, timeout=5.0: ["1.2.3.4"])

    def fake_query(domain, rtype, timeout=5.0):
        # Real _query strips TXT quotes, so these are unquoted already.
        if rtype == "TXT" and domain == "example.com":
            return ["v=spf1 include:_spf.mx.cloudflare.net ~all"]
        if rtype == "TXT" and domain == "_dmarc.example.com":
            return ["v=DMARC1; p=none"]
        if rtype == "TXT" and domain == "default._domainkey.example.com":
            return ["v=DKIM1; k=rsa; p=abc"]
        return []

    monkeypatch.setattr("xwllz.engines.dns._query", fake_query)
    result = dns.check_posture("example.com")
    assert result.has_spf is True
    assert result.spf_record == "v=spf1 include:_spf.mx.cloudflare.net ~all"
    assert result.has_dmarc is True
    assert result.dmarc_record == "v=DMARC1; p=none"
    assert result.has_dkim is True
