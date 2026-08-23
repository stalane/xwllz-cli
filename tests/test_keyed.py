"""Tests for keyed API source wrappers — no live calls."""

import asyncio

from xwllz.config import Config
from xwllz.sources.keyed import (
    CensysSource,
    SecurityTrailsSource,
    ShodanSource,
    URLhausSource,
)


def _cfg(**keys):
    return Config(keys=keys)


def test_censys_disabled_returns_none_without_keys():
    # No Censys keys configured -> must skip gracefully, never crash.
    src = CensysSource(_cfg())
    assert not src.enabled
    result = asyncio.run(src.search_certificates("example.com"))
    assert result is None


def test_censys_disabled_with_partial_keys():
    # Only ID present (no secret) -> still disabled.
    src = CensysSource(_cfg(censys="id123"))
    assert not src.enabled
    result = asyncio.run(src.search_certificates("example.com"))
    assert result is None


def test_shodan_disabled_returns_none():
    src = ShodanSource(_cfg())
    assert not src.enabled
    assert asyncio.run(src.host("1.2.3.4")) is None
    assert asyncio.run(src.domain_subdomains("example.com")) is None


def test_securitytrails_disabled_returns_none():
    src = SecurityTrailsSource(_cfg())
    assert not src.enabled
    assert asyncio.run(src.subdomains("example.com")) is None


def test_urlhaus_lookup_without_keys():
    # URLhaus is keyless; a malformed host returns a handled None, not a crash.
    src = URLhausSource(_cfg())
    result = asyncio.run(src.lookup("example.com", "domain"))
    # Without network this either returns a dict or None — but must not raise.
    assert result is None or isinstance(result, dict)


def test_censys_enabled_only_when_both_keys():
    src = CensysSource(_cfg(censys="id", censys_secret="secret"))
    assert src.enabled