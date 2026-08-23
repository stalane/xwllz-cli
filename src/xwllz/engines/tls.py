"""TLS certificate inspection via stdlib ssl + cryptography."""

from __future__ import annotations

import asyncio
import ssl
from dataclasses import dataclass, field
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.backends import default_backend


@dataclass
class TlsResult:
    host: str = ""
    port: int = 0
    cn: str | None = None
    san: list[str] = field(default_factory=list)
    issuer: str | None = None
    not_before: datetime | None = None
    not_after: datetime | None = None
    days_left: int | None = None
    error: str | None = None


def parse_cert(der: bytes) -> TlsResult:
    cert = x509.load_der_x509_certificate(der, default_backend())
    try:
        cn = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
    except IndexError:
        cn = None
    try:
        issuer = cert.issuer.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
    except IndexError:
        issuer = None

    san: list[str] = []
    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        san = [name.value for name in ext.value]
    except x509.ExtensionNotFound:
        pass

    not_after = cert.not_valid_after_utc
    days_left = int((not_after - datetime.now(timezone.utc)).total_seconds() // 86400)
    return TlsResult(
        cn=cn,
        san=san,
        issuer=issuer,
        not_before=cert.not_valid_before_utc,
        not_after=not_after,
        days_left=days_left,
    )


async def fetch_cert(host: str, port: int, timeout: float = 6.0) -> TlsResult:
    """Grab the TLS certificate from host:port."""
    result = TlsResult(host=host, port=port)

    def _sync() -> bytes:
        import socket

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        raw = socket.create_connection((host, port), timeout=timeout)
        with ctx.wrap_socket(raw, server_hostname=host) as sock:
            der = sock.getpeercert(binary_form=True)
            if not der:
                raise ValueError("no certificate")
            return der

    try:
        der = await asyncio.get_running_loop().run_in_executor(None, _sync)
        parsed = parse_cert(der)
        parsed.host = host
        parsed.port = port
        return parsed
    except (OSError, ssl.SSLError, ValueError, asyncio.TimeoutError) as exc:
        result.error = str(exc)
        return result


async def fetch_many(
    hosts: list[tuple[str, int]],
    timeout: float = 6.0,
    max_workers: int = 16,
) -> dict[tuple[str, int], TlsResult]:
    """Fetch certs for many (host, port) pairs concurrently."""
    sem = asyncio.Semaphore(max_workers)

    async def one(pair: tuple[str, int]) -> tuple[tuple[str, int], TlsResult]:
        async with sem:
            return pair, await fetch_cert(pair[0], pair[1], timeout)

    results = await asyncio.gather(*(one(p) for p in hosts))
    return dict(results)