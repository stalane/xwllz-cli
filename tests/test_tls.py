"""TLS engine tests — cert parsing with no live network."""

from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from xwllz.engines.tls import TlsResult, parse_cert


def _make_cert(hostname: str = "example.com") -> bytes:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(hostname)]),
            critical=False,
        )
        .sign(key, hashes.SHA256(), default_backend())
    )
    return cert.public_bytes(serialization.Encoding.DER)


def test_tlsresult_can_build_without_host_port():
    # Regression: parse_cert constructs TlsResult without host/port.
    tls = TlsResult()
    assert tls.host == ""
    assert tls.port == 0


def test_parse_cert_returns_host_port_defaults():
    result = parse_cert(_make_cert())
    assert result.cn == "example.com"
    assert result.san == ["example.com"]
    assert result.host == ""  # caller overrides after parse
    assert result.port == 0
    assert result.days_left is not None and result.days_left > 0
