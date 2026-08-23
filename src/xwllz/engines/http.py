"""HTTP/HTTPS probing with httpx (pure Python)."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

import httpx

TECH_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("nginx", re.compile(r"nginx[/\s]", re.IGNORECASE)),
    ("apache", re.compile(r"apache", re.IGNORECASE)),
    ("iis", re.compile(r"microsoft-iis", re.IGNORECASE)),
    ("cloudflare", re.compile(r"cloudflare", re.IGNORECASE)),
    ("wordpress", re.compile(r"wp-content|wordpress", re.IGNORECASE)),
    ("drupal", re.compile(r"drupal", re.IGNORECASE)),
    ("next.js", re.compile(r"__next_data__|next\.js", re.IGNORECASE)),
    ("react", re.compile(r"_next/static", re.IGNORECASE)),
    ("express", re.compile(r"express", re.IGNORECASE)),
    ("python", re.compile(r"python|gunicorn|werkzeug", re.IGNORECASE)),
    ("java", re.compile(r"tomcat|jetty|spring", re.IGNORECASE)),
    ("php", re.compile(r"php/|x-powered-by:\s*php", re.IGNORECASE)),
]


@dataclass
class HttpResult:
    host: str
    port: int
    scheme: str
    status: int | None = None
    title: str | None = None
    tech: list[str] = field(default_factory=list)
    server: str | None = None
    headers: dict[str, str] = field(default_factory=dict)
    error: str | None = None


def detect_tech(server: str | None, body: str, headers: dict[str, str]) -> list[str]:
    found: list[str] = []
    for name, pattern in TECH_PATTERNS:
        if name == "cloudflare" and (server and pattern.search(server)) or pattern.search(body[:200_000]):
            found.append(name)
    # power-by header
    powered = headers.get("x-powered-by") or headers.get("x-generator")
    if powered:
        found.append(powered)
    return list(dict.fromkeys(found))


def extract_title(html: str) -> str | None:
    m = re.search(r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
    if not m:
        return None
    title = re.sub(r"\s+", " ", m.group(1)).strip()
    return title[:200] or None


async def probe(
    host: str,
    port: int,
    timeout: float = 8.0,
) -> HttpResult:
    """Probe HTTP and/or HTTPS on a host:port. Returns the better result."""
    candidates = [("https", f"https://{host}:{port}", 443), ("http", f"http://{host}:{port}", 80)]

    best: HttpResult | None = None
    async with httpx.AsyncClient(
        verify=False,
        follow_redirects=True,
        timeout=timeout,
        headers={"User-Agent": "xwllz/0.1 (attack-surface management)"},
    ) as client:
        for scheme, url, _default_port in candidates:
            result = HttpResult(host=host, port=port, scheme=scheme)
            try:
                resp = await client.get(url)
                result.status = resp.status_code
                result.headers = dict(resp.headers)
                result.server = resp.headers.get("server")
                result.title = extract_title(resp.text)
                result.tech = detect_tech(result.server, resp.text, result.headers)
                if best is None or (result.status is not None and best.status is None):
                    best = result
                elif best.status is not None and result.status is not None and result.title:
                    best = result  # prefer the one that gave us content
            except httpx.HTTPError as exc:
                result.error = str(exc)
                if best is None:
                    best = result
            if scheme == "http" and best is not None and best.status is not None and best.title:
                break
    if best is None:
        best = HttpResult(host=host, port=port, scheme="http")
    return best