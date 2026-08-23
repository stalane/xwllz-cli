"""Configuration: API keys from env vars, optional tool detection on PATH."""

from __future__ import annotations

import os
import shutil
from dataclasses import dataclass, field

ENV_KEYS: dict[str, str] = {
    "shodan": "SHODAN_API_KEY",
    "securitytrails": "SECURITYTRAILS_API_KEY",
    "censys": "CENSYS_API_ID",
    "censys_secret": "CENSYS_API_SECRET",
    "urlscan": "URL_SCAN_API_KEY",
    "urlhaus": "URLHAUS_API_KEY",
    "virustotal": "VIRUSTOTAL_API_KEY",
}

# Optional binaries that accelerate phases when present.
TOOLS: list[str] = [
    "nmap",
    "masscan",
    "rustscan",
    "nuclei",
    "httpx",
    "dnsx",
    "dig",
    "whatweb",
    "openssl",
]


@dataclass
class Config:
    """Resolved runtime configuration."""

    keys: dict[str, str | None] = field(default_factory=dict)
    tools: dict[str, str | None] = field(default_factory=dict)
    http_timeout: float = 8.0
    dns_timeout: float = 5.0
    port_scan_concurrency: int = 256
    max_workers: int = 32

    def has(self, name: str) -> bool:
        return bool(self.keys.get(name))

    def tool(self, name: str) -> str | None:
        """Path to an optional tool, or None if not installed."""
        return self.tools.get(name)


def load_config() -> Config:
    cfg = Config()
    cfg.keys = {name: os.getenv(var) or None for name, var in ENV_KEYS.items()}
    cfg.tools = {name: shutil.which(name) for name in TOOLS}
    return cfg