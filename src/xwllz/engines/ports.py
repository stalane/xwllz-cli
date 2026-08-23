"""Async TCP port scanner (pure Python, no binaries required)."""

from __future__ import annotations

import asyncio

# Top ~250 common ports; callers can pass an explicit list to extend.
COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 465, 514, 587,
    636, 873, 993, 995, 1025, 1099, 1433, 1521, 1723, 2049, 2082, 2083, 2181,
    2222, 2375, 2376, 3000, 3001, 3128, 3306, 3389, 4369, 5000, 5001, 5060,
    5222, 5432, 5601, 5900, 5984, 5985, 6379, 7001, 8000, 8008, 8009, 8080,
    8081, 8088, 8443, 8888, 9000, 9042, 9090, 9100, 9200, 9300, 9418, 9999,
    10000, 11211, 15672, 27017, 50000, 50070,
]


async def _try_connect(host: str, port: int, timeout: float) -> bool:
    try:
        _reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
        writer.close()
        return True
    except (OSError, asyncio.TimeoutError, ValueError):
        return False


async def scan_host(
    host: str,
    ports: list[int] | None = None,
    timeout: float = 1.0,
    concurrency: int = 256,
) -> list[int]:
    """Return open TCP ports on a host using bounded concurrency."""
    targets = ports or COMMON_PORTS
    sem = asyncio.Semaphore(concurrency)

    async def probe(port: int) -> int | None:
        async with sem:
            if await _try_connect(host, port, timeout):
                return port
        return None

    results = await asyncio.gather(*(probe(p) for p in targets))
    return sorted(p for p in results if p is not None)


async def scan_many(
    hosts: list[str],
    ports: list[int] | None = None,
    timeout: float = 1.0,
    concurrency: int = 256,
    max_workers: int = 32,
) -> dict[str, list[int]]:
    """Scan many hosts concurrently; returns {host: [open ports]}."""
    sem = asyncio.Semaphore(max_workers)

    async def one(host: str) -> tuple[str, list[int]]:
        async with sem:
            return host, await scan_host(host, ports, timeout, concurrency)

    results = await asyncio.gather(*(one(h) for h in hosts))
    return {host: ports for host, ports in results if ports}