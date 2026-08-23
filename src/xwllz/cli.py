"""xwllz CLI — attack-surface management for blue teams."""

from __future__ import annotations

import asyncio
import subprocess
import sys

import typer
from rich.console import Console
from rich.table import Table

from xwllz import db, discovery
from xwllz import intel as intel_mod
from xwllz import report as report_mod
from xwllz.config import load_config

app = typer.Typer(add_completion=False, no_args_is_help=True, help="Attack-surface management for blue teams.")
console = Console()

DEFAULT_PORTS = "top-1000"


@app.command()
def init(
    org: str = typer.Argument(..., help="Org/scope name"),
    domains: str = typer.Option(..., "--domains", help="Comma-separated root domains"),
    db_path: str = typer.Option(None, "--db", help="SQLite database path"),
) -> None:
    """Define a scope to monitor."""
    conn = db.connect(db_path)
    try:
        conn.execute("INSERT INTO orgs (name, domains) VALUES (?, ?)", (org, domains))
        conn.commit()
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]error:[/red] {exc}")
        raise typer.Exit(1)
    console.print(f"[green]✓[/green] org [bold]{org}[/bold] set up for {domains}")
    console.print(f"  next: [bold]xwllz discover {org}[/bold]")


def _load_org(name: str, db_path: str | None):
    conn = db.connect(db_path)
    try:
        org = discovery.load_org(conn, name)
    except KeyError as exc:
        console.print(f"[red]error:[/red] {exc}")
        raise typer.Exit(1) from exc
    return conn, org


@app.command()
def discover(
    org: str = typer.Argument(...),
    passive: bool = typer.Option(False, "--passive", help="Subdomains + DNS posture only, no port scanning"),
    ports: str = typer.Option(DEFAULT_PORTS, "--ports", help="Port list for scanning (nmap format) or 'top-1000'"),
    no_nmap: bool = typer.Option(False, "--no-nmap", help="Force pure-Python port scan"),
    db_path: str = typer.Option(None, "--db"),
) -> None:
    """Enumerate an org's attack surface."""
    conn, org_obj = _load_org(org, db_path)
    cfg = load_config()
    console.print(f"[bold]xwllz discover {org}[/bold] — passive={passive}")
    port_list = None if ports == DEFAULT_PORTS else [int(p) for p in ports.split(",") if p]
    try:
        stats = asyncio.run(
            discovery.run_discovery(
                conn, org_obj, cfg, passive_only=passive, ports=port_list, use_nmap=not no_nmap
            )
        )
    except KeyboardInterrupt:
        console.print("\n[yellow]interrupted[/yellow]")
        raise typer.Exit(130)
    table = Table(title=f"{org} — discovery results")
    table.add_column("Phase", style="cyan")
    table.add_column("Count", justify="right")
    table.add_row("subdomains", str(stats.subdomains))
    table.add_row("hosts resolved", str(stats.hosts_resolved))
    table.add_row("open ports", str(stats.open_ports))
    table.add_row("services probed", str(stats.services_probed))
    table.add_row("findings", str(stats.findings))
    console.print(table)
    console.print(f"next: [bold]xwllz monitor {org}[/bold] or [bold]xwllz report {org}[/bold]")


@app.command()
def monitor(
    org: str = typer.Argument(...),
    passive: bool = typer.Option(False, "--passive"),
    ports: str = typer.Option(DEFAULT_PORTS, "--ports"),
    db_path: str = typer.Option(None, "--db"),
) -> None:
    """Re-run discovery and show what changed since the last snapshot."""
    conn, org_obj = _load_org(org, db_path)
    cfg = load_config()
    baseline = conn.execute(
        "SELECT id FROM snapshots WHERE org_id = ? ORDER BY id DESC LIMIT 1",
        (org_obj.id,),
    ).fetchone()
    console.print(f"[bold]xwllz monitor {org}[/bold]")
    port_list = None if ports == DEFAULT_PORTS else [int(p) for p in ports.split(",") if p]
    try:
        stats = asyncio.run(discovery.run_discovery(conn, org_obj, cfg, passive_only=passive, ports=port_list))
    except KeyboardInterrupt:
        console.print("\n[yellow]interrupted[/yellow]")
        raise typer.Exit(130)

    if baseline is None:
        console.print("[green]first snapshot taken[/green] — no baseline to diff against")
    else:
        diff = discovery.diff_snapshots(conn, org_obj, 0)
        table = Table(title="delta vs previous snapshot")
        table.add_column("Metric")
        table.add_column("Before", justify="right")
        table.add_column("After", justify="right")
        table.add_column("Δ", justify="right")
        for key, label in (("assets", "assets"), ("services", "services"), ("findings", "findings")):
            prev_n = diff[key]["prev"]
            new_n = diff[key]["new"]
            delta = new_n - prev_n
            color = "red" if delta > 0 else ("green" if delta < 0 else "white")
            table.add_row(label, str(prev_n), str(new_n), f"[{color}]{delta:+d}[/{color}]")
        console.print(table)
    console.print(f"new findings recorded this run: [bold]{stats.findings}[/bold]")


@app.command()
def report(
    org: str = typer.Argument(...),
    format: str = typer.Option("md", "--format", "-f", help="md | json | html"),
    output: str = typer.Option(None, "--output", "-o", help="Write to file instead of stdout"),
    db_path: str = typer.Option(None, "--db"),
) -> None:
    """Render a report for an org."""
    if format not in ("md", "json", "html"):
        console.print(f"[red]unsupported format {format!r} (use md|json|html)[/red]")
        raise typer.Exit(1)
    conn = db.connect(db_path)
    try:
        body = report_mod.render(conn, org, format)
    except KeyError as exc:
        console.print(f"[red]error:[/red] {exc}")
        raise typer.Exit(1) from exc
    if output:
        with open(output, "w") as fh:
            fh.write(body)
        console.print(f"[green]✓[/green] wrote {output}")
    else:
        console.print(body)


@app.command()
def status(
    org: str = typer.Argument(...),
    db_path: str = typer.Option(None, "--db"),
) -> None:
    """Show the current surface dashboard for an org."""
    conn, org_obj = _load_org(org, db_path)
    counts = conn.execute(
        """SELECT
             (SELECT COUNT(*) FROM assets WHERE org_id = ? AND status='active'),
             (SELECT COUNT(*) FROM services s JOIN assets a ON s.asset_id=a.id
                 WHERE a.org_id=? AND a.status='active'),
             (SELECT COUNT(*) FROM findings WHERE org_id = ?)""",
        (org_obj.id, org_obj.id, org_obj.id),
    ).fetchone()
    table = Table(title=f"{org} — current surface")
    table.add_column("Metric")
    table.add_column("Value", justify="right")
    table.add_row("active assets", str(counts[0]))
    table.add_row("live services", str(counts[1]))
    table.add_row("open findings", str(counts[2]))
    console.print(table)

    top = conn.execute(
        """SELECT severity, COUNT(*) n FROM findings WHERE org_id=? GROUP BY severity
           ORDER BY CASE severity WHEN 'high' THEN 0 WHEN 'medium' THEN 1 WHEN 'low' THEN 2 ELSE 3 END""",
        (org_obj.id,),
    ).fetchall()
    if top:
        t = Table(title="findings by severity")
        t.add_column("Severity")
        t.add_column("Count", justify="right")
        for row in top:
            t.add_row(row["severity"], str(row["n"]))
        console.print(t)


@app.command()
def intel(
    indicator: str = typer.Argument(...),
    db_path: str = typer.Option(None, "--db"),
) -> None:
    """Look up a URL/domain/IP across enabled intel sources."""
    cfg = load_config()
    conn = db.connect(db_path) if db_path else None
    results = asyncio.run(intel_mod.run_lookup(indicator, cfg, conn))
    if not results:
        console.print("[yellow]no sources enabled — set SHODAN_API_KEY / VIRUSTOTAL_API_KEY / URLHAUS_API_KEY[/yellow]")
        return
    for source, payload in results.items():
        console.print(f"[bold cyan]{source}:[/bold cyan]")
        if source == "urlhaus":
            status = (payload.get("data") or {}).get("query_status")
            console.print(f"  query_status: {status}")
            for url in (payload.get("data") or {}).get("urls", [])[:5]:
                console.print(f"  - {url.get('url')} [{url.get('threat')}]")
        elif source == "virustotal":
            console.print(f"  stats: {payload['stats']}")
        elif source == "shodan":
            console.print(f"  ports: {payload['ports']}  org: {payload['org']}")


@app.command()
def whois(
    domain: str = typer.Argument(...),
) -> None:
    """Look up whois for a domain (requires 'whois')."""
    try:
        out = subprocess.run(["whois", domain], capture_output=True, text=True, timeout=30, check=False)
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        console.print(f"[red]whois unavailable:[/red] {exc}")
        raise typer.Exit(1) from exc
    console.print(out.stdout)


@app.command()
def cert(
    host: str = typer.Argument(...),
    port: int = typer.Option(443, "--port"),
) -> None:
    """Show TLS certificate details for a host."""
    from xwllz.engines.tls import fetch_cert

    result = asyncio.run(fetch_cert(host, port))
    if result.error:
        console.print(f"[red]error:[/red] {result.error}")
        raise typer.Exit(1)
    console.print(f"host:    {result.host}")
    console.print(f"subject: CN={result.cn}")
    console.print(f"issuer:  {result.issuer}")
    console.print(f"expires: {result.not_after} ({result.days_left} days)")
    if result.san:
        console.print(f"sans:    {', '.join(result.san[:8])}")


def main() -> None:
    app()


if __name__ == "__main__":
    sys.exit(main())