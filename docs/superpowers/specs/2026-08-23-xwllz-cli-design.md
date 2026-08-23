# xwllz CLI — Design Spec

Date: 2026-08-23
Status: Approved (design approved by user; implementation complete)

## Overview

A new open-source Python CLI, **`xwllz`**, for **blue-team attack-surface
management** (ASM): discover, monitor, and report on an organization's own
external perimeter — domains, subdomains, IPs, services, certificates, and
exposure points. It is a separate project/repo from the `xwllz` marketing site,
built to be distributable via PyPI with zero required system binaries.

## Goals

- OSS-distributable ASM CLI: works on any machine with Python ≥3.10 only.
- Keyless data sources by default; optional keyed API enrichment when the user
  supplies keys.
- Optional accelerators: detect installed binaries (nmap, masscan, rustscan,
  nuclei, httpx, dnsx, dig) and use them when present, degrading gracefully to
  pure-Python paths otherwise.
- Full ASM loop: discover → store → monitor (diff) → report.

## Non-goals

- Real product copy/branding, docs site, multi-language support.
- Cloud deployment, SaaS, API server.
- Offensive/red-team functionality (this is a blue-team tool).

## Architecture

Approach A chosen (from brainstorm): **pure-Python core with optional tool
accelerators and optional keyed APIs**.

Repo: `/home/david/Documents/xwllz-cli` (package name `xwllz`, PyPI-distributable).

### Dependencies (runtime)
`typer` (CLI), `rich` (output), `httpx` (HTTP probing + API calls),
`dnspython` (DNS), `cryptography` (TLS/cert parsing). No system binaries required.

### Layout
```
src/xwllz/
  cli.py          Typer app, all subcommands, rich output
  db.py           SQLite schema + migrations + upsert helpers
  config.py       env-key loading + PATH tool detection
  discovery.py    ASM pipeline (gather→resolve→scan→probe→detect→store)
  detectors.py    passive blue-team findings
  report.py       markdown/JSON/HTML renderers
  intel.py        indicator lookup logic (URLhaus/VT/Shodan/urlscan)
  sources/crt_sh.py   keyless cert-transparency subdomain harvest
  sources/keyed.py    Shodan, SecurityTrails, Censys, URLhaus, urlscan, VT
  engines/dns.py      dnspython A/NS/MX/SPF/DMARC/DKIM
  engines/ports.py    async socket port scanner (pure Python)
  engines/http.py     httpx HTTP/HTTPS probing + tech detection
  engines/tls.py      ssl + cryptography cert inspection
  integrations/       optional nmap/nuclei/dnsx wrappers (auto-detect)
tests/              mocked unit tests (no live calls)
```

### Storage
SQLite at `~/.local/share/xwllz/xwllz.db` (XDG data dir). Schema:
`orgs`, `assets`, `services`, `findings`, `snapshots`, `intel`.
Findings dedupe on org+kind+asset+service+title with NULLs coerced to 0 via a
partial unique index (SQLite NULL-distinct gotcha handled).

## Data sources & tool selection (blue team)

| Phase | Pure-Python default | Optional accelerator | Keyed enrichment |
|---|---|---|---|
| Subdomain enum | crt.sh CT + DNS | dnsx brute | SecurityTrails, Shodan, Censys |
| DNS posture | dnspython (SPF/DMARC/DKIM) | dig | — |
| Port/service scan | async socket scan | nmap, masscan, rustscan | Shodan host data |
| HTTP fingerprint | httpx probe (title/headers/tech) | httpx bin, whatweb | — |
| TLS/cert | ssl + cryptography (expiry, SAN) | openssl | Censys |
| Exposure checks | passive rules | nuclei templates | — |
| Threat intel | — | — | URLhaus, urlscan, VirusTotal |

Blue-team differentiator: built-in **posture findings** — missing SPF/DMARC/DKIM,
expiring/expired certs, missing security headers (HSTS/CSP/nosniff/clickjack),
and exposed high-risk ports (RDP/SMB/FTP/DB listeners).

## Command surface

```
xwllz init <org> --domains d1,d2
xwllz discover <org> [--passive] [--ports N] [--no-nmap]
xwllz monitor <org> [--passive]          # re-scan + snapshot diff
xwllz report <org> --format md|json|html
xwllz status <org>                       # surface dashboard
xwllz intel <indicator>                  # URL/domain/IP lookup
xwllz whois <domain>
xwllz cert <host> [--port N]
```

## Error handling / resilience

- Per-phase isolation: a failing phase never aborts the run (try/except +
  `# noqa: BLE001, S112` documented).
- Missing tool → silent fallback to pure-Python path; missing API key → source
  skipped.
- Network errors → caught, source returns None; DNS failures → empty result.
- `KeyboardInterrupt` handled in `discover`/`monitor`.

## Testing

- `pytest` (29 tests): DB upsert/dedupe, detectors, report rendering, discovery
  pipeline with all network functions mocked (no live calls), config/key/tool
  detection.
- `ruff` lint clean.
- Live smoke test on a new keyless target (`example.com`, passive): crt.sh
  harvest (800 subdomains), DNS resolution, SPF/DMARC findings — verified.
- CI: GitHub Actions on 3.10/3.12/3.14 (`pytest`).

## Verified behavior

- `xwllz --help`, `init`, `status`, `report`, `discover --passive` all run.
- Engines verified against a local HTTP service (port scan → probe → detectors).
- Live passive discover on example.com produced SPF + DMARC findings.

## Deferred

- GitHub Actions PyPI publish (v1 later).
- nuclei integration wiring into the findings pipeline (wrapper exists, not yet
  invoked from `discover`).
- HTTPS-on-nonstandard-port TLS probing (only 443/8443 currently).