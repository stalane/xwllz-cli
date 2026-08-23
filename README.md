# xwllz — Attack-surface management for blue teams

`xwllz` is a CLI for discovering, monitoring, and reporting on your **own external
attack surface**. It maps the domains, subdomains, IPs, services, certificates, and
exposure points an attacker can reach — so blue teams can see their perimeter before
attackers do.

## Quickstart

```bash
pip install xwllz

xwllz init acme --domains example.com,corp.example.com
xwllz discover acme
xwllz monitor acme        # re-scan and show what changed
xwllz report acme --format md
```

No system binaries are required. `xwllz` is pure Python by default; if you have
`nmap`, `masscan`, `rustscan`, `nuclei`, `httpx`, `dnsx`, or `dig` on your PATH,
it will detect and use them as accelerators automatically.

## Data sources

**Keyless by default:** crt.sh (certificate transparency), DNS (A/NS/MX/SPF/DMARC/DKIM),
HTTP probing, TLS/cert inspection, socket port scans.

**Optional keyed enrichment** (set env vars to enable):

| Source | Env vars |
|---|---|
| Shodan | `SHODAN_API_KEY` |
| SecurityTrails | `SECURITYTRAILS_API_KEY` |
| Censys | `CENSYS_API_ID`, `CENSYS_API_SECRET` |
| urlscan.io | `URL_SCAN_API_KEY` |
| URLhaus | `URLHAUS_API_KEY` |
| VirusTotal | `VIRUSTOTAL_API_KEY` |

## Commands

```
xwllz init <org> --domains d1,d2      define the scope to monitor
xwllz discover <org>                  enumerate the attack surface
xwllz monitor <org>                   re-scan and report new/changed/removed
xwllz report <org> --format md|json|html
xwllz status <org>                    current surface dashboard
xwllz intel <indicator>               URL/domain/IP lookup
xwllz whois <domain>                  whois lookup
xwllz cert <host>                     TLS certificate details
```

Data is stored in SQLite at `~/.local/share/xwllz/xwllz.db`.

## License

MIT