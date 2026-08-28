<!-- agents:start -->
## graphify

This project has a knowledge graph at graphify-out/ with god nodes, community structure, and cross-file relationships.

When the user types `/graphify`, use the installed graphify skill or instructions before doing anything else.

Rules:
- For codebase questions, first run `graphify query "<question>"` when graphify-out/graph.json exists. Use `graphify path "<A>" "<B>"` for relationships and `graphify explain "<concept>"` for focused concepts. These return a scoped subgraph, usually much smaller than GRAPH_REPORT.md or raw grep output.
- Dirty graphify-out/ files are expected after hooks or incremental updates; dirty graph files are not a reason to skip graphify. Only skip graphify if the task is about stale or incorrect graph output, or the user explicitly says not to use it.
- If graphify-out/wiki/index.md exists, use it for broad navigation instead of raw source browsing.
- Read graphify-out/GRAPH_REPORT.md only for broad architecture review or when query/path/explain do not surface enough context.
- After modifying code, run `graphify update .` to keep the graph current (AST-only, no API cost).

## Code style

- Follow the codebase's existing conventions: mimic the style, use the same libraries and utilities, and follow the patterns already in place.
- Never assume a library is available — check the codebase first (package.json, pyproject.toml, or imports in neighboring files) before using it.
- When creating a new component, study existing components first and match their framework choice, naming, typing, and conventions.
- Do not add code comments unless asked.
- Follow security best practices: never log, print, or commit secrets or keys.

## Verification before completion

- Before declaring work done, run the project's tests and any lint/typecheck commands and confirm the output — do not claim success without seeing it.
- Find the correct command from the README or existing config rather than guessing the framework.
- A failing test is an open drain: fix it (or explicitly record it out of scope) before moving on, and keep the suite green at the end of the session.

## Reusable build recipes (xwllz landing page + CLI + docs)

Proven end-to-end on the xwllz build (2026-08-23). These are repeatable methods.

### 1. X-wall / dark-tech single-page site (inline SVG backdrop)

- Embed the hero SVG **inline** in HTML inside `<div class="bg">` with
  `position: fixed; inset: 0; z-index: -1`, `preserveAspectRatio="xMidYMid slice"`.
  The SVG's own center-fade mask already clears room for centered content.
- To make the busy background "more opaque", add a `.bg-overlay` div
  (`position:absolute; inset:0; background: rgba(5,5,6,0.93)`) over the SVG —
  near-solid overlay dims the pattern while logo/buttons keep their accent.
- Palette from the SVG itself: near-black `#050506`–`#14161c`, accent `#4a90e2`
  blue, text `#e0e6ed`, muted `#aab4c6`. Monospace (`SFMono-Regular, Consolas…`)
  for wordmark/labels/terminal.
- Glassy panels: `rgba(10,11,13,0.55)` + `1px rgba(74,144,226,0.25)` border +
  `backdrop-filter: blur(8px)`. Primary = solid blue, ghost = blue border.
- Light JS: IntersectionObserver reveal (add `.visible`, unobserve), mobile nav
  toggle, auto footer year. Respect `prefers-reduced-motion`.

### 2. VERIFY ANY RENDER — the model can't see screenshots

Headless Chrome dumps/screenshots are unviewable by the model. Verify programmatically:

```bash
google-chrome --headless=new --disable-gpu --no-sandbox --window-size=1440,900 \
  --screenshot=/tmp/opencode/s.png "file:///path/index.html"
python3 - <<'EOF'
from PIL import Image
im = Image.open("/tmp/opencode/s.png").convert("RGB"); px = im.load()
blue=dark=light=0
for y in range(0,im.height,6):
  for x in range(0,im.width,6):
    r,g,b=px[x,y]
    if b>90 and b>r+40 and b>g+20: blue+=1
    elif r<40 and g<40 and b<40: dark+=1
    elif r>150 and g>150 and b>150: light+=1
print(blue,dark,light)
EOF
```

- Presence of blue accents (`#4a90e2`) + light text + dark bg => the design renders.
- Sample at **2px** for thin text (an 8px sample undercounts small strokes).
- Use `--dump-dom` + grep for IDs/content to confirm structure and no console errors.
- JS reveals need scrolling — in `--dump-dom` cards below the 100vh hero stay
  hidden (correct; not a bug). Confirm IO fires with a tiny inline test page.

### 3. Open-source CLI (pure-Python core + optional accelerators + keyed APIs)

The architecture that made xwllz-cli OSS-distributable:

- **Pure-Python core** so it works with zero system binaries: async socket port
  scan, `httpx` HTTP probing, `dnspython` DNS/SPF-DMARC-DKIM, `cryptography`
  TLS/cert. Deps: `typer`, `rich`, `httpx`, `dnspython`, `cryptography`.
- **Optional accelerators**: detect `nmap`/`masscan`/`rustscan`/`nuclei`/
  `httpx`/`dnsx` on PATH (`shutil.which`) and shell out when present; fall back
  to pure-Python otherwise. Never fail on a missing tool.
- **Keyless-by-default**, optional keyed sources (Shodan/Censys/SecurityTrails/
  URLhaus/urlscan/VT) gated on env keys; a missing key skips the source.
- SQLite via stdlib (`~/.local/share/xwllz/xwllz.db`). Schema: orgs/assets/
  services/findings/snapshots/intel. Findings dedupe with NULLs coerced to 0 via
  a **partial unique index** (plain `UNIQUE` treats NULLs as distinct -> dupes).
- Commands: init/discover/monitor(diff)/report/status/intel.
- Tests: mock ALL network functions (no live calls), `pytest` + `ruff`.
- Packaging: `pyproject.toml` (hatchling), `[project.scripts]`, MIT, CI workflow.

### 4. Publishing an OSS CLI (GitHub + PyPI via uv)

- **GitHub**: `gh repo create <owner>/<name> --public --source . --push`
  (pick the owner per the operator's GitHub-accounts rules).
- **PyPI**: build + publish with `uv` (no twine/.pypirc needed):
  ```
  uv build
  set -a; source ~/.env; set +a     # UV_PUBLISH_TOKEN lives here
  uv publish                          # or: uv publish dist/<ver>.tar.gz dist/<ver>.whl
  ```
  Publish **specific files**; `uv publish` with no args uploads everything in
  `dist/`, so stale earlier versions get re-uploaded (fails). Clean `dist/` or
  pass explicit files. Verify in a fresh venv: `pip install <pkg>`.
- Bump `version` in pyproject.toml AND `__version__` in the package.

### 5. Branded SVG diagrams for READMEs (no diagram tools installed)

No mmdc/inkscape/convert on this machine. GitHub renders SVG natively via
relative links, so hand-author diagrams:

- Copy the site `logo.svg` into the repo `docs/`, reference `<img src="docs/logo.svg">`.
- Hand-write `docs/architecture.svg` + `docs/pipeline.svg` in the **dark X-wall
  style** (near-black `#0a0b0d` panels, `#4a90e2` strokes/arrows, monospace
  labels, dashed panel = "optional"). 1600x900 viewBox, `<marker>` arrowheads.
- Validate: `python3 -c "import xml.dom.minidom as m; m.parse('f.svg')"`, then
  the headless render + pixel check from recipe #2 (dark bg + blue present).
- README: centered `<p align="center"><img src="docs/x.svg" width="800">`,
  badge row, then weave diagrams into "How it works" / "The loop" sections.
<!-- agents:end -->
