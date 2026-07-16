# Basilisk

Installable CLI vulnerability scanner: crawl a site, run passive security checks, then actively fuzz forms for SQLi and XSS.

> **Use only on systems you own or have explicit permission to test.** Unauthorized scanning is illegal.

## Install

```bash
git clone <your-repo-url>
cd Basilisk
pip install -e .
```

Requires Python 3.10+.

## Usage

```bash
basilisk scan https://example.com
basilisk scan https://example.com --max-pages 10 --no-active
basilisk login https://example.com --endpoint /login
```

Or without installing:

```bash
python -m basilisk scan https://example.com
```

| Option | Description |
|--------|-------------|
| `-n` / `--max-pages` | Crawl page limit (default: 15) |
| `--no-active` | Passive checks only (skip form fuzzing) |
| `-t` / `--timeout` | Request timeout in seconds |
| `-e` / `--endpoint` | Login path for `basilisk login` |

Exit code `1` when high-severity issues are found.

## Project layout

```
basilisk/
  cli.py       # Typer + Rich terminal UI
  core.py      # Scan orchestrator
  http.py      # HTTP session engine
  parser.py    # Link / form extraction
  passive.py   # Header & secret audits
  attack.py    # Payloads, judge, active fuzzer
```

## Development

```bash
pip install -e .
basilisk --help
```
