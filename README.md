# Basilisk 🐍

**Standalone local CLI vulnerability scanner for AI-made and AI-assisted web applications.**

> **Authorization required.** Only scan systems you own or have explicit written permission to test. Unauthorized scanning is illegal.

---

## What is Basilisk?

Basilisk is an **installable, offline-first security scanner** you run entirely on your own machine. It needs no account, no cloud dashboard, no backend service, and no internet access beyond reaching the target you specify.

- No Basilisk account required
- No results uploaded automatically
- No external Basilisk server contacted
- Everything stays on your filesystem by default

---

## Install

```bash
git clone https://github.com/Astraa14/basilisk
cd basilisk
pip install -e .
```

Requires **Python 3.10+**.

Optional extras:

```bash
pip install -e ".[llm]"        # OpenAI-compatible LLM support
pip install -e ".[all]"        # All optional features
```

---

## Quick Start

```bash
# Basic scan (static/heuristic mode — no LLM required)
basilisk scan https://example.com

# Save a JSON report
basilisk scan https://example.com --output report.json

# Save an HTML report
basilisk scan https://example.com --output report.html

# Save both to a directory (auto-named files)
basilisk scan https://example.com --output-dir ./reports/

# Force static-only (ignore any configured LLM key)
basilisk scan https://example.com --no-llm

# Probe a login endpoint for SQLi
basilisk login https://example.com --endpoint /auth/login

# Machine-readable JSON output
basilisk scan https://example.com --json
```

---

## LLM Support (Optional)

Basilisk works without any LLM. LLM mode enables an adversarial generator+judge pipeline for smarter payload generation.

### Option 1 – Local Ollama (free, no API key)

```bash
# Install and start Ollama
ollama serve
ollama pull llama3.2

# Basilisk auto-detects Ollama at http://localhost:11434
basilisk scan https://example.com
```

### Option 2 – Cloud / OpenAI-compatible provider

```bash
cp .env.example .env
# Edit .env:
# BASILISK_LLM_API_KEY=sk-...
# BASILISK_LLM_BASE_URL=https://api.openai.com/v1
# BASILISK_LLM_MODEL=gpt-4o-mini

basilisk scan https://example.com
```

### Option 3 – No LLM (always works)

```bash
basilisk scan https://example.com --no-llm
```

### Environment variables

| Variable | Default | Purpose |
|---|---|---|
| `BASILISK_LLM_API_KEY` | — | API key for LLM provider (or `ollama` for local) |
| `BASILISK_LLM_BASE_URL` | provider URL or `http://localhost:11434/v1` | OpenAI-compatible base URL |
| `BASILISK_LLM_MODEL` | `gpt-4o-mini` / `llama3.2` | Model name |

---

## Output Formats

| Format | How |
|---|---|
| Live Local Web UI | Default — code-authenticated ephemeral web session (`http://127.0.0.1:<port>`) |
| Terminal (Rich) | Default — live CLI output |
| JSON file | `--output result.json` |
| HTML report | `--output report.html` |
| Auto-directory | `--output-dir ./reports/` (writes `.json` + `.html`) |
| Stdout JSON | `--json` (pipe-friendly, suppresses Rich & Web UI) |

---

## Live Local Web Dashboard

When starting a scan (`basilisk scan <url>`), Basilisk automatically launches an **ephemeral local web dashboard**:

- **Passcode Authenticated:** The CLI process generates a one-time session code (e.g. `BSK-XK8912`) displayed in your terminal.
- **Real-Time Stream:** Live metrics, vulnerabilities as they are detected, and terminal console logs stream to your browser.
- **Self-Destructs On Exit:** When the CLI scan completes or the terminal process is terminated, the local web server closes immediately. Refreshing the browser page will show the session as expired.

To disable the local web dashboard:
```bash
basilisk scan https://example.com --no-ui
```

---

## Exit Codes

| Code | Meaning |
|---|---|
| `0` | Scan completed, no high/critical findings |
| `1` | Scan completed, high or critical findings detected |
| `2` | Configuration or runtime error (LLM config, invalid URL, etc.) |
| `130` | Interrupted by user (Ctrl+C) |

---

## Scan Options

```
basilisk scan --help
```

Key options:

| Option | Description |
|---|---|
| `--max-pages N` | Crawl limit (default: 15) |
| `--no-active` | Passive audit only (no form fuzzing) |
| `--no-url-fuzz` | Skip URL parameter fuzzing |
| `--timeout N` | HTTP request timeout in seconds |
| `--proxy URL` | Route through HTTP/SOCKS5 proxy |
| `--no-verify-tls` | Disable TLS certificate validation |
| `--auth-bearer TOKEN` | Bearer token for Authorization header |
| `--cookie 'k=v; k2=v2'` | Custom cookies |
| `--header 'X-Foo: bar'` | Custom headers (repeatable) |
| `--no-llm` | Static-only, never calls LLM |
| `--llm` | Force LLM mode |
| `--no-protocol-scan` | Skip transport-layer checks (DNS, TLS, etc.) |

---

## Architecture

```
Target URL
  └─▶ Recon (crawl + passive headers)
        └─▶ Attack Engine
              ├─▶ Generator (static templates or LLM)
              ├─▶ HTTP execution (RequestEngine)
              └─▶ Judge (heuristic or LLM)
                    └─▶ Report (terminal / JSON / HTML)
```

| Component | Module |
|---|---|
| Scanner facade | `basilisk/core.py` |
| Attack Engine | `basilisk/engine.py` |
| Generator | `basilisk/generator.py` |
| Judge | `basilisk/judge.py` |
| HTTP client | `basilisk/http.py` |
| Recon / crawler | `basilisk/recon.py` |
| Datasets | `basilisk/datasets/*.json` |
| LLM client | `basilisk/llm.py` |
| Reporter | `basilisk/reporter.py` |

---

## Privacy & Security

- **No automatic uploads.** Scan results never leave your machine unless you explicitly choose to share them.
- **No target URLs sent to Basilisk.** The scanner runs entirely locally.
- **API keys are not logged.** `BASILISK_LLM_API_KEY` is never written to reports or output files.
- **Temporary files** (cookie jars, request logs) are written only to paths you specify.
- **HTTP headers** containing `Authorization` or `Cookie` values are not included in HTML/JSON reports.

---

## Development

```bash
pip install -e .
pytest tests/ -v
basilisk --help
```

---

## Docker

```bash
docker build -t basilisk .
docker run --rm basilisk scan https://example.com --no-llm
```

---

## License

MIT — see [LICENSE](./LICENSE).
