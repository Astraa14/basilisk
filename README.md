# Basilisk

Installable CLI vulnerability scanner for **web apps**, structured like [HackAgent](https://github.com/AISecurityLab/hackagent): **Attack Engine**, **Generator**, **Judge**, **Target**, and **Datasets**.

> **Use only on systems you own or have explicit permission to test.** Unauthorized scanning is illegal.

## Install

```bash
git clone <your-repo-url>
cd Basilisk
pip install -e .
cp .env.example .env
# edit .env and set BASILISK_LLM_API_KEY=...
```

Requires Python 3.10+.

## LLM roles (HackAgent-style)

When an LLM backend is available, Basilisk uses the same **role split** as HackAgent:

| Role | What it does |
|------|----------------|
| **Generator** | LLM creates adversarial SQLi/XSS payloads for each form (datasets are seeds only) |
| **Judge** | LLM decides if the Target's HTTP response means the attack succeeded |
| **Target** | Your live web app (HTTP) |
| **Datasets** | Static seed templates + optional `--dataset` |

Backend resolution order:

1. Cloud / OpenAI-compatible key in `.env` (`BASILISK_LLM_API_KEY` + `BASILISK_LLM_BASE_URL`)
2. Else local **Ollama** at `http://localhost:11434` (no paid key — same idea as HackAgent)

```bash
# With .env key -> full Generator + Judge pipeline
basilisk scan https://example.com

# Force static-only
basilisk scan https://example.com --no-llm
```

Create `.env` from `.env.example` (never commit real keys).

| Variable | Default | Purpose |
|----------|---------|---------|
| `BASILISK_LLM_API_KEY` | (cloud) or `ollama` | API key |
| `BASILISK_LLM_BASE_URL` | provider URL or Ollama `/v1` | OpenAI-compatible base |
| `BASILISK_LLM_MODEL` | `gpt-4o-mini` / `llama3.2` | Model name |

Exit code `1` when high-severity issues are found; `2` on LLM config/API errors.

## Architecture

```
Datasets -> Attack Engine -> Generator -> Target (HTTP) -> Judge -> Report
                ^
              Recon (crawl + passive)
```

| Role | Module |
|------|--------|
| Attack Engine | `basilisk/engine.py` |
| Generator | `basilisk/generator.py` (static + optional LLM) |
| Judge | `basilisk/judge.py` (heuristic + optional LLM) |
| Target | `basilisk/target.py` |
| Datasets | `basilisk/datasets/*.json` |
| Recon | `basilisk/recon.py` |

## Development

```bash
pip install -e .
basilisk --help
```
