# Threat Intel Fusion Platform

Threat Intel Fusion Platform is a defensive SOC/threat-intelligence MVP that turns raw threat report text into analyst-ready intelligence. It extracts indicators, normalizes and deduplicates them, enriches them with safe local heuristics and optional provider APIs, assigns explainable risk scores, clusters related infrastructure, and exports hunt/detection artifacts.

## Features

- IOC extraction from pasted reports or files:
  - IPv4 addresses
  - domains
  - URLs
  - email addresses
  - MD5, SHA1, and SHA256 hashes
- Normalization and deduplication.
- SQLite-backed persistence.
- Explainable confidence and severity scoring.
- Lightweight clustering by domain root, URL host, IP range, and shared tags.
- Optional enrichment hooks for VirusTotal, AbuseIPDB, and OTX via environment variables.
- Exports:
  - STIX 2.1 bundle
  - Sigma rule scaffold
  - Splunk SPL
  - Elastic/KQL query
  - CSV
- Browser dashboard for analyst workflow demos.

## Responsible use

This project is intended for defensive threat-intelligence, SOC, and detection-engineering workflows. It does not execute malware, exploit systems, or provide offensive tradecraft.

## Quick start

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
uvicorn app.main:app --reload
```

Open `http://127.0.0.1:8000` and paste a public threat report or IOC list.

## Security notes

This MVP is designed for local portfolio demos and analyst workflow experimentation. Do not expose it directly to the public internet without adding authentication, authorization, HTTPS, rate limiting, and operational monitoring.

Built-in public-readiness safeguards:

- no provider API keys are stored in the repo; optional keys are read from environment variables only
- `.env`, local databases, virtual environments, and build artifacts are gitignored
- browser security headers are applied to app responses
- intake text, source names, and export indicator filters have size limits
- CORS is not enabled by default

Interactive API docs are enabled for local development. Disable them before deployment:

```bash
export TIFP_ENABLE_DOCS=false
```

## Optional provider API keys

The app works without third-party credentials. To enable external enrichment, copy `.env.example` to `.env` and set any available keys:

```bash
export VIRUSTOTAL_API_KEY="..."
export ABUSEIPDB_API_KEY="..."
export OTX_API_KEY="..."
```

## API examples

Analyze text:

```bash
curl -X POST http://127.0.0.1:8000/api/intake \
  -H "Content-Type: application/json" \
  -d '{"source_name":"demo-report","text":"C2 at hxxp://evil.example/login and 8.8.8.8. SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}'
```

Export STIX:

```bash
curl -X POST http://127.0.0.1:8000/api/export \
  -H "Content-Type: application/json" \
  -d '{"format":"stix"}'
```

## Development

```bash
ruff check .
pytest
```

## Project structure

```text
app/
  main.py             FastAPI app and API routes
  core/               extraction, enrichment, scoring, clustering, export, storage
  static/             lightweight analyst dashboard
examples/             sample public-style report text
tests/                unit and API tests
```
