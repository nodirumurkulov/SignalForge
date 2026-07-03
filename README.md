# SignalForge

A defensive threat-intelligence dashboard that turns raw threat-report text into useful
analyst output.

Paste a report or IOC list, and the app will:

1. extract indicators such as IPs, domains, URLs, emails, and file hashes
2. normalize and deduplicate them
3. enrich them with local heuristics and optional threat-intel APIs
4. score severity with plain-English explanations
5. group related indicators into simple campaign clusters
6. export detection and hunting artifacts

This project is built for SOC, threat-intelligence, and detection-engineering portfolio work.
It does **not** execute malware, exploit systems, or provide offensive tooling.

## What it looks like

The browser dashboard includes:

- **Report intake** — paste threat-report text or load the included demo
- **Indicator workbench** — review normalized IOCs, severity, scores, tags, and explanations
- **Campaign clusters** — see related infrastructure grouped together
- **Detection exports** — generate STIX, Sigma, Splunk SPL, Elastic/KQL, or CSV output

## Features

- Extracts common IOCs:
  - IPv4 addresses
  - domains
  - URLs, including defanged `hxxp://` URLs
  - email addresses
  - MD5, SHA1, and SHA256 hashes
- Normalizes and deduplicates repeated indicators.
- Stores indicators locally in SQLite.
- Scores each indicator with explainable severity logic.
- Clusters related indicators by domain root, URL host, `/24` IP range, and shared tags.
- Works offline with local enrichment heuristics.
- Optionally enriches with VirusTotal, AbuseIPDB, and OTX API keys.
- Exports:
  - STIX 2.1 bundle
  - Sigma rule scaffold
  - Splunk SPL query
  - Elastic/KQL query
  - CSV
- Includes a lightweight FastAPI backend and browser dashboard.
- Adds public-readiness safeguards such as security headers, request size limits, and
  environment-based docs disabling.

## Quick start

### 1. Clone the repo

```bash
git clone https://github.com/nodirumurkulov/Threat-Intel-Fusion-Platform.git
cd Threat-Intel-Fusion-Platform
```

### 2. Create a virtual environment

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install dependencies

```bash
python -m pip install -e ".[dev]"
```

### 4. Run the app

```bash
uvicorn app.main:app --reload
```

### 5. Open the dashboard

Visit:

```text
http://127.0.0.1:8000
```

Then click **Load demo** and **Analyze and fuse intelligence**.

You should see six extracted indicators, severity scores, campaign clusters, and export options.

## Example workflow

1. Paste a public threat report, IOC list, or incident note into the dashboard.
2. Click **Analyze and fuse intelligence**.
3. Review the extracted indicators and scoring explanations.
4. Check the generated campaign clusters.
5. Choose an export format such as **Splunk SPL** or **STIX 2.1**.
6. Click **Generate export**.

A sample report is available at:

```text
examples/sample_report.txt
```

## API examples

### Analyze report text

```bash
curl -X POST http://127.0.0.1:8000/api/intake \
  -H "Content-Type: application/json" \
  -d '{
    "source_name": "demo-report",
    "text": "C2 at hxxp://evil.example/login and 8.8.8.8. SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
  }'
```

### List saved indicators

```bash
curl http://127.0.0.1:8000/api/indicators
```

### Export STIX

```bash
curl -X POST http://127.0.0.1:8000/api/export \
  -H "Content-Type: application/json" \
  -d '{"format":"stix"}'
```

## Optional enrichment API keys

The app works without third-party credentials. Optional provider keys only improve enrichment.

You can export keys in your shell:

```bash
export VIRUSTOTAL_API_KEY="..."
export ABUSEIPDB_API_KEY="..."
export OTX_API_KEY="..."
```

Or copy the example environment file:

```bash
cp .env.example .env
```

Then fill in any keys you have.

## Security notes

This is an MVP for local portfolio demos and analyst workflow experimentation.

Safe defaults and public-readiness safeguards:

- provider API keys are never stored in the repo
- optional keys are read from environment variables
- `.env`, local databases, virtual environments, and build artifacts are gitignored
- browser security headers are applied to app responses
- intake text, source names, and export filters have size limits
- CORS is not enabled by default

Before exposing a hosted demo to the internet, add:

- authentication and authorization
- HTTPS
- rate limiting
- operational logging and monitoring
- a production database and backup plan

Interactive API docs are useful locally but should be disabled for public deployments:

```bash
export TIFP_ENABLE_DOCS=false
```

## Development

Run linting:

```bash
ruff check .
```

Run tests:

```bash
pytest
```

Run security checks:

```bash
bandit -r app
pip-audit .
```

## Project structure

```text
app/
  main.py             FastAPI app, API routes, and security middleware
  core/               extraction, enrichment, scoring, clustering, export, storage
  static/             browser dashboard
examples/             sample public-style report text
tests/                unit and API tests
```

## Responsible use

Use this project for defensive security learning, SOC workflows, threat-intelligence
engineering, and detection engineering. Do not use it to target systems, distribute malware,
or support unauthorized activity.
