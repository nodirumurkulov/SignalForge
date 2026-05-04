# Architecture

Threat Intel Fusion Platform is intentionally small enough to understand during a portfolio
review while still resembling real SOC/threat-intelligence engineering workflows.

The app is a local-first FastAPI service with a lightweight browser dashboard. It accepts
unstructured report text, turns it into normalized indicators, enriches and scores them, stores
the result in SQLite, and exports analyst-ready detection artifacts.

## High-level flow

```text
Browser dashboard
      |
      v
FastAPI routes in app/main.py
      |
      v
Extraction -> Enrichment -> Scoring -> SQLite storage
      |              |            |            |
      v              v            v            v
Normalized IOCs   Context      Severity     Deduplicated
                  and tags     and reason   indicator records
      |
      v
Clustering and export APIs
      |
      v
STIX, Sigma, Splunk SPL, Elastic/KQL, CSV
```

## Runtime components

### Browser dashboard

The dashboard lives in `app/static/` and calls the API with plain JSON requests. It provides:

- report intake and demo data loading
- indicator table rendering
- campaign cluster rendering
- export format selection

### FastAPI application

`app/main.py` wires together the dashboard, API routes, storage, enrichment, and security
middleware.

Key routes:

- `GET /` serves the dashboard
- `GET /health` returns a simple health response
- `POST /api/intake` runs the full analysis pipeline
- `GET /api/indicators` lists stored indicators
- `GET /api/clusters` builds clusters from stored indicators
- `POST /api/export` generates detection/hunting output
- `DELETE /api/indicators` clears the local indicator database

### Core modules

```text
app/core/extraction.py   IOC regex extraction, defang normalization, deduplication
app/core/enrichment.py   local enrichment plus optional VirusTotal, AbuseIPDB, OTX lookups
app/core/scoring.py      explainable severity scoring
app/core/storage.py      SQLite persistence and indicator merging
app/core/clustering.py   infrastructure/tag-based grouping
app/core/exports.py      STIX, Sigma, Splunk, KQL, and CSV generation
app/core/models.py       Pydantic request/response/domain models
```

## Data pipeline

1. **Intake**
   - The browser or API submits a source name and raw report text.
   - Pydantic validates request size and field limits.

2. **Extraction**
   - Defanged values such as `hxxp://` and `[.]` are normalized.
   - The extractor identifies URLs, domains, IPv4 addresses, email addresses, and MD5/SHA1/SHA256
     hashes.
   - Obvious documentation-style false-positive domains are skipped.
   - Duplicate indicators from the same input are removed.

3. **Enrichment**
   - Local enrichment always runs and adds context such as IP type, URL scheme, phishing keywords,
     hash length, and domain shape.
   - External enrichment is optional. If API keys are present in environment variables, the app can
     query VirusTotal, AbuseIPDB, and OTX.
   - Provider keys are not stored in the repo.

4. **Scoring**
   - Each indicator receives a type-based base score.
   - Enrichment confidence, malicious/abusive tags, phishing keywords, and multi-source sightings
     adjust the score.
   - The final score is bounded from 0 to 100 and mapped to `informational`, `low`, `medium`,
     `high`, or `critical`.

5. **Storage**
   - Indicators are stored in SQLite at `data/intel.db` by default.
   - `TIFP_DB_PATH` can point the app to another database path.
   - Indicator value is the primary key, so repeat sightings update the existing record instead of
     creating duplicates.

6. **Clustering**
   - URLs and domains are grouped by root domain.
   - IPv4 indicators are grouped by `/24`.
   - Hashes and other indicators can be grouped by shared tags or type.
   - Cluster score is based on the strongest member plus a relationship bonus.

7. **Exports**
   - Analysts can export the current indicator set as STIX 2.1, Sigma, Splunk SPL, Elastic/KQL, or
     CSV.
   - Export requests can optionally filter to a specific list of indicator values.

## Configuration

| Variable | Purpose | Default |
| --- | --- | --- |
| `TIFP_DB_PATH` | SQLite database path | `data/intel.db` |
| `TIFP_ENABLE_DOCS` | Enables `/docs`, `/redoc`, and `/openapi.json` | `true` |
| `VIRUSTOTAL_API_KEY` | Optional VirusTotal enrichment | unset |
| `ABUSEIPDB_API_KEY` | Optional AbuseIPDB IP enrichment | unset |
| `OTX_API_KEY` | Optional AlienVault OTX enrichment | unset |

## Public-readiness safeguards

The app includes basic safeguards for a public source-code release:

- no provider secrets committed to the repo
- `.env`, local databases, virtual environments, and build artifacts ignored by git
- request body limit at the middleware layer
- Pydantic field limits for intake text, source names, indicator values, and export filters
- browser security headers including CSP, frame blocking, MIME-sniffing protection, referrer policy,
  and permissions policy
- CORS disabled by default
- interactive docs can be disabled with `TIFP_ENABLE_DOCS=false`

These safeguards do not make the app a production internet service by themselves. A hosted public
demo should add authentication, authorization, HTTPS, rate limiting, logging, monitoring, and a
production database strategy.

## Why this is threat-intel focused

The project demonstrates the work of transforming unstructured reporting into intelligence products
that detection engineers and SOC analysts can operationalize:

- normalized indicators
- enrichment and reputation context
- confidence and severity scoring
- campaign/infrastructure clustering
- hunt query and detection export

## Safe design boundaries

The platform does not execute samples, bypass controls, exploit systems, or automate intrusion
behavior. It is for defensive enrichment, analysis, and detection engineering.
