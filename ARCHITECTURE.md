# Architecture

Threat Intel Fusion Platform is intentionally small enough to understand during a portfolio review while still resembling real SOC/threat-intelligence engineering workflows.

## Pipeline

1. **Intake** receives pasted report text or IOC lists.
2. **Extraction** normalizes defanged indicators and identifies URLs, domains, IPs, emails, and hashes.
3. **Enrichment** adds local context and can call VirusTotal, AbuseIPDB, and OTX when API keys are configured.
4. **Scoring** produces explainable confidence/severity decisions.
5. **Storage** persists normalized indicators in SQLite.
6. **Clustering** groups indicators by infrastructure relationships such as domain root or IP /24.
7. **Exports** generate STIX, Sigma, Splunk, Elastic/KQL, and CSV output.

## Why this is threat-intel focused

The project demonstrates the work of transforming unstructured reporting into intelligence products that detection engineers and SOC analysts can operationalize:

- normalized indicators
- enrichment and reputation context
- confidence scoring
- campaign/infrastructure clustering
- hunt query and detection export

## Safe design boundaries

The platform does not execute samples, bypass controls, exploit systems, or automate intrusion behavior. It is for defensive enrichment and detection engineering.
