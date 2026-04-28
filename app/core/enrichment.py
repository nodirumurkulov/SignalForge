import ipaddress
import os
from urllib.parse import urlparse

import httpx

from app.core.models import EnrichmentObservation, Indicator, IndicatorType


class EnrichmentClient:
    def __init__(self) -> None:
        self.virustotal_api_key = os.getenv("VIRUSTOTAL_API_KEY", "")
        self.abuseipdb_api_key = os.getenv("ABUSEIPDB_API_KEY", "")
        self.otx_api_key = os.getenv("OTX_API_KEY", "")

    async def enrich(self, indicator: Indicator) -> Indicator:
        observations = [self.local_enrichment(indicator)]
        external_observations = await self.external_enrichment(indicator)
        observations.extend(external_observations)
        tags = sorted({tag for observation in observations for tag in observation.tags})
        return indicator.model_copy(
            update={
                "enrichments": observations,
                "tags": sorted(set(indicator.tags + tags)),
            }
        )

    def local_enrichment(self, indicator: Indicator) -> EnrichmentObservation:
        if indicator.type == IndicatorType.IPV4:
            return self.local_ip_enrichment(indicator.value)
        if indicator.type == IndicatorType.URL:
            return self.local_url_enrichment(indicator.value)
        if indicator.type == IndicatorType.DOMAIN:
            return self.local_domain_enrichment(indicator.value)
        if indicator.type in {IndicatorType.MD5, IndicatorType.SHA1, IndicatorType.SHA256}:
            return EnrichmentObservation(
                provider="local",
                verdict="file_hash",
                confidence=55,
                tags=["file-hash"],
                details={"hash_length": len(indicator.value)},
            )
        return EnrichmentObservation(provider="local", verdict="observed", confidence=35)

    def local_ip_enrichment(self, value: str) -> EnrichmentObservation:
        address = ipaddress.ip_address(value)
        tags: list[str] = ["ip"]
        verdict = "public_ip"
        confidence = 50
        details: dict[str, str | int | float | bool | None] = {
            "is_private": address.is_private,
            "is_global": address.is_global,
            "version": address.version,
        }
        if address.is_private or address.is_loopback or address.is_multicast:
            verdict = "non_public_ip"
            confidence = 10
            tags.append("low-signal")
        return EnrichmentObservation(
            provider="local",
            verdict=verdict,
            confidence=confidence,
            tags=tags,
            details=details,
        )

    def local_url_enrichment(self, value: str) -> EnrichmentObservation:
        parsed = urlparse(value)
        tags = ["url"]
        if parsed.scheme == "http":
            tags.append("cleartext-http")
        if any(token in value.lower() for token in ["login", "verify", "update", "invoice"]):
            tags.append("phishing-keyword")
        return EnrichmentObservation(
            provider="local",
            verdict="url_observed",
            confidence=65 if "phishing-keyword" in tags else 50,
            tags=tags,
            details={"host": parsed.netloc, "scheme": parsed.scheme},
        )

    def local_domain_enrichment(self, value: str) -> EnrichmentObservation:
        labels = value.split(".")
        tags = ["domain"]
        if len(labels) > 3:
            tags.append("deep-subdomain")
        if any(token in value for token in ["login", "verify", "secure", "update"]):
            tags.append("brand-or-phishing-keyword")
        return EnrichmentObservation(
            provider="local",
            verdict="domain_observed",
            confidence=60 if len(tags) > 1 else 45,
            tags=tags,
            details={"label_count": len(labels), "root": ".".join(labels[-2:])},
        )

    async def external_enrichment(self, indicator: Indicator) -> list[EnrichmentObservation]:
        observations: list[EnrichmentObservation] = []
        async with httpx.AsyncClient(timeout=8.0) as client:
            if self.virustotal_api_key:
                vt_observation = await self.virustotal_lookup(client, indicator)
                if vt_observation:
                    observations.append(vt_observation)
            if self.abuseipdb_api_key and indicator.type == IndicatorType.IPV4:
                abuse_observation = await self.abuseipdb_lookup(client, indicator.value)
                if abuse_observation:
                    observations.append(abuse_observation)
            if self.otx_api_key:
                otx_observation = await self.otx_lookup(client, indicator)
                if otx_observation:
                    observations.append(otx_observation)
        return observations

    async def virustotal_lookup(
        self, client: httpx.AsyncClient, indicator: Indicator
    ) -> EnrichmentObservation | None:
        path_by_type = {
            IndicatorType.IPV4: "ip_addresses",
            IndicatorType.DOMAIN: "domains",
            IndicatorType.URL: "urls",
            IndicatorType.MD5: "files",
            IndicatorType.SHA1: "files",
            IndicatorType.SHA256: "files",
        }
        resource_type = path_by_type.get(indicator.type)
        if not resource_type:
            return None
        value = indicator.value
        if indicator.type == IndicatorType.URL:
            return EnrichmentObservation(
                provider="virustotal",
                verdict="api_key_configured_url_lookup_deferred",
                confidence=40,
                tags=["external-api-configured"],
            )
        response = await client.get(
            f"https://www.virustotal.com/api/v3/{resource_type}/{value}",
            headers={"x-apikey": self.virustotal_api_key},
        )
        if response.status_code >= 400:
            return EnrichmentObservation(
                provider="virustotal",
                verdict=f"http_{response.status_code}",
                confidence=20,
                tags=["external-api-error"],
            )
        data = response.json()
        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        malicious = int(stats.get("malicious", 0))
        suspicious = int(stats.get("suspicious", 0))
        return EnrichmentObservation(
            provider="virustotal",
            verdict="malicious" if malicious else "observed",
            confidence=min(95, 55 + malicious * 8 + suspicious * 4),
            tags=["virustotal", "malicious"] if malicious else ["virustotal"],
            details={"malicious": malicious, "suspicious": suspicious},
        )

    async def abuseipdb_lookup(
        self, client: httpx.AsyncClient, value: str
    ) -> EnrichmentObservation | None:
        response = await client.get(
            "https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": value, "maxAgeInDays": 90},
            headers={"Key": self.abuseipdb_api_key, "Accept": "application/json"},
        )
        if response.status_code >= 400:
            return EnrichmentObservation(
                provider="abuseipdb",
                verdict=f"http_{response.status_code}",
                confidence=20,
                tags=["external-api-error"],
            )
        data = response.json().get("data", {})
        abuse_score = int(data.get("abuseConfidenceScore", 0))
        return EnrichmentObservation(
            provider="abuseipdb",
            verdict="abusive" if abuse_score >= 50 else "observed",
            confidence=min(95, 40 + abuse_score),
            tags=["abuseipdb", "abusive"] if abuse_score >= 50 else ["abuseipdb"],
            details={"abuse_confidence_score": abuse_score},
        )

    async def otx_lookup(
        self, client: httpx.AsyncClient, indicator: Indicator
    ) -> EnrichmentObservation | None:
        section_by_type = {
            IndicatorType.IPV4: "IPv4",
            IndicatorType.DOMAIN: "domain",
            IndicatorType.URL: "url",
            IndicatorType.MD5: "file",
            IndicatorType.SHA1: "file",
            IndicatorType.SHA256: "file",
        }
        section = section_by_type.get(indicator.type)
        if not section:
            return None
        response = await client.get(
            f"https://otx.alienvault.com/api/v1/indicators/{section}/{indicator.value}/general",
            headers={"X-OTX-API-KEY": self.otx_api_key},
        )
        if response.status_code >= 400:
            return EnrichmentObservation(
                provider="otx",
                verdict=f"http_{response.status_code}",
                confidence=20,
                tags=["external-api-error"],
            )
        data = response.json()
        pulse_count = int(data.get("pulse_info", {}).get("count", 0))
        return EnrichmentObservation(
            provider="otx",
            verdict="pulse_match" if pulse_count else "observed",
            confidence=min(90, 45 + pulse_count * 5),
            tags=["otx", "pulse-match"] if pulse_count else ["otx"],
            details={"pulse_count": pulse_count},
        )
