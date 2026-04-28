import csv
import io
import json
from datetime import UTC, datetime

from app.core.models import ExportFormat, Indicator, IndicatorType


def export_indicators(indicators: list[Indicator], export_format: ExportFormat) -> tuple[str, str]:
    if export_format == ExportFormat.STIX:
        return "application/stix+json", export_stix(indicators)
    if export_format == ExportFormat.SIGMA:
        return "text/yaml", export_sigma(indicators)
    if export_format == ExportFormat.SPLUNK:
        return "text/plain", export_splunk(indicators)
    if export_format == ExportFormat.KQL:
        return "text/plain", export_kql(indicators)
    return "text/csv", export_csv(indicators)


def export_stix(indicators: list[Indicator]) -> str:
    objects: list[dict[str, str | list[str] | dict[str, str]]] = []
    now = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    for index, indicator in enumerate(indicators, start=1):
        pattern = stix_pattern(indicator)
        objects.append(
            {
                "type": "indicator",
                "spec_version": "2.1",
                "id": f"indicator--00000000-0000-4000-8000-{index:012d}",
                "created": now,
                "modified": now,
                "name": f"{indicator.type.value}: {indicator.value}",
                "description": "; ".join(indicator.explanation),
                "pattern": pattern,
                "pattern_type": "stix",
                "valid_from": now,
                "labels": [indicator.severity, *indicator.tags],
                "external_references": [
                    {
                        "source_name": source_name,
                        "description": "Source that supplied this indicator",
                    }
                    for source_name in indicator.source_names
                ],
            }
        )
    bundle = {
        "type": "bundle",
        "id": "bundle--00000000-0000-4000-8000-000000000001",
        "objects": objects,
    }
    return json.dumps(bundle, indent=2)


def stix_pattern(indicator: Indicator) -> str:
    value = indicator.value.replace("'", "\\'")
    if indicator.type == IndicatorType.IPV4:
        return f"[ipv4-addr:value = '{value}']"
    if indicator.type == IndicatorType.DOMAIN:
        return f"[domain-name:value = '{value}']"
    if indicator.type == IndicatorType.URL:
        return f"[url:value = '{value}']"
    if indicator.type == IndicatorType.EMAIL:
        return f"[email-addr:value = '{value}']"
    return f"[file:hashes.'{indicator.type.value.upper()}' = '{value}']"


def export_sigma(indicators: list[Indicator]) -> str:
    values = [indicator.value for indicator in indicators]
    quoted_values = "\n".join(f"            - '{value}'" for value in values)
    return f"""title: Threat Intel Fusion IOC Match
id: 00000000-0000-4000-8000-000000000002
status: experimental
description: Matches indicators exported from Threat Intel Fusion Platform.
author: Threat Intel Fusion Platform
date: {datetime.now(UTC).date().isoformat()}
logsource:
    category: network_connection
detection:
    selection:
        DestinationHostname|contains:
{quoted_values or "            - 'replace-me.example'"}
    condition: selection
falsepositives:
    - Internal testing infrastructure
level: medium
tags:
    - attack.command_and_control
"""


def export_splunk(indicators: list[Indicator]) -> str:
    values = " OR ".join(f'"{indicator.value}"' for indicator in indicators)
    return f'index=* ({values}) | stats count by host sourcetype source\n'


def export_kql(indicators: list[Indicator]) -> str:
    values = ", ".join(f'"{indicator.value}"' for indicator in indicators)
    return f"""let threat_iocs = dynamic([{values}]);
union isfuzzy=true
    DeviceNetworkEvents,
    DeviceFileEvents,
    EmailUrlInfo
| where RemoteUrl in (threat_iocs)
    or RemoteIP in (threat_iocs)
    or SHA256 in (threat_iocs)
    or FileName in (threat_iocs)
"""


def export_csv(indicators: list[Indicator]) -> str:
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["type", "value", "severity", "score", "tags", "sources"])
    for indicator in indicators:
        writer.writerow(
            [
                indicator.type.value,
                indicator.value,
                indicator.severity,
                indicator.score,
                "|".join(indicator.tags),
                "|".join(indicator.source_names),
            ]
        )
    return output.getvalue()
