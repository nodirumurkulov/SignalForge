import json

from app.core.exports import export_indicators
from app.core.models import EnrichmentObservation, ExportFormat, Indicator, IndicatorType
from app.core.scoring import score_indicator


def test_score_indicator_is_explainable() -> None:
    indicator = Indicator(
        value="http://secure-login.example/path",
        type=IndicatorType.URL,
        source_names=["unit"],
        first_seen="2026-01-01T00:00:00+00:00",
        enrichments=[
            EnrichmentObservation(
                provider="local",
                verdict="url_observed",
                confidence=65,
                tags=["url", "phishing-keyword"],
            )
        ],
    )

    scored = score_indicator(indicator)

    assert scored.score > 0
    assert scored.severity in {"low", "medium", "high", "critical"}
    assert any("phishing keyword" in reason for reason in scored.explanation)


def test_stix_export_contains_indicator_patterns() -> None:
    indicator = score_indicator(
        Indicator(
            value="8.8.8.8",
            type=IndicatorType.IPV4,
            source_names=["unit"],
            first_seen="2026-01-01T00:00:00+00:00",
        )
    )

    content_type, content = export_indicators([indicator], ExportFormat.STIX)
    payload = json.loads(content)

    assert content_type == "application/stix+json"
    assert payload["type"] == "bundle"
    assert payload["objects"][0]["pattern"] == "[ipv4-addr:value = '8.8.8.8']"
