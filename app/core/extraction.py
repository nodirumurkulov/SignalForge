import re
from collections.abc import Iterable
from datetime import UTC, datetime

from app.core.models import Indicator, IndicatorType

HASH_RE = re.compile(r"\b(?P<hash>[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})\b")
IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
URL_RE = re.compile(
    r"\b(?:(?:https?|hxxps?|ftp)://)[^\s\"'<>()\[\]{}]+",
    flags=re.IGNORECASE,
)
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}\b")
DOMAIN_RE = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[A-Za-z]{2,63}\b"
)

COMMON_FALSE_POSITIVE_DOMAINS = {
    "example.com",
    "example.org",
    "example.net",
    "github.com",
    "mitre.org",
}


def normalize_text(text: str) -> str:
    return (
        text.replace("[.]", ".")
        .replace("(.)", ".")
        .replace("{.}", ".")
        .replace("hxxps://", "https://")
        .replace("hxxp://", "http://")
    )


def hash_type(value: str) -> IndicatorType:
    if len(value) == 32:
        return IndicatorType.MD5
    if len(value) == 40:
        return IndicatorType.SHA1
    return IndicatorType.SHA256


def strip_trailing_punctuation(value: str) -> str:
    return value.rstrip(".,;:!?)\"]}'")


def deduplicate(indicators: Iterable[Indicator]) -> list[Indicator]:
    seen: set[tuple[IndicatorType, str]] = set()
    unique: list[Indicator] = []
    for indicator in indicators:
        key = (indicator.type, indicator.value)
        if key in seen:
            continue
        seen.add(key)
        unique.append(indicator)
    return unique


def extract_indicators(text: str, source_name: str) -> list[Indicator]:
    normalized = normalize_text(text)
    observed_at = datetime.now(UTC).isoformat()
    indicators: list[Indicator] = []

    urls: set[str] = set()
    for match in URL_RE.finditer(normalized):
        value = strip_trailing_punctuation(match.group(0))
        urls.add(value.lower())
        indicators.append(
            Indicator(
                value=value.lower(),
                type=IndicatorType.URL,
                source_names=[source_name],
                first_seen=observed_at,
            )
        )

    for match in EMAIL_RE.finditer(normalized):
        indicators.append(
            Indicator(
                value=match.group(0).lower(),
                type=IndicatorType.EMAIL,
                source_names=[source_name],
                first_seen=observed_at,
            )
        )

    for match in IPV4_RE.finditer(normalized):
        indicators.append(
            Indicator(
                value=match.group(0),
                type=IndicatorType.IPV4,
                source_names=[source_name],
                first_seen=observed_at,
            )
        )

    for match in HASH_RE.finditer(normalized):
        value = match.group("hash").lower()
        indicators.append(
            Indicator(
                value=value,
                type=hash_type(value),
                source_names=[source_name],
                first_seen=observed_at,
            )
        )

    for match in DOMAIN_RE.finditer(normalized):
        value = strip_trailing_punctuation(match.group(0)).lower()
        if value in COMMON_FALSE_POSITIVE_DOMAINS:
            continue
        if any(value in url for url in urls):
            continue
        indicators.append(
            Indicator(
                value=value,
                type=IndicatorType.DOMAIN,
                source_names=[source_name],
                first_seen=observed_at,
            )
        )

    return deduplicate(indicators)
