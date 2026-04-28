from app.core.models import Indicator


def severity_from_score(score: int) -> str:
    if score >= 80:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 35:
        return "medium"
    if score >= 15:
        return "low"
    return "informational"


def score_indicator(indicator: Indicator) -> Indicator:
    score = 0
    explanation: list[str] = []

    type_weights = {
        "sha256": 25,
        "sha1": 22,
        "md5": 20,
        "url": 18,
        "domain": 14,
        "ipv4": 12,
        "email": 8,
    }
    base = type_weights.get(indicator.type.value, 5)
    score += base
    explanation.append(f"{indicator.type.value} base signal +{base}")

    for observation in indicator.enrichments:
        if observation.confidence:
            addition = min(25, observation.confidence // 4)
            score += addition
            explanation.append(f"{observation.provider} confidence +{addition}")
        if "malicious" in observation.tags or "abusive" in observation.tags:
            score += 25
            explanation.append(f"{observation.provider} malicious reputation +25")
        phishing_tags = {"phishing-keyword", "brand-or-phishing-keyword"}
        if phishing_tags.intersection(observation.tags):
            score += 10
            explanation.append("phishing keyword +10")
        if "low-signal" in observation.tags:
            score -= 20
            explanation.append("non-public or low-signal indicator -20")

    if len(indicator.source_names) > 1:
        source_bonus = min(15, len(indicator.source_names) * 3)
        score += source_bonus
        explanation.append(f"multiple source sightings +{source_bonus}")

    bounded_score = max(0, min(100, score))
    return indicator.model_copy(
        update={
            "score": bounded_score,
            "severity": severity_from_score(bounded_score),
            "explanation": explanation,
        }
    )
