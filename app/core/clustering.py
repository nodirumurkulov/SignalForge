import hashlib
import ipaddress
from collections import defaultdict
from urllib.parse import urlparse

from app.core.models import CampaignCluster, Indicator, IndicatorType


def cluster_key(indicator: Indicator) -> str:
    if indicator.type == IndicatorType.URL:
        host = urlparse(indicator.value).netloc.lower()
        root = root_domain(host) if host else indicator.value
        return f"domain-root:{root}"
    if indicator.type == IndicatorType.DOMAIN:
        return f"domain-root:{root_domain(indicator.value)}"
    if indicator.type == IndicatorType.IPV4:
        network = ipaddress.ip_network(f"{indicator.value}/24", strict=False)
        return f"ipv4-/24:{network.network_address}"
    if indicator.tags:
        return f"tag:{indicator.tags[0]}"
    return f"type:{indicator.type.value}"


def root_domain(domain: str) -> str:
    labels = domain.split(".")
    if len(labels) < 2:
        return domain
    return ".".join(labels[-2:])


def stable_cluster_id(key: str) -> str:
    digest = hashlib.sha256(key.encode()).hexdigest()[:12]
    return f"cluster-{digest}"


def build_clusters(indicators: list[Indicator]) -> list[CampaignCluster]:
    grouped: dict[str, list[Indicator]] = defaultdict(list)
    for indicator in indicators:
        grouped[cluster_key(indicator)].append(indicator)

    clusters: list[CampaignCluster] = []
    for key, members in grouped.items():
        if not members:
            continue
        shared_tags = sorted(set.intersection(*(set(member.tags) for member in members)))
        score = max(member.score for member in members)
        if len(members) > 1:
            score = min(100, score + 10)
        clusters.append(
            CampaignCluster(
                cluster_id=stable_cluster_id(key),
                title=key,
                indicators=sorted(members, key=lambda item: (item.type.value, item.value)),
                shared_tags=shared_tags,
                score=score,
                rationale=[
                    f"{len(members)} indicator(s) grouped by {key}",
                    "cluster score is based on highest member score plus relationship bonus",
                ],
            )
        )
    return sorted(clusters, key=lambda cluster: (-cluster.score, cluster.title))
