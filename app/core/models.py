from enum import StrEnum

from pydantic import BaseModel, Field


class IndicatorType(StrEnum):
    IPV4 = "ipv4"
    DOMAIN = "domain"
    URL = "url"
    EMAIL = "email"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"


class EnrichmentObservation(BaseModel):
    provider: str
    verdict: str
    confidence: int = Field(ge=0, le=100)
    tags: list[str] = Field(default_factory=list)
    details: dict[str, str | int | float | bool | None] = Field(default_factory=dict)


class Indicator(BaseModel):
    value: str
    type: IndicatorType
    source_names: list[str] = Field(default_factory=list)
    first_seen: str
    tags: list[str] = Field(default_factory=list)
    enrichments: list[EnrichmentObservation] = Field(default_factory=list)
    score: int = Field(default=0, ge=0, le=100)
    severity: str = "unknown"
    explanation: list[str] = Field(default_factory=list)


class CampaignCluster(BaseModel):
    cluster_id: str
    title: str
    indicators: list[Indicator]
    shared_tags: list[str] = Field(default_factory=list)
    score: int = Field(default=0, ge=0, le=100)
    rationale: list[str] = Field(default_factory=list)


class IntakeRequest(BaseModel):
    source_name: str = Field(default="manual")
    text: str = Field(min_length=1)


class IntakeResponse(BaseModel):
    source_name: str
    extracted_count: int
    new_or_updated_count: int
    indicators: list[Indicator]
    clusters: list[CampaignCluster]


class ExportFormat(StrEnum):
    STIX = "stix"
    SIGMA = "sigma"
    SPLUNK = "splunk"
    KQL = "kql"
    CSV = "csv"


class ExportRequest(BaseModel):
    format: ExportFormat
    indicator_values: list[str] | None = None


class ExportResponse(BaseModel):
    format: ExportFormat
    content_type: str
    content: str
