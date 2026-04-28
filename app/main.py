from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from app.core.clustering import build_clusters
from app.core.enrichment import EnrichmentClient
from app.core.exports import export_indicators
from app.core.extraction import extract_indicators
from app.core.models import ExportRequest, ExportResponse, Indicator, IntakeRequest, IntakeResponse
from app.core.scoring import score_indicator
from app.core.storage import IndicatorStore

APP_DIR = Path(__file__).resolve().parent
STATIC_DIR = APP_DIR / "static"

app = FastAPI(
    title="Threat Intel Fusion Platform",
    description="Defensive IOC ingestion, enrichment, scoring, clustering, and export.",
    version="0.1.0",
)

app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
store = IndicatorStore()
enrichment_client = EnrichmentClient()


@app.get("/")
def dashboard() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/api/intake", response_model=IntakeResponse)
async def intake(request: IntakeRequest) -> IntakeResponse:
    extracted = extract_indicators(request.text, request.source_name)
    enriched = [await enrichment_client.enrich(indicator) for indicator in extracted]
    scored = [score_indicator(indicator) for indicator in enriched]
    saved = store.upsert_many(scored)
    all_indicators = store.list_all()
    clusters = build_clusters(all_indicators)
    return IntakeResponse(
        source_name=request.source_name,
        extracted_count=len(extracted),
        new_or_updated_count=len(saved),
        indicators=saved,
        clusters=clusters,
    )


@app.get("/api/indicators", response_model=list[Indicator])
def list_indicators() -> list[Indicator]:
    return store.list_all()


@app.get("/api/clusters")
def list_clusters() -> dict[str, object]:
    indicators = store.list_all()
    return {"clusters": build_clusters(indicators)}


@app.post("/api/export", response_model=ExportResponse)
def export(request: ExportRequest) -> ExportResponse:
    indicators = store.list_all()
    if request.indicator_values is not None:
        requested = set(request.indicator_values)
        indicators = [indicator for indicator in indicators if indicator.value in requested]
    if not indicators:
        raise HTTPException(status_code=404, detail="No indicators available for export")
    content_type, content = export_indicators(indicators, request.format)
    return ExportResponse(format=request.format, content_type=content_type, content=content)


@app.delete("/api/indicators")
def clear_indicators() -> dict[str, str]:
    store.clear()
    return {"status": "cleared"}
