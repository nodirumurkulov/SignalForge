import json
import os
import sqlite3
from pathlib import Path

from app.core.models import Indicator


def default_db_path() -> Path:
    return Path(os.getenv("TIFP_DB_PATH", "data/intel.db"))


class IndicatorStore:
    def __init__(self, db_path: Path | None = None) -> None:
        self.db_path = db_path or default_db_path()
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.initialize()

    def connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.db_path)
        connection.row_factory = sqlite3.Row
        return connection

    def initialize(self) -> None:
        with self.connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS indicators (
                    value TEXT PRIMARY KEY,
                    type TEXT NOT NULL,
                    document TEXT NOT NULL
                )
                """
            )

    def upsert_many(self, indicators: list[Indicator]) -> list[Indicator]:
        saved: list[Indicator] = []
        with self.connect() as connection:
            for indicator in indicators:
                existing = self.get(indicator.value)
                candidate = merge_indicator(existing, indicator) if existing else indicator
                connection.execute(
                    """
                    INSERT INTO indicators(value, type, document)
                    VALUES (?, ?, ?)
                    ON CONFLICT(value) DO UPDATE SET
                        type = excluded.type,
                        document = excluded.document
                    """,
                    (
                        candidate.value,
                        candidate.type.value,
                        candidate.model_dump_json(),
                    ),
                )
                saved.append(candidate)
        return saved

    def get(self, value: str) -> Indicator | None:
        with self.connect() as connection:
            row = connection.execute(
                "SELECT document FROM indicators WHERE value = ?",
                (value,),
            ).fetchone()
        if not row:
            return None
        return Indicator.model_validate(json.loads(row["document"]))

    def list_all(self) -> list[Indicator]:
        with self.connect() as connection:
            rows = connection.execute("SELECT document FROM indicators ORDER BY value").fetchall()
        return [Indicator.model_validate(json.loads(row["document"])) for row in rows]

    def clear(self) -> None:
        with self.connect() as connection:
            connection.execute("DELETE FROM indicators")


def merge_indicator(existing: Indicator, new_indicator: Indicator) -> Indicator:
    source_names = sorted(set(existing.source_names + new_indicator.source_names))
    tags = sorted(set(existing.tags + new_indicator.tags))
    enrichments = existing.enrichments or new_indicator.enrichments
    return new_indicator.model_copy(
        update={
            "source_names": source_names,
            "first_seen": existing.first_seen,
            "tags": tags,
            "enrichments": enrichments,
        }
    )
