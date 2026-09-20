"""Result enrichment helper — thin wrapper kept for TaskRecord.to_response."""

from app.db.repositories.results import load_status_enrichment

__all__ = ["load_status_enrichment"]
