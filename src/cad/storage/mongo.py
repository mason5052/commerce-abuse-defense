"""MongoDB storage backend for CAD reports and scores."""

from __future__ import annotations

import logging
import os
from datetime import datetime, timedelta, timezone
from typing import Any

from cad.scoring.models import AbuseReport, AbuseScore

logger = logging.getLogger("cad.storage")


class MongoStorage:
    """Persistent storage using MongoDB for reports and score time-series.

    Stores full AbuseReport documents and time-series score data for
    trending analysis across runs. Handles connection failures gracefully
    so that CAD continues to function even if MongoDB is unavailable.

    Collections:
    - reports: Full AbuseReport documents (30-day TTL)
    - scores: Time-series score entries (90-day TTL)
    """

    def __init__(self, config: dict[str, Any] | None = None):
        config = config or {}
        self._uri = config.get("uri") or os.environ.get(
            "CAD_MONGO_URI", "mongodb://localhost:27017"
        )
        self._db_name = config.get("database") or os.environ.get(
            "CAD_MONGO_DB", "cad"
        )
        self._client: Any = None
        self._db: Any = None

    def _connect(self) -> None:
        """Establish MongoDB connection and create indexes."""
        if self._client is not None:
            return

        from pymongo import MongoClient

        self._client = MongoClient(self._uri, serverSelectionTimeoutMS=5000)
        self._db = self._client[self._db_name]
        self._ensure_indexes()

    def _ensure_indexes(self) -> None:
        """Create TTL and query indexes."""
        self._db.scores.create_index(
            "timestamp", expireAfterSeconds=90 * 86400,
        )
        self._db.reports.create_index(
            "generated_at", expireAfterSeconds=30 * 86400,
        )
        self._db.scores.create_index([("timestamp", -1)])

    def save_report(self, report: AbuseReport) -> str:
        """Store a full AbuseReport document. Returns the inserted _id."""
        self._connect()
        doc = report.model_dump(mode="json")
        result = self._db.reports.insert_one(doc)
        logger.info("Report saved to MongoDB (id: %s)", result.inserted_id)
        return str(result.inserted_id)

    def save_score(self, score: AbuseScore, report_id: str) -> str:
        """Store a score time-series entry linked to a report."""
        self._connect()
        doc = {
            "report_id": report_id,
            "timestamp": datetime.now(timezone.utc),
            "total_score": score.total_score,
            "threat_level": score.threat_level.value,
            "total_events": score.total_events_analyzed,
            "total_detections": score.total_detections,
            "categories": {
                cat.category: {
                    "score": cat.score,
                    "weighted_score": cat.weighted_score,
                    "detections": len(cat.detections),
                }
                for cat in score.categories
            },
        }
        result = self._db.scores.insert_one(doc)
        logger.info("Score saved to MongoDB (id: %s)", result.inserted_id)
        return str(result.inserted_id)

    def get_recent_scores(self, days: int = 7) -> list[dict]:
        """Fetch score entries from the last N days."""
        self._connect()
        since = datetime.now(timezone.utc) - timedelta(days=days)
        cursor = self._db.scores.find(
            {"timestamp": {"$gte": since}},
            {"_id": 0},
        ).sort("timestamp", -1)
        return list(cursor)

    def get_baseline(self, days: int = 7) -> dict:
        """Compute average/max/min scores from the last N days."""
        scores = self.get_recent_scores(days)
        if not scores:
            return {"avg": 0.0, "max": 0.0, "min": 0.0, "count": 0}

        values = [s["total_score"] for s in scores]
        return {
            "avg": sum(values) / len(values),
            "max": max(values),
            "min": min(values),
            "count": len(values),
        }

    def get_report(self, report_id: str) -> dict | None:
        """Fetch a single report by its MongoDB _id."""
        self._connect()
        from bson import ObjectId

        doc = self._db.reports.find_one({"_id": ObjectId(report_id)})
        if doc:
            doc["_id"] = str(doc["_id"])
        return doc
