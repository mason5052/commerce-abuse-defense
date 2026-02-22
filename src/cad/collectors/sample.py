"""Sample data collector that loads from JSON fixture files for demo and testing."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from cad.collectors.base import BaseCollector
from cad.scoring.models import CommerceEvent, EventType

# Default fixture directory relative to package root
_FIXTURES_DIR = Path(__file__).parent.parent.parent.parent / "tests" / "fixtures"


class SampleCollector(BaseCollector):
    """Collector that loads sample data from JSON fixture files.

    Useful for demos, testing, and development without requiring
    real API credentials.
    """

    def __init__(self, config: dict[str, Any] | None = None):
        super().__init__(config)
        self._fixtures_dir = Path(
            self.config.get("fixtures_dir", str(_FIXTURES_DIR))
        )

    @property
    def source_name(self) -> str:
        return "sample"

    def collect(
        self,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
    ) -> list[CommerceEvent]:
        """Load all sample data from fixture JSON files."""
        events: list[CommerceEvent] = []

        fixture_files = [
            "sample_orders.json",
            "sample_cloudflare.json",
            "sample_events.json",
        ]

        for filename in fixture_files:
            filepath = self._fixtures_dir / filename
            if filepath.exists():
                events.extend(self._load_fixture(filepath))

        # Filter by time range if provided
        if start_time or end_time:
            events = [
                e for e in events
                if (not start_time or e.timestamp >= start_time)
                and (not end_time or e.timestamp <= end_time)
            ]

        return sorted(events, key=lambda e: e.timestamp)

    def _load_fixture(self, filepath: Path) -> list[CommerceEvent]:
        """Load and parse a single fixture file into CommerceEvent objects."""
        with open(filepath) as f:
            raw_events = json.load(f)

        events = []
        for raw in raw_events:
            try:
                # Parse event_type string to enum
                raw["event_type"] = EventType(raw["event_type"])
                # Parse timestamp string to datetime
                if isinstance(raw.get("timestamp"), str):
                    raw["timestamp"] = datetime.fromisoformat(
                        raw["timestamp"].replace("Z", "+00:00")
                    )
                events.append(CommerceEvent(**raw))
            except (ValueError, KeyError) as e:
                # Skip malformed events but don't crash
                print(f"Warning: Skipping malformed event in {filepath.name}: {e}")

        return events
