"""Detection rule for high-frequency requests from the same IP or session."""

from __future__ import annotations

from collections import defaultdict
from datetime import timedelta
from typing import Any

from cad.detectors.base import BaseDetector
from cad.scoring.models import CommerceEvent, DetectionResult, Severity


class HighFrequencyDetector(BaseDetector):
    """Detects rapid-fire requests from the same IP address or session.

    Triggers when a single IP or session generates more than N events
    within an M-minute window. This is a strong indicator of automated
    bot activity or scripted attacks.
    """

    def __init__(self, config: dict[str, Any] | None = None):
        super().__init__(config)
        self._max_events = self.config.get("max_events_per_ip", 10)
        self._window_minutes = self.config.get("window_minutes", 5)

    @property
    def rule_id(self) -> str:
        return "CAD-001"

    @property
    def rule_name(self) -> str:
        return "High-Frequency Requests"

    @property
    def category(self) -> str:
        return "high_frequency"

    def detect(self, events: list[CommerceEvent]) -> list[DetectionResult]:
        results: list[DetectionResult] = []

        # Group events by IP address
        ip_events: dict[str, list[CommerceEvent]] = defaultdict(list)
        for event in events:
            if event.ip_address:
                ip_events[event.ip_address].append(event)

        window = timedelta(minutes=self._window_minutes)

        for ip, ip_event_list in ip_events.items():
            sorted_events = sorted(ip_event_list, key=lambda e: e.timestamp)

            # Sliding window check
            for i, event in enumerate(sorted_events):
                window_events = [
                    e for e in sorted_events[i:]
                    if e.timestamp - event.timestamp <= window
                ]

                if len(window_events) >= self._max_events:
                    event_count = len(window_events)
                    confidence = min(1.0, event_count / (self._max_events * 2))

                    results.append(DetectionResult(
                        rule_name=self.rule_name,
                        rule_id=self.rule_id,
                        severity=Severity.HIGH,
                        confidence=confidence,
                        description=(
                            f"IP {ip} generated {event_count} events in "
                            f"{self._window_minutes} minutes "
                            f"(threshold: {self._max_events})"
                        ),
                        evidence=[
                            f"IP: {ip}",
                            f"Event count: {event_count}",
                            f"Window: {self._window_minutes}min",
                            f"First event: {event.timestamp.isoformat()}",
                            f"Last event: {window_events[-1].timestamp.isoformat()}",
                        ],
                        affected_events=[e.event_id for e in window_events],
                        metadata={"ip": ip, "event_count": event_count},
                    ))
                    break  # One detection per IP is sufficient

        return results
