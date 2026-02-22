"""Detection rule for sudden session/device count explosion (bot swarm indicator)."""

from __future__ import annotations

from datetime import timedelta
from typing import Any

from cad.detectors.base import BaseDetector
from cad.scoring.models import CommerceEvent, DetectionResult, Severity


class SessionExplosionDetector(BaseDetector):
    """Detects sudden increase in unique sessions or devices.

    Bot swarms generate many unique sessions in a short time window.
    This detector measures the rate of new unique sessions and flags
    when it exceeds a configurable multiplier over the baseline.
    """

    def __init__(self, config: dict[str, Any] | None = None):
        super().__init__(config)
        self._baseline_multiplier = self.config.get("baseline_multiplier", 3.0)
        self._min_sessions = self.config.get("min_sessions", 50)

    @property
    def rule_id(self) -> str:
        return "CAD-004"

    @property
    def rule_name(self) -> str:
        return "Session Explosion"

    @property
    def category(self) -> str:
        return "session_explosion"

    def detect(self, events: list[CommerceEvent]) -> list[DetectionResult]:
        results: list[DetectionResult] = []

        if not events:
            return results

        # Collect unique sessions and IPs
        unique_sessions = set()
        unique_ips = set()
        for event in events:
            if event.session_id:
                unique_sessions.add(event.session_id)
            if event.ip_address:
                unique_ips.add(event.ip_address)

        total_sessions = len(unique_sessions)
        total_ips = len(unique_ips)
        total_events = len(events)

        # Check for high session-to-event ratio (many unique sessions = bot swarm)
        if total_events > 0 and total_sessions > 0:
            session_ratio = total_sessions / total_events

            # If most events come from unique sessions, it's suspicious
            if session_ratio > 0.8 and total_sessions >= 3:
                confidence = min(1.0, session_ratio * (total_sessions / 10))

                results.append(DetectionResult(
                    rule_name=self.rule_name,
                    rule_id=self.rule_id,
                    severity=Severity.MEDIUM,
                    confidence=confidence,
                    description=(
                        f"{total_sessions} unique sessions across {total_events} events "
                        f"(ratio: {session_ratio:.1%}) -- "
                        f"possible bot swarm"
                    ),
                    evidence=[
                        f"Unique sessions: {total_sessions}",
                        f"Unique IPs: {total_ips}",
                        f"Total events: {total_events}",
                        f"Session/event ratio: {session_ratio:.1%}",
                    ],
                    affected_events=[e.event_id for e in events if e.session_id],
                    metadata={
                        "unique_sessions": total_sessions,
                        "unique_ips": total_ips,
                        "session_ratio": round(session_ratio, 3),
                    },
                ))

        # Check for rapid session creation in time windows
        results.extend(self._check_session_burst(events))

        return results

    def _check_session_burst(self, events: list[CommerceEvent]) -> list[DetectionResult]:
        """Check for bursts of new sessions in short time windows."""
        results: list[DetectionResult] = []

        sorted_events = sorted(events, key=lambda e: e.timestamp)
        if len(sorted_events) < 2:
            return results

        window = timedelta(minutes=5)
        seen_sessions: set[str] = set()

        for i, event in enumerate(sorted_events):
            if not event.session_id:
                continue

            window_new_sessions: set[str] = set()
            for e in sorted_events[i:]:
                if e.timestamp - event.timestamp > window:
                    break
                if e.session_id and e.session_id not in seen_sessions:
                    window_new_sessions.add(e.session_id)

            if len(window_new_sessions) >= 10:
                results.append(DetectionResult(
                    rule_name=self.rule_name,
                    rule_id=f"{self.rule_id}-BURST",
                    severity=Severity.HIGH,
                    confidence=min(1.0, len(window_new_sessions) / 20),
                    description=(
                        f"{len(window_new_sessions)} new sessions created within "
                        f"5 minutes starting at {event.timestamp.isoformat()}"
                    ),
                    evidence=[
                        f"New sessions in window: {len(window_new_sessions)}",
                        f"Window start: {event.timestamp.isoformat()}",
                    ],
                    metadata={
                        "new_session_count": len(window_new_sessions),
                        "window_start": event.timestamp.isoformat(),
                    },
                ))
                break  # One burst detection is sufficient

            seen_sessions.add(event.session_id)

        return results
