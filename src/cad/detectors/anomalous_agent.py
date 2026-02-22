"""Detection rule for suspicious user-agent patterns and headless browser fingerprints."""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from cad.detectors.base import BaseDetector
from cad.scoring.models import CommerceEvent, DetectionResult, Severity


class AnomalousAgentDetector(BaseDetector):
    """Detects known bot user-agent patterns and headless browser fingerprints.

    Identifies traffic from:
    - Known automation libraries (requests, scrapy, curl, wget)
    - Headless browsers (HeadlessChrome, PhantomJS)
    - Missing or empty user-agents
    - HTTP client libraries not used by real browsers
    """

    def __init__(self, config: dict[str, Any] | None = None):
        super().__init__(config)
        self._bot_patterns = self.config.get("known_bot_patterns", [
            "headlesschrome",
            "phantomjs",
            "python-requests",
            "go-http-client",
            "curl/",
            "wget/",
            "scrapy",
            "httpclient",
        ])

    @property
    def rule_id(self) -> str:
        return "CAD-005"

    @property
    def rule_name(self) -> str:
        return "Anomalous User-Agent"

    @property
    def category(self) -> str:
        return "anomalous_agent"

    def detect(self, events: list[CommerceEvent]) -> list[DetectionResult]:
        results: list[DetectionResult] = []

        # Track bot UA matches
        bot_events: dict[str, list[CommerceEvent]] = defaultdict(list)
        missing_ua_events: list[CommerceEvent] = []

        for event in events:
            if not event.user_agent:
                missing_ua_events.append(event)
                continue

            matched_pattern = self._match_bot_pattern(event.user_agent)
            if matched_pattern:
                bot_events[matched_pattern].append(event)

        # Report each bot pattern found
        for pattern, pattern_events in bot_events.items():
            unique_ips = set(e.ip_address for e in pattern_events if e.ip_address)
            sample_ua = pattern_events[0].user_agent or ""

            confidence = min(1.0, len(pattern_events) / 10)

            results.append(DetectionResult(
                rule_name=self.rule_name,
                rule_id=self.rule_id,
                severity=Severity.MEDIUM,
                confidence=confidence,
                description=(
                    f"Bot user-agent pattern '{pattern}' detected in "
                    f"{len(pattern_events)} events from {len(unique_ips)} IPs"
                ),
                evidence=[
                    f"Pattern: {pattern}",
                    f"Sample UA: {sample_ua[:100]}",
                    f"Event count: {len(pattern_events)}",
                    f"Unique IPs: {len(unique_ips)}",
                ],
                affected_events=[e.event_id for e in pattern_events],
                metadata={
                    "pattern": pattern,
                    "event_count": len(pattern_events),
                    "unique_ips": len(unique_ips),
                },
            ))

        # Report missing user-agents
        if missing_ua_events:
            results.append(DetectionResult(
                rule_name=self.rule_name,
                rule_id=f"{self.rule_id}-EMPTY",
                severity=Severity.LOW if len(missing_ua_events) < 5 else Severity.MEDIUM,
                confidence=min(1.0, len(missing_ua_events) / 20),
                description=(
                    f"{len(missing_ua_events)} events with missing user-agent"
                ),
                evidence=[
                    f"Events without UA: {len(missing_ua_events)}",
                ],
                affected_events=[e.event_id for e in missing_ua_events],
                metadata={"missing_ua_count": len(missing_ua_events)},
            ))

        return results

    def _match_bot_pattern(self, user_agent: str) -> str | None:
        """Check if user-agent matches any known bot pattern."""
        ua_lower = user_agent.lower()
        for pattern in self._bot_patterns:
            if pattern.lower() in ua_lower:
                return pattern
        return None
