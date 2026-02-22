"""Scoring engine that aggregates detection results into a single abuse score."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from cad.scoring.models import (
    AbuseReport,
    AbuseScore,
    CategoryScore,
    DetectionResult,
    Severity,
    ThreatLevel,
)


# Default scoring weights per detection category
DEFAULT_WEIGHTS: dict[str, float] = {
    "high_frequency": 0.20,
    "hidden_product": 0.15,
    "payment_failure": 0.25,
    "session_explosion": 0.15,
    "anomalous_agent": 0.10,
    "geo_concentration": 0.15,
}

# Severity multipliers for calculating raw category scores
SEVERITY_MULTIPLIERS: dict[Severity, float] = {
    Severity.LOW: 20.0,
    Severity.MEDIUM: 45.0,
    Severity.HIGH: 70.0,
    Severity.CRITICAL: 95.0,
}


class ScoringEngine:
    """Weighted score aggregation engine.

    Takes detection results from all detectors, groups them by category,
    applies configurable weights, and produces a single AbuseScore (0-100).

    Thresholds:
    - 0-25: Normal (typical eCommerce traffic)
    - 25-50: Elevated (unusual patterns, worth monitoring)
    - 50-75: High (likely active abuse, action recommended)
    - 75-100: Critical (active attack, immediate action required)
    """

    def __init__(self, config: dict[str, Any] | None = None):
        config = config or {}
        scoring_config = config.get("scoring", {})
        self._weights = scoring_config.get("weights", DEFAULT_WEIGHTS)

    def score(
        self,
        detections: list[DetectionResult],
        total_events: int = 0,
        period_start: datetime | None = None,
        period_end: datetime | None = None,
    ) -> AbuseScore:
        """Compute the aggregate abuse score from detection results.

        Args:
            detections: All detection results from all detectors.
            total_events: Total number of events analyzed.
            period_start: Start of the analysis period.
            period_end: End of the analysis period.

        Returns:
            AbuseScore with total score, threat level, and category breakdown.
        """
        # Group detections by category
        categories: dict[str, list[DetectionResult]] = {}
        for detection in detections:
            # Extract category from rule_id prefix mapping
            category = self._detection_to_category(detection)
            if category not in categories:
                categories[category] = []
            categories[category].append(detection)

        # Calculate category scores
        category_scores: list[CategoryScore] = []
        for category_name, weight in self._weights.items():
            cat_detections = categories.get(category_name, [])
            raw_score = self._calculate_category_score(cat_detections)
            weighted = raw_score * weight

            category_scores.append(CategoryScore(
                category=category_name,
                score=round(raw_score, 1),
                weight=weight,
                weighted_score=round(weighted, 1),
                detections=cat_detections,
            ))

        # Sum weighted scores, cap at 100
        total_score = min(100.0, sum(cs.weighted_score for cs in category_scores))

        return AbuseScore(
            total_score=round(total_score, 1),
            threat_level=AbuseScore.threat_level_from_score(total_score),
            categories=category_scores,
            total_events_analyzed=total_events,
            total_detections=len(detections),
            period_start=period_start,
            period_end=period_end,
        )

    def generate_report(
        self,
        detections: list[DetectionResult],
        total_events: int = 0,
        sources: list[str] | None = None,
        period_start: datetime | None = None,
        period_end: datetime | None = None,
    ) -> AbuseReport:
        """Generate a full abuse report with score, threats, and recommendations."""
        abuse_score = self.score(detections, total_events, period_start, period_end)

        # Identify top threats (highest severity detections)
        sorted_detections = sorted(
            detections,
            key=lambda d: (
                list(Severity).index(d.severity),
                -d.confidence,
            ),
            reverse=True,
        )
        top_threats = [d.description for d in sorted_detections[:5]]

        # Generate recommendations based on detections
        recommendations = self._generate_recommendations(detections, abuse_score)

        report_id = f"CAD-{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}"

        return AbuseReport(
            report_id=report_id,
            score=abuse_score,
            detections=detections,
            top_threats=top_threats,
            recommendations=recommendations,
            sources=sources or [],
            period_start=period_start,
            period_end=period_end,
        )

    def _calculate_category_score(self, detections: list[DetectionResult]) -> float:
        """Calculate raw score (0-100) for a category from its detections."""
        if not detections:
            return 0.0

        # Use the highest severity detection's base score
        max_severity_score = max(
            SEVERITY_MULTIPLIERS[d.severity] for d in detections
        )

        # Boost by confidence of the strongest detection
        max_confidence = max(d.confidence for d in detections)

        # Additional boost for multiple detections (compounding evidence)
        volume_boost = min(20.0, len(detections) * 5.0)

        raw_score = (max_severity_score * max_confidence) + volume_boost
        return min(100.0, raw_score)

    def _detection_to_category(self, detection: DetectionResult) -> str:
        """Map a detection result to its scoring category."""
        rule_id_map = {
            "CAD-001": "high_frequency",
            "CAD-002": "hidden_product",
            "CAD-003": "payment_failure",
            "CAD-003-IP": "payment_failure",
            "CAD-004": "session_explosion",
            "CAD-004-BURST": "session_explosion",
            "CAD-005": "anomalous_agent",
            "CAD-005-EMPTY": "anomalous_agent",
            "CAD-006": "geo_concentration",
            "CAD-006-GEO": "geo_concentration",
        }
        return rule_id_map.get(detection.rule_id, "unknown")

    def _generate_recommendations(
        self,
        detections: list[DetectionResult],
        score: AbuseScore,
    ) -> list[str]:
        """Generate actionable recommendations based on detected threats."""
        recommendations: list[str] = []
        categories_found = set()

        for detection in detections:
            cat = self._detection_to_category(detection)
            categories_found.add(cat)

        if "payment_failure" in categories_found:
            recommendations.append(
                "Enable CAPTCHA on checkout to disrupt card-testing automation"
            )
            recommendations.append(
                "Implement rate limiting on payment endpoints (max 3 attempts per session)"
            )

        if "hidden_product" in categories_found:
            recommendations.append(
                "Remove or restrict direct URL access to $0/warranty products"
            )
            recommendations.append(
                "Add referrer validation -- block checkout without prior browse session"
            )

        if "high_frequency" in categories_found:
            recommendations.append(
                "Deploy IP-based rate limiting (Cloudflare WAF or application-level)"
            )

        if "anomalous_agent" in categories_found:
            recommendations.append(
                "Block known bot user-agents at the edge (Cloudflare WAF rule)"
            )

        if "geo_concentration" in categories_found:
            recommendations.append(
                "Review Cloudflare Firewall rules for datacenter ASN traffic"
            )
            recommendations.append(
                "Consider geo-blocking or CAPTCHA challenge for high-risk regions"
            )

        if "session_explosion" in categories_found:
            recommendations.append(
                "Enable Cloudflare Bot Management or JS challenge for new sessions"
            )

        if score.threat_level in (ThreatLevel.HIGH, ThreatLevel.CRITICAL):
            recommendations.insert(0,
                "IMMEDIATE: Review and block top attacking IPs in Cloudflare Firewall"
            )

        return recommendations
