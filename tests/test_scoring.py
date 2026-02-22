"""Unit tests for the scoring engine."""

from datetime import datetime, timezone

import pytest

from cad.scoring.engine import ScoringEngine
from cad.scoring.models import (
    AbuseScore,
    DetectionResult,
    Severity,
    ThreatLevel,
)


def _make_detection(
    rule_id: str = "CAD-001",
    severity: Severity = Severity.MEDIUM,
    confidence: float = 0.8,
    description: str = "Test detection",
) -> DetectionResult:
    return DetectionResult(
        rule_name="Test Rule",
        rule_id=rule_id,
        severity=severity,
        confidence=confidence,
        description=description,
    )


class TestScoringEngine:
    def test_empty_detections_score_zero(self):
        engine = ScoringEngine()
        score = engine.score([], total_events=100)
        assert score.total_score == 0.0
        assert score.threat_level == ThreatLevel.NORMAL

    def test_single_critical_detection(self):
        engine = ScoringEngine()
        detections = [
            _make_detection(
                rule_id="CAD-003",
                severity=Severity.CRITICAL,
                confidence=1.0,
            ),
        ]
        score = engine.score(detections, total_events=100)
        assert score.total_score > 0
        assert score.total_detections == 1

    def test_multiple_detections_increase_score(self):
        engine = ScoringEngine()

        single = [_make_detection(rule_id="CAD-001", severity=Severity.HIGH)]
        score_single = engine.score(single, total_events=100)

        multiple = [
            _make_detection(rule_id="CAD-001", severity=Severity.HIGH),
            _make_detection(rule_id="CAD-003", severity=Severity.CRITICAL),
            _make_detection(rule_id="CAD-005", severity=Severity.MEDIUM),
        ]
        score_multiple = engine.score(multiple, total_events=100)

        assert score_multiple.total_score > score_single.total_score

    def test_score_capped_at_100(self):
        engine = ScoringEngine()
        # Flood with critical detections across all categories
        detections = [
            _make_detection(rule_id="CAD-001", severity=Severity.CRITICAL, confidence=1.0),
            _make_detection(rule_id="CAD-002", severity=Severity.CRITICAL, confidence=1.0),
            _make_detection(rule_id="CAD-003", severity=Severity.CRITICAL, confidence=1.0),
            _make_detection(rule_id="CAD-004", severity=Severity.CRITICAL, confidence=1.0),
            _make_detection(rule_id="CAD-005", severity=Severity.CRITICAL, confidence=1.0),
            _make_detection(rule_id="CAD-006", severity=Severity.CRITICAL, confidence=1.0),
        ]
        score = engine.score(detections, total_events=100)
        assert score.total_score <= 100.0

    def test_threat_level_thresholds(self):
        assert AbuseScore.threat_level_from_score(0) == ThreatLevel.NORMAL
        assert AbuseScore.threat_level_from_score(10) == ThreatLevel.NORMAL
        assert AbuseScore.threat_level_from_score(24.9) == ThreatLevel.NORMAL
        assert AbuseScore.threat_level_from_score(25) == ThreatLevel.ELEVATED
        assert AbuseScore.threat_level_from_score(49.9) == ThreatLevel.ELEVATED
        assert AbuseScore.threat_level_from_score(50) == ThreatLevel.HIGH
        assert AbuseScore.threat_level_from_score(74.9) == ThreatLevel.HIGH
        assert AbuseScore.threat_level_from_score(75) == ThreatLevel.CRITICAL
        assert AbuseScore.threat_level_from_score(100) == ThreatLevel.CRITICAL

    def test_generate_report(self):
        engine = ScoringEngine()
        detections = [
            _make_detection(rule_id="CAD-003", severity=Severity.CRITICAL),
            _make_detection(rule_id="CAD-001", severity=Severity.HIGH),
        ]
        report = engine.generate_report(
            detections=detections,
            total_events=50,
            sources=["sample"],
        )
        assert report.report_id.startswith("CAD-")
        assert report.score.total_score > 0
        assert len(report.detections) == 2
        assert len(report.recommendations) > 0
        assert "sample" in report.sources

    def test_recommendations_include_payment_advice(self):
        engine = ScoringEngine()
        detections = [
            _make_detection(rule_id="CAD-003", severity=Severity.CRITICAL),
        ]
        report = engine.generate_report(detections=detections, total_events=50)
        rec_text = " ".join(report.recommendations).lower()
        assert "captcha" in rec_text or "rate limit" in rec_text
