"""Unit tests for report generators."""

import json

from cad.reporters.json_reporter import JsonReporter
from cad.reporters.markdown_reporter import MarkdownReporter
from cad.scoring.models import (
    AbuseReport,
    AbuseScore,
    CategoryScore,
    DetectionResult,
    Severity,
    ThreatLevel,
)


def _make_report() -> AbuseReport:
    """Create a sample report for testing."""
    detection = DetectionResult(
        rule_name="Payment Failure Spike",
        rule_id="CAD-003",
        severity=Severity.CRITICAL,
        confidence=0.95,
        description="Payment failure rate at 80% (8/10 attempts)",
        evidence=["Total attempts: 10", "Failed: 8", "Failure rate: 80%"],
        affected_events=["pay_001", "pay_002"],
    )

    category = CategoryScore(
        category="payment_failure",
        score=90.0,
        weight=0.25,
        weighted_score=22.5,
        detections=[detection],
    )

    score = AbuseScore(
        total_score=45.0,
        threat_level=ThreatLevel.ELEVATED,
        categories=[category],
        total_events_analyzed=100,
        total_detections=1,
    )

    return AbuseReport(
        report_id="CAD-TEST-001",
        score=score,
        detections=[detection],
        top_threats=["Payment failure rate at 80%"],
        recommendations=["Enable CAPTCHA on checkout"],
        sources=["sample"],
    )


class TestJsonReporter:
    def test_render_produces_valid_json(self):
        reporter = JsonReporter()
        report = _make_report()
        output = reporter.render(report)
        data = json.loads(output)
        assert data["report_id"] == "CAD-TEST-001"
        assert data["score"]["total_score"] == 45.0
        assert len(data["detections"]) == 1

    def test_write_creates_file(self, tmp_path):
        reporter = JsonReporter()
        report = _make_report()
        output_file = tmp_path / "test_report.json"
        reporter.write(report, output_file)
        assert output_file.exists()
        data = json.loads(output_file.read_text())
        assert data["report_id"] == "CAD-TEST-001"


class TestMarkdownReporter:
    def test_render_contains_sections(self):
        reporter = MarkdownReporter()
        report = _make_report()
        output = reporter.render(report)

        assert "# Commerce Abuse Defense" in output
        assert "## Executive Summary" in output
        assert "## Score Breakdown" in output
        assert "## Top Threats" in output
        assert "## Detection Details" in output
        assert "## Recommendations" in output

    def test_render_contains_score(self):
        reporter = MarkdownReporter()
        report = _make_report()
        output = reporter.render(report)
        assert "45.0/100" in output
        assert "ELEVATED" in output

    def test_render_contains_detection_details(self):
        reporter = MarkdownReporter()
        report = _make_report()
        output = reporter.render(report)
        assert "Payment Failure Spike" in output
        assert "CAD-003" in output
        assert "CRITICAL" in output

    def test_write_creates_file(self, tmp_path):
        reporter = MarkdownReporter()
        report = _make_report()
        output_file = tmp_path / "test_report.md"
        reporter.write(report, output_file)
        assert output_file.exists()
        content = output_file.read_text()
        assert "Commerce Abuse Defense" in content
