"""Unit tests for guardrail generators."""

from __future__ import annotations

import json

from cad.guardrails.aws_waf import AwsWafGuardrail
from cad.guardrails.base import GuardrailRule
from cad.guardrails.cloudflare import CloudflareGuardrail
from cad.scoring.models import (
    AbuseReport,
    AbuseScore,
    DetectionResult,
    Severity,
    ThreatLevel,
)


def _make_report(
    detections: list[DetectionResult] | None = None,
    metadata: dict | None = None,
) -> AbuseReport:
    """Helper to create a test AbuseReport."""
    return AbuseReport(
        report_id="CAD-TEST-001",
        score=AbuseScore(
            total_score=68.0,
            threat_level=ThreatLevel.HIGH,
            total_events_analyzed=27,
            total_detections=len(detections or []),
        ),
        detections=detections or [],
        sources=["test"],
        metadata=metadata or {},
    )


def _make_detection(
    rule_id: str,
    severity: Severity = Severity.HIGH,
    confidence: float = 0.9,
    description: str = "Test detection",
    metadata: dict | None = None,
) -> DetectionResult:
    """Helper to create a test DetectionResult."""
    return DetectionResult(
        rule_name="Test Rule",
        rule_id=rule_id,
        severity=severity,
        confidence=confidence,
        description=description,
        metadata=metadata or {},
    )


class TestGuardrailRule:
    def test_to_dict(self):
        rule = GuardrailRule(
            name="Test Rule",
            description="A test rule",
            expression='(ip.src eq "1.2.3.4")',
            action="block",
            priority=1,
        )
        d = rule.to_dict()
        assert d["name"] == "Test Rule"
        assert d["action"] == "block"
        assert d["enabled"] is True
        assert d["priority"] == 1

    def test_defaults(self):
        rule = GuardrailRule(
            name="R",
            description="D",
            expression="(true)",
            action="log",
        )
        assert rule.priority == 100
        assert rule.enabled is True
        assert rule.metadata == {}


class TestCloudflareGuardrail:
    def test_platform_name(self):
        g = CloudflareGuardrail()
        assert g.platform == "cloudflare"

    def test_empty_report_no_rules(self):
        g = CloudflareGuardrail()
        report = _make_report(detections=[])
        rules = g.generate(report)
        assert len(rules) == 0

    def test_generates_ip_block_rule(self):
        g = CloudflareGuardrail()
        detections = [
            _make_detection(
                "CAD-003-IP",
                severity=Severity.CRITICAL,
                metadata={"ip": "198.51.100.100"},
            ),
        ]
        report = _make_report(detections=detections)
        rules = g.generate(report)

        ip_rules = [r for r in rules if r.action == "block"]
        assert len(ip_rules) >= 1
        assert "198.51.100.100" in ip_rules[0].expression

    def test_generates_bot_ua_rule(self):
        g = CloudflareGuardrail()
        detections = [
            _make_detection(
                "CAD-005",
                severity=Severity.MEDIUM,
                metadata={"pattern": "python-requests"},
            ),
        ]
        report = _make_report(detections=detections)
        rules = g.generate(report)

        ua_rules = [
            r for r in rules if r.action == "managed_challenge"
            and "user_agent" in r.expression
        ]
        assert len(ua_rules) >= 1
        assert "python-requests" in ua_rules[0].expression

    def test_generates_card_testing_rule(self):
        g = CloudflareGuardrail()
        detections = [
            _make_detection(
                "CAD-003",
                severity=Severity.CRITICAL,
            ),
        ]
        report = _make_report(detections=detections)
        rules = g.generate(report)

        rl_rules = [r for r in rules if r.action == "rate_limit"]
        assert len(rl_rules) >= 1
        assert "checkout" in rl_rules[0].expression
        assert rl_rules[0].metadata["rate_limit"]["requests"] == 3

    def test_generates_hidden_product_rule(self):
        g = CloudflareGuardrail()
        detections = [
            _make_detection(
                "CAD-002",
                severity=Severity.HIGH,
                metadata={
                    "products": ["Extended Warranty - Test"],
                },
            ),
        ]
        report = _make_report(
            detections=detections,
            metadata={"domain": "test.myshopify.com"},
        )
        rules = g.generate(report)

        hp_rules = [
            r for r in rules
            if "hidden_product" in r.metadata.get("category", "")
        ]
        assert len(hp_rules) >= 1
        assert "extended-warranty" in hp_rules[0].expression.lower()
        assert "test.myshopify.com" in hp_rules[0].expression

    def test_generates_session_flood_rule(self):
        g = CloudflareGuardrail()
        detections = [
            _make_detection(
                "CAD-004",
                severity=Severity.MEDIUM,
            ),
        ]
        report = _make_report(detections=detections)
        rules = g.generate(report)

        js_rules = [r for r in rules if r.action == "js_challenge"]
        assert len(js_rules) >= 1
        assert "cookie" in js_rules[0].expression

    def test_full_report_generates_multiple_rules(self):
        """A report with all detection types should generate rules."""
        g = CloudflareGuardrail()
        detections = [
            _make_detection(
                "CAD-003-IP",
                severity=Severity.CRITICAL,
                metadata={"ip": "198.51.100.100"},
            ),
            _make_detection(
                "CAD-003",
                severity=Severity.CRITICAL,
            ),
            _make_detection(
                "CAD-005",
                severity=Severity.MEDIUM,
                metadata={"pattern": "python-requests"},
            ),
            _make_detection(
                "CAD-002",
                severity=Severity.HIGH,
                metadata={"products": ["Test Product"]},
            ),
            _make_detection(
                "CAD-004",
                severity=Severity.MEDIUM,
            ),
        ]
        report = _make_report(detections=detections)
        rules = g.generate(report)

        # Should have: IP block, bot UA, rate limit, hidden product, session
        assert len(rules) >= 4
        actions = {r.action for r in rules}
        assert "block" in actions
        assert "managed_challenge" in actions
        assert "rate_limit" in actions
        assert "js_challenge" in actions

    def test_export_json_format(self):
        g = CloudflareGuardrail()
        rules = [
            GuardrailRule(
                name="Test Block",
                description="Block test",
                expression='(ip.src eq "1.2.3.4")',
                action="block",
                priority=1,
            ),
        ]
        output = g.export(rules)
        data = json.loads(output)

        assert data["platform"] == "cloudflare"
        assert data["rules_count"] == 1
        assert data["rules"][0]["action"] == "block"
        assert data["rules"][0]["enabled"] is True

    def test_export_rate_limit_config(self):
        g = CloudflareGuardrail()
        rules = [
            GuardrailRule(
                name="Rate Limit",
                description="RL test",
                expression='(http.request.uri.path eq "/checkout")',
                action="rate_limit",
                metadata={
                    "rate_limit": {"requests": 3, "period": 300},
                },
            ),
        ]
        output = g.export(rules)
        data = json.loads(output)

        rule_data = data["rules"][0]
        assert "ratelimit" in rule_data
        assert rule_data["ratelimit"]["requests_per_period"] == 3
        assert rule_data["ratelimit"]["period"] == 300

    def test_export_as_commands(self):
        g = CloudflareGuardrail()
        rules = [
            GuardrailRule(
                name="Test Rule",
                description="Test",
                expression='(ip.src eq "1.2.3.4")',
                action="block",
            ),
        ]
        output = g.export_as_commands(rules, zone_id="abc123")
        assert "abc123" in output
        assert "curl -X POST" in output
        assert "$CAD_CF_API_TOKEN" in output
        assert "Rule 1: Test Rule" in output

    def test_action_mapping(self):
        g = CloudflareGuardrail()
        assert g._map_action("block") == "block"
        assert g._map_action("managed_challenge") == "managed_challenge"
        assert g._map_action("js_challenge") == "js_challenge"
        assert g._map_action("rate_limit") == "block"
        assert g._map_action("log") == "log"
        assert g._map_action("unknown") == "managed_challenge"

    def test_ip_list_capped_at_20(self):
        """IP block rule should cap at 20 IPs max."""
        g = CloudflareGuardrail()
        detections = [
            _make_detection(
                "CAD-003-IP",
                severity=Severity.CRITICAL,
                metadata={"ip": f"10.0.0.{i}"},
            )
            for i in range(30)
        ]
        report = _make_report(detections=detections)
        rules = g.generate(report)

        ip_rules = [r for r in rules if r.action == "block"]
        assert len(ip_rules) == 1
        # Count quoted IPs in expression
        ip_count = ip_rules[0].expression.count('"10.0.0.')
        assert ip_count <= 20


class TestAwsWafGuardrail:
    def test_platform_name(self):
        g = AwsWafGuardrail()
        assert g.platform == "aws_waf"

    def test_empty_report_no_rules(self):
        g = AwsWafGuardrail()
        report = _make_report(detections=[])
        rules = g.generate(report)
        assert len(rules) == 0

    def test_generates_ip_block_rule(self):
        g = AwsWafGuardrail()
        detections = [
            _make_detection(
                "CAD-003-IP",
                severity=Severity.CRITICAL,
                metadata={"ip": "198.51.100.100"},
            ),
        ]
        report = _make_report(detections=detections)
        rules = g.generate(report)

        ip_rules = [r for r in rules if r.action == "block"]
        assert len(ip_rules) >= 1
        assert ip_rules[0].name == "CAD-IPBlock-AttackingIPs"
        stmt = json.loads(ip_rules[0].expression)
        assert "IPSetReferenceStatement" in stmt
        assert "198.51.100.100/32" in (
            ip_rules[0].metadata["ip_set_addresses"]
        )

    def test_generates_bot_ua_rule(self):
        g = AwsWafGuardrail()
        detections = [
            _make_detection(
                "CAD-005",
                severity=Severity.MEDIUM,
                metadata={"pattern": "python-requests"},
            ),
        ]
        report = _make_report(detections=detections)
        rules = g.generate(report)

        ua_rules = [r for r in rules if r.action == "captcha"]
        assert len(ua_rules) >= 1
        stmt = json.loads(ua_rules[0].expression)
        # Single pattern -> direct ByteMatchStatement
        assert "ByteMatchStatement" in stmt
        assert stmt["ByteMatchStatement"]["SearchString"] == (
            "python-requests"
        )

    def test_bot_ua_multiple_patterns_uses_or(self):
        g = AwsWafGuardrail()
        detections = [
            _make_detection(
                "CAD-005",
                severity=Severity.MEDIUM,
                metadata={"pattern": "python-requests"},
            ),
            _make_detection(
                "CAD-005",
                severity=Severity.MEDIUM,
                metadata={"pattern": "scrapy"},
            ),
        ]
        report = _make_report(detections=detections)
        rules = g.generate(report)

        ua_rules = [
            r for r in rules
            if r.name == "CAD-BotUA-Challenge"
        ]
        assert len(ua_rules) == 1
        stmt = json.loads(ua_rules[0].expression)
        assert "OrStatement" in stmt
        assert len(stmt["OrStatement"]["Statements"]) == 2

    def test_generates_checkout_rate_limit(self):
        g = AwsWafGuardrail()
        detections = [
            _make_detection(
                "CAD-003",
                severity=Severity.CRITICAL,
            ),
        ]
        report = _make_report(detections=detections)
        rules = g.generate(report)

        rl_rules = [
            r for r in rules
            if r.name == "CAD-RateLimit-Checkout"
        ]
        assert len(rl_rules) == 1
        stmt = json.loads(rl_rules[0].expression)
        assert "RateBasedStatement" in stmt
        assert stmt["RateBasedStatement"]["Limit"] == 100

    def test_generates_hidden_product_rule(self):
        g = AwsWafGuardrail()
        detections = [
            _make_detection(
                "CAD-002",
                severity=Severity.HIGH,
                metadata={
                    "products": ["Extended Warranty"],
                },
            ),
        ]
        report = _make_report(detections=detections)
        rules = g.generate(report)

        hp_rules = [
            r for r in rules
            if r.name == "CAD-HiddenProduct-Protect"
        ]
        assert len(hp_rules) == 1
        stmt = json.loads(hp_rules[0].expression)
        assert "ByteMatchStatement" in stmt
        assert stmt["ByteMatchStatement"]["SearchString"] == (
            "extended-warranty"
        )

    def test_generates_session_flood_rule(self):
        g = AwsWafGuardrail()
        detections = [
            _make_detection(
                "CAD-004",
                severity=Severity.MEDIUM,
            ),
        ]
        report = _make_report(detections=detections)
        rules = g.generate(report)

        sf_rules = [
            r for r in rules
            if r.name == "CAD-SessionFlood-RateLimit"
        ]
        assert len(sf_rules) == 1
        stmt = json.loads(sf_rules[0].expression)
        assert "RateBasedStatement" in stmt
        assert stmt["RateBasedStatement"]["Limit"] == 200

    def test_full_report_generates_multiple_rules(self):
        g = AwsWafGuardrail()
        detections = [
            _make_detection(
                "CAD-003-IP",
                severity=Severity.CRITICAL,
                metadata={"ip": "198.51.100.100"},
            ),
            _make_detection(
                "CAD-003",
                severity=Severity.CRITICAL,
            ),
            _make_detection(
                "CAD-005",
                severity=Severity.MEDIUM,
                metadata={"pattern": "python-requests"},
            ),
            _make_detection(
                "CAD-002",
                severity=Severity.HIGH,
                metadata={"products": ["Test Product"]},
            ),
            _make_detection(
                "CAD-004",
                severity=Severity.MEDIUM,
            ),
        ]
        report = _make_report(detections=detections)
        rules = g.generate(report)

        assert len(rules) == 5
        names = {r.name for r in rules}
        assert "CAD-IPBlock-AttackingIPs" in names
        assert "CAD-BotUA-Challenge" in names
        assert "CAD-RateLimit-Checkout" in names
        assert "CAD-HiddenProduct-Protect" in names
        assert "CAD-SessionFlood-RateLimit" in names

    def test_export_json_format(self):
        g = AwsWafGuardrail()
        detections = [
            _make_detection(
                "CAD-003-IP",
                severity=Severity.CRITICAL,
                metadata={"ip": "10.0.0.1"},
            ),
        ]
        report = _make_report(detections=detections)
        rules = g.generate(report)
        output = g.export(rules)
        data = json.loads(output)

        assert data["platform"] == "aws_waf"
        assert data["rules_count"] == 1
        assert len(data["web_acl_rules"]) == 1
        assert len(data["ip_sets"]) == 1
        waf_rule = data["web_acl_rules"][0]
        assert waf_rule["Name"] == "CAD-IPBlock-AttackingIPs"
        assert "Block" in waf_rule["Action"]
        assert waf_rule["VisibilityConfig"]["CloudWatchMetricsEnabled"]

    def test_export_as_commands(self):
        g = AwsWafGuardrail()
        detections = [
            _make_detection(
                "CAD-003-IP",
                severity=Severity.CRITICAL,
                metadata={"ip": "10.0.0.1"},
            ),
        ]
        report = _make_report(detections=detections)
        rules = g.generate(report)
        output = g.export_as_commands(
            rules, web_acl_name="MyWebACL",
        )
        assert "MyWebACL" in output
        assert "aws wafv2 create-ip-set" in output
        assert "10.0.0.1/32" in output

    def test_action_mapping(self):
        g = AwsWafGuardrail()
        assert g._map_action_obj("block") == {"Block": {}}
        assert "Captcha" in g._map_action_obj("captcha")
        assert g._map_action_obj("count") == {"Count": {}}
        assert g._map_action_obj("rate_limit") == {"Block": {}}
        assert g._map_action_obj("unknown") == {"Count": {}}

    def test_ip_list_capped_at_20(self):
        g = AwsWafGuardrail()
        detections = [
            _make_detection(
                "CAD-003-IP",
                severity=Severity.CRITICAL,
                metadata={"ip": f"10.0.0.{i}"},
            )
            for i in range(30)
        ]
        report = _make_report(detections=detections)
        rules = g.generate(report)

        ip_rules = [r for r in rules if r.action == "block"]
        assert len(ip_rules) == 1
        addrs = ip_rules[0].metadata["ip_set_addresses"]
        assert len(addrs) <= 20
