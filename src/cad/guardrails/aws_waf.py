"""AWS WAF rule generator from abuse analysis reports."""

from __future__ import annotations

import json
from typing import Any

from cad.guardrails.base import BaseGuardrail, GuardrailRule
from cad.scoring.models import AbuseReport, Severity


class AwsWafGuardrail(BaseGuardrail):
    """Generates AWS WAF rules from abuse report detections.

    Produces rules compatible with AWS WAF v2 (WAFV2) API. Rules are
    structured as WebACL rule statements that can be deployed via the
    AWS CLI or CloudFormation/Terraform.

    Defense strategy:
    - CRITICAL threats -> Block
    - HIGH threats -> CAPTCHA
    - MEDIUM threats -> Count (monitor)
    - LOW threats -> Count (log only)
    """

    @property
    def platform(self) -> str:
        return "aws_waf"

    def generate(self, report: AbuseReport) -> list[GuardrailRule]:
        """Generate AWS WAF rules from the abuse report."""
        rules: list[GuardrailRule] = []

        attacking_ips = self._extract_attacking_ips(report)
        bot_ua_patterns = self._extract_bot_patterns(report)
        has_card_testing = self._has_detection_category(
            report, "payment_failure",
        )
        has_hidden_product = self._has_detection_category(
            report, "hidden_product",
        )

        # Rule 1: IP set block for confirmed attackers
        if attacking_ips:
            ip_addresses = sorted(attacking_ips)[:20]
            cidr_list = [f"{ip}/32" for ip in ip_addresses]
            rules.append(GuardrailRule(
                name="CAD-IPBlock-AttackingIPs",
                description=(
                    f"Block {len(ip_addresses)} IPs identified "
                    f"in abuse analysis"
                ),
                expression=json.dumps({
                    "IPSetReferenceStatement": {
                        "ARN": "<IP_SET_ARN>",
                    }
                }),
                action="block",
                priority=1,
                metadata={
                    "source": "cad",
                    "category": "ip_block",
                    "ip_set_addresses": cidr_list,
                    "ip_set_name": "CAD-Attacking-IPs",
                },
            ))

        # Rule 2: Block/CAPTCHA known bot user-agents
        if bot_ua_patterns:
            ua_statements = []
            for pattern in sorted(bot_ua_patterns):
                ua_statements.append({
                    "ByteMatchStatement": {
                        "SearchString": pattern,
                        "FieldToMatch": {
                            "SingleHeader": {"Name": "user-agent"},
                        },
                        "TextTransformations": [
                            {"Priority": 0, "Type": "LOWERCASE"},
                        ],
                        "PositionalConstraint": "CONTAINS",
                    }
                })

            statement = (
                ua_statements[0] if len(ua_statements) == 1
                else {"OrStatement": {"Statements": ua_statements}}
            )

            rules.append(GuardrailRule(
                name="CAD-BotUA-Challenge",
                description=(
                    "CAPTCHA requests from known bot user-agents"
                ),
                expression=json.dumps(statement),
                action="captcha",
                priority=10,
                metadata={
                    "source": "cad",
                    "category": "bot_ua",
                    "patterns": sorted(bot_ua_patterns),
                },
            ))

        # Rule 3: Rate limit checkout (card-testing defense)
        if has_card_testing:
            rules.append(GuardrailRule(
                name="CAD-RateLimit-Checkout",
                description=(
                    "Rate limit POST to checkout "
                    "(100 req/5min per IP)"
                ),
                expression=json.dumps({
                    "RateBasedStatement": {
                        "Limit": 100,
                        "AggregateKeyType": "IP",
                        "ScopeDownStatement": {
                            "AndStatement": {
                                "Statements": [
                                    {
                                        "ByteMatchStatement": {
                                            "SearchString": "/checkout",
                                            "FieldToMatch": {
                                                "UriPath": {},
                                            },
                                            "TextTransformations": [{
                                                "Priority": 0,
                                                "Type": "LOWERCASE",
                                            }],
                                            "PositionalConstraint":
                                                "CONTAINS",
                                        }
                                    },
                                    {
                                        "ByteMatchStatement": {
                                            "SearchString": "POST",
                                            "FieldToMatch": {
                                                "Method": {},
                                            },
                                            "TextTransformations": [{
                                                "Priority": 0,
                                                "Type": "NONE",
                                            }],
                                            "PositionalConstraint":
                                                "EXACTLY",
                                        }
                                    },
                                ]
                            }
                        },
                    }
                }),
                action="block",
                priority=5,
                metadata={
                    "source": "cad",
                    "category": "card_testing_defense",
                    "rate_limit": {
                        "requests": 100,
                        "period": 300,
                    },
                },
            ))

        # Rule 4: Protect hidden products
        if has_hidden_product:
            hidden_products = self._extract_hidden_products(report)
            if hidden_products:
                path_statements = []
                for product in hidden_products[:10]:
                    path_slug = self._product_to_path(product)
                    path_statements.append({
                        "ByteMatchStatement": {
                            "SearchString": path_slug,
                            "FieldToMatch": {"UriPath": {}},
                            "TextTransformations": [{
                                "Priority": 0,
                                "Type": "LOWERCASE",
                            }],
                            "PositionalConstraint": "CONTAINS",
                        }
                    })

                path_statement = (
                    path_statements[0]
                    if len(path_statements) == 1
                    else {
                        "OrStatement": {
                            "Statements": path_statements,
                        }
                    }
                )

                rules.append(GuardrailRule(
                    name="CAD-HiddenProduct-Protect",
                    description=(
                        "CAPTCHA direct access to hidden/zero-price "
                        "products"
                    ),
                    expression=json.dumps(path_statement),
                    action="captcha",
                    priority=15,
                    metadata={
                        "source": "cad",
                        "category": "hidden_product_defense",
                        "products": hidden_products,
                    },
                ))

        # Rule 5: Session flood defense
        if self._has_detection_category(report, "session_explosion"):
            rules.append(GuardrailRule(
                name="CAD-SessionFlood-RateLimit",
                description=(
                    "Rate limit new sessions during bot swarm "
                    "(200 req/5min per IP)"
                ),
                expression=json.dumps({
                    "RateBasedStatement": {
                        "Limit": 200,
                        "AggregateKeyType": "IP",
                    }
                }),
                action="captcha",
                priority=30,
                metadata={
                    "source": "cad",
                    "category": "session_flood_defense",
                },
            ))

        return rules

    def export(self, rules: list[GuardrailRule]) -> str:
        """Export rules as AWS WAF WebACL-compatible JSON."""
        output: dict[str, Any] = {
            "generated_by": "Commerce Abuse Defense (CAD)",
            "platform": "aws_waf",
            "rules_count": len(rules),
            "ip_sets": [],
            "web_acl_rules": [],
        }

        for rule in rules:
            statement = json.loads(rule.expression)
            waf_rule: dict[str, Any] = {
                "Name": rule.name,
                "Priority": rule.priority,
                "Statement": statement,
                "Action": self._map_action_obj(rule.action),
                "VisibilityConfig": {
                    "SampledRequestsEnabled": True,
                    "CloudWatchMetricsEnabled": True,
                    "MetricName": rule.name.replace("-", ""),
                },
            }
            output["web_acl_rules"].append(waf_rule)

            # Collect IP sets that need to be created
            if "ip_set_addresses" in rule.metadata:
                output["ip_sets"].append({
                    "Name": rule.metadata.get(
                        "ip_set_name", "CAD-IPs",
                    ),
                    "Scope": "REGIONAL",
                    "IPAddressVersion": "IPV4",
                    "Addresses": rule.metadata[
                        "ip_set_addresses"
                    ],
                })

        return json.dumps(output, indent=2)

    def export_as_commands(
        self,
        rules: list[GuardrailRule],
        web_acl_name: str = "<WEB_ACL_NAME>",
        scope: str = "REGIONAL",
    ) -> str:
        """Export rules as AWS CLI commands."""
        lines = [
            "# AWS WAF Rules generated by Commerce Abuse "
            "Defense (CAD)",
            f"# WebACL: {web_acl_name}",
            f"# Scope: {scope}",
            "",
        ]

        # IP set creation commands
        for rule in rules:
            if "ip_set_addresses" in rule.metadata:
                addresses = rule.metadata["ip_set_addresses"]
                ip_set_name = rule.metadata.get(
                    "ip_set_name", "CAD-IPs",
                )
                addr_json = json.dumps(addresses)
                lines.append(
                    f"# Create IP set: {ip_set_name}"
                )
                lines.append(
                    "aws wafv2 create-ip-set \\"
                )
                lines.append(
                    f"  --name {ip_set_name} \\"
                )
                lines.append(f"  --scope {scope} \\")
                lines.append(
                    "  --ip-address-version IPV4 \\"
                )
                lines.append(f"  --addresses '{addr_json}'")
                lines.append("")

        # Note about WebACL update
        lines.append(
            "# To add these rules, update your WebACL with "
            "the JSON from:"
        )
        lines.append(
            "# cad guardrail --platform aws_waf --format json"
        )
        lines.append(
            "# Then use: aws wafv2 update-web-acl "
            "--name <NAME> --scope REGIONAL "
            "--rules file://rules.json ..."
        )
        lines.append("")

        return "\n".join(lines)

    def _extract_attacking_ips(
        self, report: AbuseReport,
    ) -> set[str]:
        """Extract IPs identified as sources of attacks."""
        ips: set[str] = set()
        for detection in report.detections:
            if detection.severity in (
                Severity.HIGH, Severity.CRITICAL,
            ):
                ip = detection.metadata.get("ip")
                if ip:
                    ips.add(ip)
        return ips

    def _extract_bot_patterns(
        self, report: AbuseReport,
    ) -> set[str]:
        """Extract bot user-agent patterns."""
        patterns: set[str] = set()
        for detection in report.detections:
            if detection.rule_id in ("CAD-005", "CAD-005-EMPTY"):
                pattern = detection.metadata.get("pattern")
                if pattern:
                    patterns.add(pattern)
        return patterns

    def _extract_hidden_products(
        self, report: AbuseReport,
    ) -> list[str]:
        """Extract hidden product names."""
        products: list[str] = []
        for detection in report.detections:
            if detection.rule_id == "CAD-002":
                prods = detection.metadata.get("products", [])
                products.extend(prods)
        return list(set(products))

    def _has_detection_category(
        self, report: AbuseReport, category: str,
    ) -> bool:
        """Check if a detection category exists."""
        rule_id_map = {
            "payment_failure": ("CAD-003", "CAD-003-IP"),
            "hidden_product": ("CAD-002",),
            "high_frequency": ("CAD-001",),
            "session_explosion": ("CAD-004", "CAD-004-BURST"),
            "anomalous_agent": ("CAD-005", "CAD-005-EMPTY"),
            "geo_concentration": ("CAD-006", "CAD-006-GEO"),
        }
        target_ids = rule_id_map.get(category, ())
        return any(
            d.rule_id in target_ids for d in report.detections
        )

    def _product_to_path(self, product_name: str) -> str:
        """Convert a product name to a URL path segment."""
        return (
            product_name.lower()
            .replace(" ", "-")
            .replace("$", "")
        )

    def _map_action_obj(self, action: str) -> dict[str, Any]:
        """Map CAD action to AWS WAF action object."""
        mapping: dict[str, dict[str, Any]] = {
            "block": {"Block": {}},
            "captcha": {
                "Captcha": {
                    "CustomRequestHandling": {
                        "InsertHeaders": [{
                            "Name": "x-cad-action",
                            "Value": "captcha",
                        }],
                    },
                },
            },
            "count": {"Count": {}},
            "rate_limit": {"Block": {}},
        }
        return mapping.get(action, {"Count": {}})
