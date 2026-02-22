"""Cloudflare WAF rule generator from abuse analysis reports."""

from __future__ import annotations

import json
from typing import Any

from cad.guardrails.base import BaseGuardrail, GuardrailRule
from cad.scoring.models import AbuseReport, Severity


class CloudflareGuardrail(BaseGuardrail):
    """Generates Cloudflare WAF custom rules from abuse report detections.

    Produces rules in Cloudflare's expression language that can be deployed
    via the Cloudflare Dashboard or API. Rules follow the principle of
    "increase attacker cost" rather than blanket blocking.

    Defense strategy:
    - CRITICAL threats -> Block
    - HIGH threats -> Managed Challenge (CAPTCHA)
    - MEDIUM threats -> JS Challenge
    - LOW threats -> Log only
    """

    @property
    def platform(self) -> str:
        return "cloudflare"

    def generate(self, report: AbuseReport) -> list[GuardrailRule]:
        """Generate Cloudflare WAF rules from the abuse report."""
        rules: list[GuardrailRule] = []

        # Collect attack indicators from detections
        attacking_ips = self._extract_attacking_ips(report)
        bot_ua_patterns = self._extract_bot_patterns(report)
        datacenter_asns = self._extract_datacenter_asns(report)
        has_card_testing = self._has_detection_category(report, "payment_failure")
        has_hidden_product = self._has_detection_category(report, "hidden_product")

        # Rule 1: Block confirmed attacking IPs
        if attacking_ips:
            ip_list = " ".join(f'"{ip}"' for ip in attacking_ips[:20])
            rules.append(GuardrailRule(
                name="CAD: Block Attacking IPs",
                description=f"Block {len(attacking_ips)} IPs identified in abuse analysis",
                expression=f'(ip.src in {{{ip_list}}})',
                action="block",
                priority=1,
                metadata={"source": "cad", "category": "ip_block", "ips": list(attacking_ips)},
            ))

        # Rule 2: Challenge known bot user-agents
        if bot_ua_patterns:
            ua_conditions = " or ".join(
                f'http.user_agent contains "{pattern}"'
                for pattern in bot_ua_patterns
            )
            rules.append(GuardrailRule(
                name="CAD: Challenge Bot User-Agents",
                description="Challenge requests from known automation tools",
                expression=f"({ua_conditions})",
                action="managed_challenge",
                priority=10,
                metadata={"source": "cad", "category": "bot_ua", "patterns": list(bot_ua_patterns)},
            ))

        # Rule 3: Challenge datacenter ASN traffic on sensitive paths
        if datacenter_asns:
            asn_list = " ".join(str(asn) for asn in datacenter_asns)
            rules.append(GuardrailRule(
                name="CAD: Challenge Datacenter Traffic on Checkout",
                description="Challenge requests from datacenter ASNs hitting checkout/cart",
                expression=(
                    f'(ip.geoip.asnum in {{{asn_list}}}) and '
                    f'(http.request.uri.path contains "/checkout" or '
                    f'http.request.uri.path contains "/cart")'
                ),
                action="managed_challenge",
                priority=20,
                metadata={
                    "source": "cad",
                    "category": "datacenter_asn",
                    "asns": list(datacenter_asns),
                },
            ))

        # Rule 4: Rate limit checkout endpoint (card-testing defense)
        if has_card_testing:
            rules.append(GuardrailRule(
                name="CAD: Rate Limit Checkout",
                description=(
                    "Rate limit checkout requests to disrupt "
                    "card-testing (3 req/5min per IP)"
                ),
                expression=(
                    '(http.request.uri.path contains "/checkout") and '
                    '(http.request.method eq "POST")'
                ),
                action="rate_limit",
                priority=5,
                metadata={
                    "source": "cad",
                    "category": "card_testing_defense",
                    "rate_limit": {"requests": 3, "period": 300},
                },
            ))

        # Rule 5: Block direct access to hidden/zero-price products
        if has_hidden_product:
            hidden_products = self._extract_hidden_products(report)
            if hidden_products:
                path_conditions = " or ".join(
                    f'http.request.uri.path contains "{self._product_to_path(p)}"'
                    for p in hidden_products[:10]
                )
                rules.append(GuardrailRule(
                    name="CAD: Protect Hidden Products",
                    description=(
                        "Challenge direct access to hidden/zero-price "
                        "products without referrer"
                    ),
                    expression=(
                        f'({path_conditions}) and '
                        f'(not http.referer contains "{self._get_site_domain(report)}")'
                    ),
                    action="managed_challenge",
                    priority=15,
                    metadata={
                        "source": "cad",
                        "category": "hidden_product_defense",
                        "products": hidden_products,
                    },
                ))

        # Rule 6: JS challenge for high session creation rate (bot swarm)
        if self._has_detection_category(report, "session_explosion"):
            rules.append(GuardrailRule(
                name="CAD: JS Challenge New Sessions",
                description=(
                    "JS challenge for requests without cookies "
                    "(new sessions) during attack"
                ),
                expression=(
                    '(not http.cookie contains "session") and '
                    '(not http.cookie contains "_shopify") and '
                    '(http.request.method eq "GET")'
                ),
                action="js_challenge",
                priority=30,
                metadata={"source": "cad", "category": "session_flood_defense"},
            ))

        return rules

    def export(self, rules: list[GuardrailRule]) -> str:
        """Export rules as Cloudflare API-compatible JSON."""
        output = {
            "generated_by": "Commerce Abuse Defense (CAD)",
            "platform": "cloudflare",
            "rules_count": len(rules),
            "rules": [],
        }

        for rule in rules:
            cf_rule: dict[str, Any] = {
                "description": rule.name,
                "expression": rule.expression,
                "action": self._map_action(rule.action),
                "enabled": rule.enabled,
            }

            # Add rate limit config if applicable
            if rule.action == "rate_limit" and "rate_limit" in rule.metadata:
                rl = rule.metadata["rate_limit"]
                cf_rule["ratelimit"] = {
                    "characteristics": ["ip.src"],
                    "requests_per_period": rl["requests"],
                    "period": rl["period"],
                    "mitigation_timeout": 600,
                    "mitigation_expression": "",
                }

            output["rules"].append(cf_rule)

        return json.dumps(output, indent=2)

    def export_as_commands(self, rules: list[GuardrailRule], zone_id: str = "<ZONE_ID>") -> str:
        """Export rules as curl commands for manual deployment."""
        lines = [
            "# Cloudflare WAF Rules generated by Commerce Abuse Defense (CAD)",
            f"# Zone ID: {zone_id}",
            "",
        ]

        for i, rule in enumerate(rules, 1):
            action = self._map_action(rule.action)
            lines.append(f"# Rule {i}: {rule.name}")
            lines.append(f"# {rule.description}")
            url = (
                f"https://api.cloudflare.com/client/v4/zones/"
                f"{zone_id}/rulesets/phases/"
                f"http_request_firewall_custom/entrypoint"
            )
            lines.append(f'curl -X POST "{url}" \\')
            lines.append('  -H "Authorization: Bearer $CAD_CF_API_TOKEN" \\')
            lines.append('  -H "Content-Type: application/json" \\')

            payload = {
                "rules": [{
                    "description": rule.name,
                    "expression": rule.expression,
                    "action": action,
                    "enabled": rule.enabled,
                }]
            }
            lines.append(f"  -d '{json.dumps(payload)}'")
            lines.append("")

        return "\n".join(lines)

    def _extract_attacking_ips(self, report: AbuseReport) -> set[str]:
        """Extract IPs identified as sources of attacks."""
        ips: set[str] = set()
        for detection in report.detections:
            if detection.severity in (Severity.HIGH, Severity.CRITICAL):
                ip = detection.metadata.get("ip")
                if ip:
                    ips.add(ip)
        return ips

    def _extract_bot_patterns(self, report: AbuseReport) -> set[str]:
        """Extract bot user-agent patterns from detections."""
        patterns: set[str] = set()
        for detection in report.detections:
            if detection.rule_id in ("CAD-005", "CAD-005-EMPTY"):
                pattern = detection.metadata.get("pattern")
                if pattern:
                    patterns.add(pattern)
        return patterns

    def _extract_datacenter_asns(self, report: AbuseReport) -> set[int]:
        """Extract datacenter ASNs from geo concentration detections."""
        asns: set[int] = set()
        for detection in report.detections:
            if detection.rule_id == "CAD-006":
                top_asns = detection.metadata.get("top_asns", {})
                for asn_name in top_asns:
                    # Reverse lookup from name to ASN number
                    from cad.detectors.geo_concentration import DATACENTER_ASNS
                    for asn_num, name in DATACENTER_ASNS.items():
                        if name == asn_name:
                            asns.add(asn_num)
        return asns

    def _extract_hidden_products(self, report: AbuseReport) -> list[str]:
        """Extract hidden product names from detections."""
        products: list[str] = []
        for detection in report.detections:
            if detection.rule_id == "CAD-002":
                prods = detection.metadata.get("products", [])
                products.extend(prods)
        return list(set(products))

    def _has_detection_category(self, report: AbuseReport, category: str) -> bool:
        """Check if a detection category exists in the report."""
        rule_id_map = {
            "payment_failure": ("CAD-003", "CAD-003-IP"),
            "hidden_product": ("CAD-002",),
            "high_frequency": ("CAD-001",),
            "session_explosion": ("CAD-004", "CAD-004-BURST"),
            "anomalous_agent": ("CAD-005", "CAD-005-EMPTY"),
            "geo_concentration": ("CAD-006", "CAD-006-GEO"),
        }
        target_ids = rule_id_map.get(category, ())
        return any(d.rule_id in target_ids for d in report.detections)

    def _product_to_path(self, product_name: str) -> str:
        """Convert a product name to a URL path segment."""
        return product_name.lower().replace(" ", "-").replace("$", "")

    def _get_site_domain(self, report: AbuseReport) -> str:
        """Get the site domain from report sources."""
        return report.metadata.get("domain", "mystore.myshopify.com")

    def _map_action(self, action: str) -> str:
        """Map CAD action names to Cloudflare API action names."""
        mapping = {
            "block": "block",
            "managed_challenge": "managed_challenge",
            "js_challenge": "js_challenge",
            "rate_limit": "block",
            "log": "log",
        }
        return mapping.get(action, "managed_challenge")
