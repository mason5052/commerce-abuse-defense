"""Detection rule for targeting hidden or $0 products."""

from __future__ import annotations

from typing import Any

from cad.detectors.base import BaseDetector
from cad.scoring.models import CommerceEvent, DetectionResult, EventType, Severity


class HiddenProductDetector(BaseDetector):
    """Detects direct access to hidden, $0, or warranty products.

    In eCommerce attacks, bots target specific products that are:
    - Priced at $0 (used for card-testing without financial risk)
    - Warranty/protection plan products (not meant for direct purchase)
    - Test products accidentally left visible via direct URL

    These products should only be accessed through normal browsing flow,
    not via direct API/URL access.
    """

    def __init__(self, config: dict[str, Any] | None = None):
        super().__init__(config)
        self._price_threshold = self.config.get("hidden_price_threshold", 0.01)
        self._hidden_keywords = self.config.get("hidden_keywords", [
            "warranty", "protection plan", "test product",
        ])

    @property
    def rule_id(self) -> str:
        return "CAD-002"

    @property
    def rule_name(self) -> str:
        return "Hidden Product Targeting"

    @property
    def category(self) -> str:
        return "hidden_product"

    def detect(self, events: list[CommerceEvent]) -> list[DetectionResult]:
        results: list[DetectionResult] = []
        hidden_events: list[CommerceEvent] = []

        for event in events:
            if self._is_hidden_product(event):
                hidden_events.append(event)

        if not hidden_events:
            return results

        # Group by IP to identify coordinated targeting
        ip_counts: dict[str, int] = {}
        for event in hidden_events:
            ip = event.ip_address or "unknown"
            ip_counts[ip] = ip_counts.get(ip, 0) + 1

        total_hidden = len(hidden_events)
        confidence = min(1.0, total_hidden / 5)

        evidence = [
            f"Total hidden product events: {total_hidden}",
        ]

        # Add top targeting IPs
        sorted_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)
        for ip, count in sorted_ips[:5]:
            evidence.append(f"IP {ip}: {count} hidden product accesses")

        # Add targeted product names
        product_names = set()
        for event in hidden_events:
            if event.product_title:
                product_names.add(event.product_title)
        if product_names:
            evidence.append(f"Targeted products: {', '.join(product_names)}")

        results.append(DetectionResult(
            rule_name=self.rule_name,
            rule_id=self.rule_id,
            severity=Severity.HIGH,
            confidence=confidence,
            description=(
                f"{total_hidden} events targeting hidden/zero-price products "
                f"from {len(ip_counts)} unique IPs"
            ),
            evidence=evidence,
            affected_events=[e.event_id for e in hidden_events],
            metadata={
                "total_hidden_events": total_hidden,
                "unique_ips": len(ip_counts),
                "products": list(product_names),
            },
        ))

        return results

    def _is_hidden_product(self, event: CommerceEvent) -> bool:
        """Check if an event involves a hidden or suspicious product."""
        # Check for $0 or near-zero price
        if event.product_price is not None and event.product_price < self._price_threshold:
            if event.event_type in (EventType.ORDER, EventType.CHECKOUT, EventType.CART_ADD):
                return True

        # Check for hidden product keywords in title
        if event.product_title:
            title_lower = event.product_title.lower()
            for keyword in self._hidden_keywords:
                if keyword.lower() in title_lower:
                    return True

        return False
