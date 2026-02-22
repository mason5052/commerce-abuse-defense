"""Detection rule for payment failure rate spikes (card-testing signal)."""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from cad.detectors.base import BaseDetector
from cad.scoring.models import CommerceEvent, DetectionResult, EventType, Severity


class PaymentFailureDetector(BaseDetector):
    """Detects payment failure rate spikes indicating card-testing.

    Card-testing attacks involve criminals validating stolen credit card
    numbers by making small purchases. The signature is:
    - High ratio of failed to successful payments
    - Many different cards tried from the same IP/session
    - Small transaction amounts ($0-$5)
    - Rapid succession of attempts
    """

    def __init__(self, config: dict[str, Any] | None = None):
        super().__init__(config)
        self._failure_threshold = self.config.get("failure_rate_threshold", 0.3)
        self._min_attempts = self.config.get("min_attempts", 5)

    @property
    def rule_id(self) -> str:
        return "CAD-003"

    @property
    def rule_name(self) -> str:
        return "Payment Failure Spike"

    @property
    def category(self) -> str:
        return "payment_failure"

    def detect(self, events: list[CommerceEvent]) -> list[DetectionResult]:
        results: list[DetectionResult] = []

        # Filter to payment-related events
        payment_events = [
            e for e in events
            if e.event_type in (EventType.PAYMENT_ATTEMPT, EventType.PAYMENT_FAILURE)
            or (e.payment_status and e.event_type == EventType.ORDER)
        ]

        if not payment_events:
            return results

        # Check global failure rate
        results.extend(self._check_global_failure_rate(payment_events))

        # Check per-IP failure patterns
        results.extend(self._check_ip_failure_patterns(payment_events))

        return results

    def _check_global_failure_rate(
        self, events: list[CommerceEvent]
    ) -> list[DetectionResult]:
        """Check overall payment failure rate across all events."""
        results: list[DetectionResult] = []

        total = len(events)
        if total < self._min_attempts:
            return results

        failed = sum(
            1 for e in events
            if e.payment_status == "failed"
            or e.event_type == EventType.PAYMENT_FAILURE
        )
        failure_rate = failed / total

        if failure_rate >= self._failure_threshold:
            confidence = min(1.0, failure_rate / 0.6)
            severity = Severity.CRITICAL if failure_rate >= 0.6 else Severity.HIGH

            results.append(DetectionResult(
                rule_name=self.rule_name,
                rule_id=self.rule_id,
                severity=severity,
                confidence=confidence,
                description=(
                    f"Payment failure rate at {failure_rate:.0%} "
                    f"({failed}/{total} attempts) -- "
                    f"threshold: {self._failure_threshold:.0%}"
                ),
                evidence=[
                    f"Total payment attempts: {total}",
                    f"Failed attempts: {failed}",
                    f"Failure rate: {failure_rate:.1%}",
                    f"Threshold: {self._failure_threshold:.0%}",
                ],
                affected_events=[e.event_id for e in events if e.payment_status == "failed"],
                metadata={
                    "total_attempts": total,
                    "failed_attempts": failed,
                    "failure_rate": round(failure_rate, 3),
                },
            ))

        return results

    def _check_ip_failure_patterns(
        self, events: list[CommerceEvent]
    ) -> list[DetectionResult]:
        """Check per-IP payment failure patterns for card-testing."""
        results: list[DetectionResult] = []

        ip_events: dict[str, list[CommerceEvent]] = defaultdict(list)
        for event in events:
            if event.ip_address:
                ip_events[event.ip_address].append(event)

        for ip, ip_event_list in ip_events.items():
            total = len(ip_event_list)
            if total < self._min_attempts:
                continue

            failed = sum(
                1 for e in ip_event_list
                if e.payment_status == "failed"
                or e.event_type == EventType.PAYMENT_FAILURE
            )
            failure_rate = failed / total

            if failure_rate < self._failure_threshold:
                continue

            # Check for card-testing signals
            unique_emails = len(set(
                e.email for e in ip_event_list if e.email
            ))
            small_amounts = sum(
                1 for e in ip_event_list
                if e.order_total is not None and e.order_total <= 5.0
            )

            is_card_testing = unique_emails >= 3 or small_amounts >= 3
            severity = Severity.CRITICAL if is_card_testing else Severity.HIGH
            confidence = min(1.0, (failure_rate + (unique_emails / 10)) / 1.5)

            evidence = [
                f"IP: {ip}",
                f"Payment attempts: {total}",
                f"Failures: {failed} ({failure_rate:.0%})",
                f"Unique emails used: {unique_emails}",
                f"Small amount attempts (<=5): {small_amounts}",
            ]

            if is_card_testing:
                evidence.append("CARD-TESTING PATTERN DETECTED")

            results.append(DetectionResult(
                rule_name=self.rule_name,
                rule_id=f"{self.rule_id}-IP",
                severity=severity,
                confidence=confidence,
                description=(
                    f"IP {ip}: {failure_rate:.0%} payment failure rate "
                    f"with {unique_emails} unique emails"
                    + (" -- card-testing pattern" if is_card_testing else "")
                ),
                evidence=evidence,
                affected_events=[e.event_id for e in ip_event_list],
                metadata={
                    "ip": ip,
                    "failure_rate": round(failure_rate, 3),
                    "unique_emails": unique_emails,
                    "is_card_testing": is_card_testing,
                },
            ))

        return results
