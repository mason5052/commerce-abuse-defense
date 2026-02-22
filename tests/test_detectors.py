"""Unit tests for detection rules."""

from __future__ import annotations

from datetime import datetime

from cad.detectors.anomalous_agent import AnomalousAgentDetector
from cad.detectors.geo_concentration import GeoConcentrationDetector
from cad.detectors.hidden_product import HiddenProductDetector
from cad.detectors.high_frequency import HighFrequencyDetector
from cad.detectors.payment_failure import PaymentFailureDetector
from cad.detectors.session_explosion import SessionExplosionDetector
from cad.scoring.models import CommerceEvent, EventType, Severity


def _make_event(
    event_id: str = "test_001",
    event_type: EventType = EventType.ORDER,
    timestamp: str = "2026-02-20T10:00:00Z",
    ip_address: str | None = "198.51.100.50",
    user_agent: str | None = "Mozilla/5.0",
    session_id: str | None = None,
    product_price: float | None = None,
    product_title: str | None = None,
    payment_status: str | None = None,
    country_code: str | None = None,
    asn: int | None = None,
    asn_org: str | None = None,
    email: str | None = None,
    order_total: float | None = None,
) -> CommerceEvent:
    """Helper to create test CommerceEvent objects."""
    return CommerceEvent(
        event_id=event_id,
        event_type=event_type,
        timestamp=datetime.fromisoformat(timestamp.replace("Z", "+00:00")),
        source="test",
        ip_address=ip_address,
        user_agent=user_agent,
        session_id=session_id,
        product_price=product_price,
        product_title=product_title,
        payment_status=payment_status,
        country_code=country_code,
        asn=asn,
        asn_org=asn_org,
        email=email,
        order_total=order_total,
    )


class TestHighFrequencyDetector:
    def test_detects_rapid_fire_from_same_ip(self):
        # 12 events from same IP in 3 minutes -> should trigger
        events = [
            _make_event(
                event_id=f"hf_{i}",
                timestamp=f"2026-02-20T10:{i:02d}:00Z",
                ip_address="198.51.100.50",
            )
            for i in range(12)
        ]
        detector = HighFrequencyDetector({"max_events_per_ip": 10, "window_minutes": 15})
        results = detector.detect(events)
        assert len(results) >= 1
        assert results[0].severity == Severity.HIGH
        assert results[0].rule_id == "CAD-001"

    def test_no_detection_below_threshold(self):
        events = [
            _make_event(event_id=f"hf_{i}", ip_address="198.51.100.50")
            for i in range(3)
        ]
        detector = HighFrequencyDetector({"max_events_per_ip": 10, "window_minutes": 5})
        results = detector.detect(events)
        assert len(results) == 0

    def test_different_ips_no_detection(self):
        events = [
            _make_event(event_id=f"hf_{i}", ip_address=f"198.51.100.{i}")
            for i in range(20)
        ]
        detector = HighFrequencyDetector({"max_events_per_ip": 10, "window_minutes": 5})
        results = detector.detect(events)
        assert len(results) == 0


class TestHiddenProductDetector:
    def test_detects_zero_price_products(self):
        events = [
            _make_event(
                event_id="hp_1",
                product_price=0.00,
                product_title="Test Product",
                event_type=EventType.ORDER,
            ),
            _make_event(
                event_id="hp_2",
                product_price=0.00,
                product_title="Another Test",
                event_type=EventType.ORDER,
            ),
        ]
        detector = HiddenProductDetector()
        results = detector.detect(events)
        assert len(results) >= 1
        assert results[0].severity == Severity.HIGH

    def test_detects_warranty_keyword(self):
        events = [
            _make_event(
                event_id="hp_3",
                product_price=29.99,
                product_title="Extended Warranty Plan",
                event_type=EventType.ORDER,
            ),
        ]
        detector = HiddenProductDetector()
        results = detector.detect(events)
        assert len(results) >= 1

    def test_normal_products_no_detection(self):
        events = [
            _make_event(
                event_id="hp_4",
                product_price=599.99,
                product_title="Memory Foam Mattress",
                event_type=EventType.ORDER,
            ),
        ]
        detector = HiddenProductDetector()
        results = detector.detect(events)
        assert len(results) == 0


class TestPaymentFailureDetector:
    def test_detects_high_failure_rate(self):
        events = []
        # 8 failures, 2 successes = 80% failure rate
        for i in range(8):
            events.append(_make_event(
                event_id=f"pf_fail_{i}",
                event_type=EventType.PAYMENT_ATTEMPT,
                payment_status="failed",
                ip_address="198.51.100.100",
                email=f"test{i}@throwaway.com",
                order_total=1.00,
            ))
        for i in range(2):
            events.append(_make_event(
                event_id=f"pf_ok_{i}",
                event_type=EventType.PAYMENT_ATTEMPT,
                payment_status="paid",
                ip_address="192.0.2.25",
                order_total=599.99,
            ))

        detector = PaymentFailureDetector({"failure_rate_threshold": 0.3, "min_attempts": 5})
        results = detector.detect(events)
        assert len(results) >= 1
        # Should detect both global and per-IP patterns
        critical_results = [r for r in results if r.severity == Severity.CRITICAL]
        assert len(critical_results) >= 1

    def test_normal_failure_rate_no_detection(self):
        events = []
        # 1 failure, 9 successes = 10% failure rate
        events.append(_make_event(
            event_id="pf_fail_0",
            event_type=EventType.PAYMENT_ATTEMPT,
            payment_status="failed",
        ))
        for i in range(9):
            events.append(_make_event(
                event_id=f"pf_ok_{i}",
                event_type=EventType.PAYMENT_ATTEMPT,
                payment_status="paid",
            ))

        detector = PaymentFailureDetector({"failure_rate_threshold": 0.3, "min_attempts": 5})
        results = detector.detect(events)
        assert len(results) == 0


class TestSessionExplosionDetector:
    def test_detects_high_session_ratio(self):
        # Each event has a unique session = 100% ratio
        events = [
            _make_event(
                event_id=f"se_{i}",
                session_id=f"unique_sess_{i}",
            )
            for i in range(10)
        ]
        detector = SessionExplosionDetector()
        results = detector.detect(events)
        assert len(results) >= 1
        assert results[0].rule_id == "CAD-004"

    def test_normal_sessions_no_detection(self):
        # Few unique sessions with many events = low ratio
        events = [
            _make_event(
                event_id=f"se_{i}",
                session_id="same_session",
            )
            for i in range(20)
        ]
        detector = SessionExplosionDetector()
        results = detector.detect(events)
        assert len(results) == 0


class TestAnomalousAgentDetector:
    def test_detects_bot_user_agents(self):
        events = [
            _make_event(event_id="aa_1", user_agent="python-requests/2.31.0"),
            _make_event(event_id="aa_2", user_agent="python-requests/2.31.0"),
            _make_event(event_id="aa_3", user_agent="HeadlessChrome/120.0"),
            _make_event(event_id="aa_4", user_agent="curl/8.1.0"),
        ]
        detector = AnomalousAgentDetector()
        results = detector.detect(events)
        assert len(results) >= 2  # python-requests and headlesschrome and curl

    def test_detects_missing_user_agent(self):
        events = [
            _make_event(event_id="aa_5", user_agent=None),
            _make_event(event_id="aa_6", user_agent=None),
        ]
        detector = AnomalousAgentDetector()
        results = detector.detect(events)
        assert len(results) >= 1
        assert any("missing" in r.description.lower() for r in results)

    def test_normal_user_agents_no_detection(self):
        events = [
            _make_event(
                event_id="aa_7",
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            ),
            _make_event(
                event_id="aa_8",
                user_agent="Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X)",
            ),
        ]
        detector = AnomalousAgentDetector()
        results = detector.detect(events)
        assert len(results) == 0


class TestGeoConcentrationDetector:
    def test_detects_datacenter_asns(self):
        events = [
            _make_event(
                event_id=f"gc_{i}",
                asn=16509,
                asn_org="AMAZON-02",
                country_code="RO",
            )
            for i in range(8)
        ]
        # Add 2 normal events
        events.extend([
            _make_event(event_id="gc_normal_1", asn=7922, country_code="US"),
            _make_event(event_id="gc_normal_2", asn=7018, country_code="US"),
        ])
        detector = GeoConcentrationDetector({"datacenter_asn_threshold": 0.3})
        results = detector.detect(events)
        assert len(results) >= 1

    def test_detects_country_concentration(self):
        events = [
            _make_event(event_id=f"gc_ro_{i}", country_code="RO")
            for i in range(9)
        ]
        events.append(_make_event(event_id="gc_us_1", country_code="US"))
        detector = GeoConcentrationDetector({"country_concentration_threshold": 0.8})
        results = detector.detect(events)
        assert len(results) >= 1

    def test_us_concentration_no_detection(self):
        # US concentration is expected for a US store
        events = [
            _make_event(event_id=f"gc_us_{i}", country_code="US")
            for i in range(10)
        ]
        detector = GeoConcentrationDetector({"country_concentration_threshold": 0.8})
        results = detector.detect(events)
        # Should NOT flag US concentration
        geo_results = [r for r in results if "GEO" in r.rule_id]
        assert len(geo_results) == 0
