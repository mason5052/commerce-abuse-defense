"""Detection rule for geographic and ASN concentration patterns."""

from __future__ import annotations

from collections import Counter
from typing import Any

from cad.detectors.base import BaseDetector
from cad.scoring.models import CommerceEvent, DetectionResult, Severity

# Well-known datacenter/cloud ASNs
DATACENTER_ASNS: dict[int, str] = {
    # AWS
    16509: "AMAZON-02",
    14618: "AMAZON-AES",
    # Google Cloud
    15169: "GOOGLE",
    396982: "GOOGLE-CLOUD",
    # Microsoft Azure
    8075: "MICROSOFT-CORP",
    # DigitalOcean
    14061: "DIGITALOCEAN",
    # OVH
    16276: "OVH",
    # Hetzner
    24940: "HETZNER",
    # Linode/Akamai
    63949: "LINODE",
    # Vultr
    20473: "CHOOPA",
}


class GeoConcentrationDetector(BaseDetector):
    """Detects traffic concentration from datacenter ASNs and unusual geographies.

    Real customer traffic comes from residential ISPs with diverse ASNs.
    Bot traffic often originates from cloud providers (AWS, GCP, Azure)
    and concentrates in unexpected geographic regions.
    """

    def __init__(self, config: dict[str, Any] | None = None):
        super().__init__(config)
        self._dc_threshold = self.config.get("datacenter_asn_threshold", 0.3)
        self._country_threshold = self.config.get("country_concentration_threshold", 0.8)

    @property
    def rule_id(self) -> str:
        return "CAD-006"

    @property
    def rule_name(self) -> str:
        return "Geo/ASN Concentration"

    @property
    def category(self) -> str:
        return "geo_concentration"

    def detect(self, events: list[CommerceEvent]) -> list[DetectionResult]:
        results: list[DetectionResult] = []

        if not events:
            return results

        results.extend(self._check_datacenter_asns(events))
        results.extend(self._check_country_concentration(events))

        return results

    def _check_datacenter_asns(self, events: list[CommerceEvent]) -> list[DetectionResult]:
        """Check for traffic originating from known datacenter ASNs."""
        results: list[DetectionResult] = []

        events_with_asn = [e for e in events if e.asn is not None]
        if not events_with_asn:
            return results

        total = len(events_with_asn)
        dc_events: list[CommerceEvent] = []
        dc_asn_counts: Counter[str] = Counter()

        for event in events_with_asn:
            if event.asn in DATACENTER_ASNS:
                dc_events.append(event)
                org = event.asn_org or DATACENTER_ASNS.get(event.asn, f"ASN{event.asn}")
                dc_asn_counts[org] += 1

        if not dc_events:
            return results

        dc_ratio = len(dc_events) / total

        if dc_ratio >= self._dc_threshold:
            severity = Severity.HIGH if dc_ratio >= 0.6 else Severity.MEDIUM

            evidence = [
                f"Datacenter traffic: {len(dc_events)}/{total} ({dc_ratio:.0%})",
                f"Threshold: {self._dc_threshold:.0%}",
            ]
            for org, count in dc_asn_counts.most_common(5):
                evidence.append(f"  {org}: {count} events")

            results.append(DetectionResult(
                rule_name=self.rule_name,
                rule_id=self.rule_id,
                severity=severity,
                confidence=min(1.0, dc_ratio / 0.6),
                description=(
                    f"{dc_ratio:.0%} of traffic from datacenter ASNs "
                    f"(threshold: {self._dc_threshold:.0%})"
                ),
                evidence=evidence,
                affected_events=[e.event_id for e in dc_events],
                metadata={
                    "datacenter_ratio": round(dc_ratio, 3),
                    "datacenter_events": len(dc_events),
                    "top_asns": dict(dc_asn_counts.most_common(5)),
                },
            ))

        return results

    def _check_country_concentration(
        self, events: list[CommerceEvent]
    ) -> list[DetectionResult]:
        """Check for unusual geographic concentration of traffic."""
        results: list[DetectionResult] = []

        events_with_country = [e for e in events if e.country_code]
        if len(events_with_country) < 5:
            return results

        total = len(events_with_country)
        country_counts = Counter(e.country_code for e in events_with_country)

        # Check if a non-US country dominates traffic (unusual for a US-based store)
        for country, count in country_counts.most_common():
            ratio = count / total
            if country == "US":
                continue  # US concentration is expected for a US store
            if ratio >= self._country_threshold:
                results.append(DetectionResult(
                    rule_name=self.rule_name,
                    rule_id=f"{self.rule_id}-GEO",
                    severity=Severity.MEDIUM,
                    confidence=min(1.0, ratio),
                    description=(
                        f"{ratio:.0%} of traffic from {country} "
                        f"(threshold: {self._country_threshold:.0%})"
                    ),
                    evidence=[
                        f"Country: {country}",
                        f"Events: {count}/{total} ({ratio:.0%})",
                        f"Top countries: {dict(country_counts.most_common(5))}",
                    ],
                    affected_events=[
                        e.event_id for e in events_with_country
                        if e.country_code == country
                    ],
                    metadata={
                        "concentrated_country": country,
                        "concentration_ratio": round(ratio, 3),
                        "country_distribution": dict(country_counts),
                    },
                ))

        return results
