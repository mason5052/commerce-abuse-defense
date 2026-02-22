"""Pydantic data models for commerce events, detection results, and abuse scores."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class EventType(str, Enum):
    """Types of commerce events that can be analyzed."""

    ORDER = "order"
    CHECKOUT = "checkout"
    ABANDONED_CHECKOUT = "abandoned_checkout"
    PAGE_VIEW = "page_view"
    CART_ADD = "cart_add"
    PAYMENT_ATTEMPT = "payment_attempt"
    PAYMENT_FAILURE = "payment_failure"
    SESSION_START = "session_start"


class Severity(str, Enum):
    """Severity levels for detection results."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ThreatLevel(str, Enum):
    """Overall threat level based on abuse score."""

    NORMAL = "normal"          # 0-25
    ELEVATED = "elevated"      # 25-50
    HIGH = "high"              # 50-75
    CRITICAL = "critical"      # 75-100


class CommerceEvent(BaseModel):
    """Normalized event from any eCommerce platform.

    Represents a single event (order, checkout, page view, etc.) with
    platform-agnostic fields for cross-source analysis.
    """

    event_id: str
    event_type: EventType
    timestamp: datetime
    source: str = "unknown"

    # Identity signals
    ip_address: str | None = None
    user_agent: str | None = None
    session_id: str | None = None
    customer_id: str | None = None
    email: str | None = None

    # Transaction details
    product_id: str | None = None
    product_title: str | None = None
    product_price: float | None = None
    order_total: float | None = None
    currency: str = "USD"
    payment_status: str | None = None

    # Location
    country_code: str | None = None
    city: str | None = None
    asn: int | None = None
    asn_org: str | None = None

    # Request metadata
    request_path: str | None = None
    referrer: str | None = None
    http_method: str | None = None

    # Platform-specific raw data
    raw_data: dict[str, Any] = Field(default_factory=dict)


class DetectionResult(BaseModel):
    """Result from a single detection rule.

    Captures what was detected, how severe it is, and the evidence
    supporting the detection.
    """

    rule_name: str
    rule_id: str
    severity: Severity
    confidence: float = Field(ge=0.0, le=1.0)
    description: str
    evidence: list[str] = Field(default_factory=list)
    affected_events: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class CategoryScore(BaseModel):
    """Score breakdown for a single threat category."""

    category: str
    score: float = Field(ge=0.0, le=100.0)
    weight: float = Field(ge=0.0, le=1.0)
    weighted_score: float = Field(ge=0.0, le=100.0)
    detections: list[DetectionResult] = Field(default_factory=list)


class AbuseScore(BaseModel):
    """Aggregated abuse score with category breakdown.

    The score ranges from 0-100:
    - 0-25: Normal (typical eCommerce traffic)
    - 25-50: Elevated (unusual patterns, worth monitoring)
    - 50-75: High (likely active abuse, action recommended)
    - 75-100: Critical (active attack, immediate action required)
    """

    total_score: float = Field(ge=0.0, le=100.0)
    threat_level: ThreatLevel
    categories: list[CategoryScore] = Field(default_factory=list)
    total_events_analyzed: int = 0
    total_detections: int = 0
    period_start: datetime | None = None
    period_end: datetime | None = None

    @staticmethod
    def threat_level_from_score(score: float) -> ThreatLevel:
        if score >= 75:
            return ThreatLevel.CRITICAL
        elif score >= 50:
            return ThreatLevel.HIGH
        elif score >= 25:
            return ThreatLevel.ELEVATED
        return ThreatLevel.NORMAL


class AbuseReport(BaseModel):
    """Full abuse analysis report.

    Contains the abuse score, all detection results, top threats,
    timeline, and actionable recommendations.
    """

    report_id: str
    generated_at: datetime = Field(default_factory=datetime.utcnow)
    score: AbuseScore
    detections: list[DetectionResult] = Field(default_factory=list)
    top_threats: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    sources: list[str] = Field(default_factory=list)
    period_start: datetime | None = None
    period_end: datetime | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
