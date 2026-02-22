"""Detection rules for identifying abuse patterns in eCommerce event data."""

from cad.detectors.anomalous_agent import AnomalousAgentDetector
from cad.detectors.base import BaseDetector
from cad.detectors.geo_concentration import GeoConcentrationDetector
from cad.detectors.hidden_product import HiddenProductDetector
from cad.detectors.high_frequency import HighFrequencyDetector
from cad.detectors.payment_failure import PaymentFailureDetector
from cad.detectors.session_explosion import SessionExplosionDetector

ALL_DETECTORS: list[type[BaseDetector]] = [
    HighFrequencyDetector,
    HiddenProductDetector,
    PaymentFailureDetector,
    SessionExplosionDetector,
    AnomalousAgentDetector,
    GeoConcentrationDetector,
]

__all__ = [
    "BaseDetector",
    "HighFrequencyDetector",
    "HiddenProductDetector",
    "PaymentFailureDetector",
    "SessionExplosionDetector",
    "AnomalousAgentDetector",
    "GeoConcentrationDetector",
    "ALL_DETECTORS",
]
