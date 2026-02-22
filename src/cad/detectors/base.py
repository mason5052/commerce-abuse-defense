"""Abstract base class for detection rules."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from cad.scoring.models import CommerceEvent, DetectionResult


class BaseDetector(ABC):
    """Abstract detector interface for identifying abuse patterns.

    Each detector analyzes a list of CommerceEvents and produces
    DetectionResult objects for any patterns it identifies.
    """

    def __init__(self, config: dict[str, Any] | None = None):
        self.config = config or {}

    @property
    @abstractmethod
    def rule_id(self) -> str:
        """Unique identifier for this detection rule."""
        ...

    @property
    @abstractmethod
    def rule_name(self) -> str:
        """Human-readable name for this detection rule."""
        ...

    @property
    @abstractmethod
    def category(self) -> str:
        """Category key used for scoring weights (e.g., 'high_frequency')."""
        ...

    @abstractmethod
    def detect(self, events: list[CommerceEvent]) -> list[DetectionResult]:
        """Run detection logic against a list of commerce events.

        Args:
            events: Normalized commerce events to analyze.

        Returns:
            List of DetectionResult objects for each pattern match found.
        """
        ...
