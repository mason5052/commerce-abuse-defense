"""Abstract base class for data collectors."""

from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any

from cad.scoring.models import CommerceEvent


class BaseCollector(ABC):
    """Abstract collector interface for ingesting eCommerce event data.

    All collectors must implement the collect() method to return a list
    of normalized CommerceEvent objects from their respective data source.
    """

    def __init__(self, config: dict[str, Any] | None = None):
        self.config = config or {}

    @property
    @abstractmethod
    def source_name(self) -> str:
        """Return the name of this data source (e.g., 'shopify', 'cloudflare')."""
        ...

    @abstractmethod
    def collect(
        self,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
    ) -> list[CommerceEvent]:
        """Collect events from the data source within the given time range.

        Args:
            start_time: Beginning of the collection window. If None, use source default.
            end_time: End of the collection window. If None, use current time.

        Returns:
            List of normalized CommerceEvent objects.
        """
        ...

    def validate_config(self) -> list[str]:
        """Validate that required configuration is present.

        Returns:
            List of error messages. Empty list means config is valid.
        """
        return []
