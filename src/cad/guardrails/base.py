"""Abstract base class for guardrail generators."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from cad.scoring.models import AbuseReport


class GuardrailRule:
    """A single generated defense rule."""

    def __init__(
        self,
        name: str,
        description: str,
        expression: str,
        action: str,
        priority: int = 100,
        enabled: bool = True,
        metadata: dict[str, Any] | None = None,
    ):
        self.name = name
        self.description = description
        self.expression = expression
        self.action = action
        self.priority = priority
        self.enabled = enabled
        self.metadata = metadata or {}

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "expression": self.expression,
            "action": self.action,
            "priority": self.priority,
            "enabled": self.enabled,
            "metadata": self.metadata,
        }


class BaseGuardrail(ABC):
    """Abstract interface for guardrail generators.

    Guardrails analyze an AbuseReport and generate platform-specific
    defense rules (WAF rules, rate limits, challenge configurations).
    """

    @property
    @abstractmethod
    def platform(self) -> str:
        """Target platform for these rules (e.g., 'cloudflare', 'shopify')."""
        ...

    @abstractmethod
    def generate(self, report: AbuseReport) -> list[GuardrailRule]:
        """Generate defense rules from an abuse report.

        Args:
            report: The abuse analysis report with detections and scores.

        Returns:
            List of GuardrailRule objects ready for deployment.
        """
        ...

    @abstractmethod
    def export(self, rules: list[GuardrailRule]) -> str:
        """Export rules in the platform's native format.

        Args:
            rules: Generated guardrail rules.

        Returns:
            String representation in the platform's format (e.g., JSON, YAML, CLI commands).
        """
        ...
