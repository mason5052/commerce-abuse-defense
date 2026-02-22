"""JSON reporter for machine-readable abuse analysis output."""

from __future__ import annotations

import json
from pathlib import Path

from cad.scoring.models import AbuseReport


class JsonReporter:
    """Generates JSON output from an abuse report.

    Produces machine-readable output suitable for integration with
    monitoring systems, SIEM tools, or other automation.
    """

    def render(self, report: AbuseReport) -> str:
        """Render the report as a JSON string."""
        data = report.model_dump(mode="json")
        return json.dumps(data, indent=2, default=str)

    def write(self, report: AbuseReport, output_path: str | Path) -> None:
        """Write the JSON report to a file."""
        content = self.render(report)
        Path(output_path).write_text(content, encoding="utf-8")
