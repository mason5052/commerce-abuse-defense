"""Console reporter with colored terminal output using Rich."""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from cad.scoring.models import AbuseReport, Severity, ThreatLevel


THREAT_COLORS: dict[ThreatLevel, str] = {
    ThreatLevel.NORMAL: "green",
    ThreatLevel.ELEVATED: "yellow",
    ThreatLevel.HIGH: "red",
    ThreatLevel.CRITICAL: "bold red",
}

SEVERITY_COLORS: dict[Severity, str] = {
    Severity.LOW: "dim",
    Severity.MEDIUM: "yellow",
    Severity.HIGH: "red",
    Severity.CRITICAL: "bold red",
}


class ConsoleReporter:
    """Renders abuse reports to the terminal with color-coded output."""

    def __init__(self) -> None:
        self.console = Console()

    def render(self, report: AbuseReport) -> None:
        """Print the abuse report to the console."""
        self._print_header(report)
        self._print_score_breakdown(report)
        self._print_top_threats(report)
        self._print_recommendations(report)

    def _print_header(self, report: AbuseReport) -> None:
        """Print the executive summary panel."""
        threat_level = report.score.threat_level
        color = THREAT_COLORS[threat_level]

        score_text = (
            f"[{color}]Abuse Score: {report.score.total_score}/100[/{color}]\n"
            f"[{color}]Threat Level: {threat_level.value.upper()}[/{color}]\n"
            f"Events Analyzed: {report.score.total_events_analyzed}\n"
            f"Detections: {report.score.total_detections}"
        )

        if report.period_start and report.period_end:
            score_text += (
                f"\nPeriod: {report.period_start.strftime('%Y-%m-%d %H:%M')} "
                f"to {report.period_end.strftime('%Y-%m-%d %H:%M')}"
            )

        panel = Panel(
            score_text,
            title="Commerce Abuse Defense",
            subtitle=f"Report {report.report_id}",
            border_style=color,
        )
        self.console.print(panel)
        self.console.print()

    def _print_score_breakdown(self, report: AbuseReport) -> None:
        """Print the score breakdown table."""
        table = Table(title="Score Breakdown")
        table.add_column("Category", style="bold")
        table.add_column("Raw Score", justify="right")
        table.add_column("Weight", justify="right")
        table.add_column("Weighted", justify="right")
        table.add_column("Detections", justify="right")

        for cat in sorted(report.score.categories, key=lambda c: c.weighted_score, reverse=True):
            style = "red" if cat.score >= 50 else "yellow" if cat.score >= 25 else "green"
            table.add_row(
                cat.category.replace("_", " ").title(),
                f"[{style}]{cat.score}[/{style}]",
                f"{cat.weight:.0%}",
                f"[{style}]{cat.weighted_score}[/{style}]",
                str(len(cat.detections)),
            )

        self.console.print(table)
        self.console.print()

    def _print_top_threats(self, report: AbuseReport) -> None:
        """Print top threats list."""
        if not report.detections:
            self.console.print("[green]No threats detected.[/green]")
            return

        self.console.print("[bold]Top Threats:[/bold]")
        for detection in sorted(
            report.detections,
            key=lambda d: (list(Severity).index(d.severity), -d.confidence),
            reverse=True,
        )[:5]:
            color = SEVERITY_COLORS[detection.severity]
            severity_tag = detection.severity.value.upper()
            self.console.print(
                f"  [{color}][{severity_tag}][/{color}] "
                f"{detection.description} "
                f"(confidence: {detection.confidence:.0%})"
            )
        self.console.print()

    def _print_recommendations(self, report: AbuseReport) -> None:
        """Print actionable recommendations."""
        if not report.recommendations:
            return

        self.console.print("[bold]Recommendations:[/bold]")
        for rec in report.recommendations:
            self.console.print(f"  - {rec}")
        self.console.print()
