"""Quickstart example for Commerce Abuse Defense.

This script demonstrates basic usage of CAD with sample data.
No API keys required -- uses built-in fixture data.
"""

from cad.collectors.sample import SampleCollector
from cad.config import load_config
from cad.detectors import ALL_DETECTORS
from cad.reporters.console_reporter import ConsoleReporter
from cad.reporters.markdown_reporter import MarkdownReporter
from cad.scoring.engine import ScoringEngine


def main():
    # Load default configuration
    config = load_config()

    # Collect sample data (no API keys needed)
    collector = SampleCollector()
    events = collector.collect()
    print(f"Collected {len(events)} sample events\n")

    # Run all detection rules
    all_detections = []
    for detector_cls in ALL_DETECTORS:
        detector = detector_cls()
        detections = detector.detect(events)
        all_detections.extend(detections)
        if detections:
            print(f"  {detector.rule_name}: {len(detections)} detection(s)")

    print(f"\nTotal detections: {len(all_detections)}\n")

    # Generate abuse report
    engine = ScoringEngine(config)
    report = engine.generate_report(
        detections=all_detections,
        total_events=len(events),
        sources=["sample"],
    )

    # Display in console
    ConsoleReporter().render(report)

    # Also save as markdown
    md_reporter = MarkdownReporter()
    md_reporter.write(report, "example_output.md")
    print("Markdown report saved to example_output.md")


if __name__ == "__main__":
    main()
