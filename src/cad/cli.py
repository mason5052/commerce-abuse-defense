"""CLI entry point for Commerce Abuse Defense."""

from __future__ import annotations

import argparse
import signal
import sys
import time
from datetime import datetime, timedelta, timezone

from cad import __version__
from cad.collectors.sample import SampleCollector
from cad.config import load_config
from cad.detectors import ALL_DETECTORS
from cad.logging_config import setup_logging
from cad.reporters.console_reporter import ConsoleReporter
from cad.reporters.json_reporter import JsonReporter
from cad.reporters.markdown_reporter import MarkdownReporter
from cad.scoring.engine import ScoringEngine


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        prog="cad",
        description="Commerce Abuse Defense -- Detect and score eCommerce abuse",
    )
    parser.add_argument(
        "--version", action="version", version=f"cad {__version__}"
    )
    parser.add_argument(
        "--config", type=str, default=None,
        help="Path to YAML config file",
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # -- report command --
    report_parser = subparsers.add_parser("report", help="Generate full abuse report")
    report_parser.add_argument(
        "--source", type=str, default="sample",
        help="Data sources (comma-separated: sample, shopify, cloudflare)",
    )
    report_parser.add_argument(
        "--format", type=str, default="console",
        choices=["console", "json", "markdown"],
        help="Output format (default: console)",
    )
    report_parser.add_argument(
        "--output", type=str, default=None,
        help="Output file path (default: stdout for console, auto-named for others)",
    )
    report_parser.add_argument(
        "--period", type=str, default="24h",
        help="Analysis period (e.g., 1h, 24h, 7d). Default: 24h",
    )
    report_parser.add_argument(
        "--store", action="store_true", default=False,
        help="Persist report and scores to MongoDB",
    )

    # -- score command --
    score_parser = subparsers.add_parser("score", help="Quick abuse score check")
    score_parser.add_argument(
        "--source", type=str, default="sample",
        help="Data sources (comma-separated: sample, shopify, cloudflare)",
    )
    score_parser.add_argument(
        "--period", type=str, default="1h",
        help="Analysis period (e.g., 1h, 24h, 7d). Default: 1h",
    )

    # -- guardrail command --
    guard_parser = subparsers.add_parser(
        "guardrail", help="Generate defense rules from abuse analysis",
    )
    guard_parser.add_argument(
        "--source", type=str, default="sample",
        help="Data sources (comma-separated: sample, shopify, cloudflare)",
    )
    guard_parser.add_argument(
        "--platform", type=str, default="cloudflare",
        choices=["cloudflare", "aws_waf"],
        help="Target WAF platform (default: cloudflare)",
    )
    guard_parser.add_argument(
        "--format", type=str, default="json",
        choices=["json", "commands"],
        help="Output format: json (API payload) or commands (curl)",
    )
    guard_parser.add_argument(
        "--zone-id", type=str, default="<ZONE_ID>",
        help="Cloudflare Zone ID (for commands format)",
    )
    guard_parser.add_argument(
        "--web-acl-name", type=str, default="<WEB_ACL_NAME>",
        help="AWS WAF WebACL name (for commands format)",
    )
    guard_parser.add_argument(
        "--output", type=str, default=None,
        help="Output file path (default: stdout)",
    )
    guard_parser.add_argument(
        "--period", type=str, default="24h",
        help="Analysis period (e.g., 1h, 24h, 7d). Default: 24h",
    )

    # -- watch command --
    watch_parser = subparsers.add_parser(
        "watch", help="Continuously monitor abuse score at intervals",
    )
    watch_parser.add_argument(
        "--source", type=str, default="sample",
        help="Data sources (comma-separated: sample, shopify, cloudflare)",
    )
    watch_parser.add_argument(
        "--period", type=str, default="1h",
        help="Analysis window per check (e.g., 1h, 24h). Default: 1h",
    )
    watch_parser.add_argument(
        "--interval", type=str, default="30m",
        help="Time between checks (e.g., 5m, 30m, 1h). Default: 30m",
    )
    watch_parser.add_argument(
        "--threshold", type=float, default=25.0,
        help="Alert when score exceeds this value (default: 25)",
    )
    watch_parser.add_argument(
        "--log", type=str, default=None,
        help="Append score history to this file (CSV format)",
    )

    return parser.parse_args(argv)


def parse_period(period_str: str) -> timedelta:
    """Parse a period string like '24h', '7d', '30m' into a timedelta."""
    unit = period_str[-1].lower()
    try:
        value = int(period_str[:-1])
    except ValueError:
        raise ValueError(f"Invalid period format: {period_str}")

    if unit == "m":
        return timedelta(minutes=value)
    elif unit == "h":
        return timedelta(hours=value)
    elif unit == "d":
        return timedelta(days=value)
    else:
        raise ValueError(f"Unknown period unit: {unit}. Use m, h, or d.")


def get_collectors(source_str: str, config: dict):
    """Create collector instances from a comma-separated source string."""
    collectors = []
    sources = [s.strip() for s in source_str.split(",")]

    for source in sources:
        if source == "sample":
            collectors.append(SampleCollector(config.get("sample", {})))
        elif source == "shopify":
            from cad.collectors.shopify import ShopifyCollector
            collectors.append(ShopifyCollector(config.get("shopify", {})))
        elif source == "cloudflare":
            from cad.collectors.cloudflare import CloudflareCollector
            collectors.append(CloudflareCollector(config.get("cloudflare", {})))
        else:
            print(f"Warning: Unknown source '{source}', skipping")

    return collectors


def run_report(args: argparse.Namespace, config: dict) -> int:
    """Execute the report command."""
    period = parse_period(args.period)
    end_time = datetime.now(timezone.utc)
    start_time = end_time - period

    # Collect events from all sources
    collectors = get_collectors(args.source, config)
    if not collectors:
        print("Error: No valid data sources specified")
        return 1

    all_events = []
    source_names = []
    for collector in collectors:
        errors = collector.validate_config()
        if errors:
            print(f"Config errors for {collector.source_name}: {', '.join(errors)}")
            return 1
        events = collector.collect(start_time, end_time)
        all_events.extend(events)
        source_names.append(collector.source_name)

    if not all_events:
        print("No events found in the specified period")
        return 0

    # Run all detectors
    detector_config = config.get("detectors", {})
    all_detections = []
    for detector_cls in ALL_DETECTORS:
        category = detector_cls.__name__.replace("Detector", "").lower()
        # Map class name to config key
        config_key_map = {
            "highfrequency": "high_frequency",
            "hiddenproduct": "hidden_product",
            "paymentfailure": "payment_failure",
            "sessionexplosion": "session_explosion",
            "anomalousagent": "anomalous_agent",
            "geoconcentration": "geo_concentration",
        }
        det_config = detector_config.get(config_key_map.get(category, category), {})
        detector = detector_cls(det_config)
        detections = detector.detect(all_events)
        all_detections.extend(detections)

    # Generate report
    engine = ScoringEngine(config)
    report = engine.generate_report(
        detections=all_detections,
        total_events=len(all_events),
        sources=source_names,
        period_start=start_time,
        period_end=end_time,
    )

    # Persist to MongoDB if requested
    if args.store:
        try:
            from cad.storage.mongo import MongoStorage

            storage = MongoStorage(config.get("mongodb", {}))
            report_oid = storage.save_report(report)
            storage.save_score(report.score, report_oid)
        except Exception as e:
            print(f"Warning: MongoDB storage failed: {e}", file=sys.stderr)

    # Output report
    if args.format == "console":
        ConsoleReporter().render(report)
    elif args.format == "json":
        reporter = JsonReporter()
        if args.output:
            reporter.write(report, args.output)
            print(f"JSON report written to {args.output}")
        else:
            print(reporter.render(report))
    elif args.format == "markdown":
        reporter = MarkdownReporter()
        if args.output:
            reporter.write(report, args.output)
            print(f"Markdown report written to {args.output}")
        else:
            print(reporter.render(report))

    return 0


def run_score(args: argparse.Namespace, config: dict) -> int:
    """Execute the score command (quick check)."""
    period = parse_period(args.period)
    end_time = datetime.now(timezone.utc)
    start_time = end_time - period

    collectors = get_collectors(args.source, config)
    if not collectors:
        print("Error: No valid data sources specified")
        return 1

    all_events = []
    for collector in collectors:
        events = collector.collect(start_time, end_time)
        all_events.extend(events)

    if not all_events:
        print("Score: 0/100 (Normal) -- No events found")
        return 0

    # Run detectors
    detector_config = config.get("detectors", {})
    all_detections = []
    for detector_cls in ALL_DETECTORS:
        category = detector_cls.__name__.replace("Detector", "").lower()
        config_key_map = {
            "highfrequency": "high_frequency",
            "hiddenproduct": "hidden_product",
            "paymentfailure": "payment_failure",
            "sessionexplosion": "session_explosion",
            "anomalousagent": "anomalous_agent",
            "geoconcentration": "geo_concentration",
        }
        det_config = detector_config.get(config_key_map.get(category, category), {})
        detector = detector_cls(det_config)
        all_detections.extend(detector.detect(all_events))

    engine = ScoringEngine(config)
    score = engine.score(all_detections, len(all_events), start_time, end_time)

    print(f"Score: {score.total_score}/100 ({score.threat_level.value.title()})")
    print(f"Events: {score.total_events_analyzed} | Detections: {score.total_detections}")

    return 0


def run_guardrail(args: argparse.Namespace, config: dict) -> int:
    """Execute the guardrail command."""
    period = parse_period(args.period)
    end_time = datetime.now(timezone.utc)
    start_time = end_time - period

    # Collect and analyze (same pipeline as report)
    collectors = get_collectors(args.source, config)
    if not collectors:
        print("Error: No valid data sources specified")
        return 1

    all_events = []
    source_names = []
    for collector in collectors:
        errors = collector.validate_config()
        if errors:
            print(
                f"Config errors for {collector.source_name}: "
                f"{', '.join(errors)}"
            )
            return 1
        events = collector.collect(start_time, end_time)
        all_events.extend(events)
        source_names.append(collector.source_name)

    if not all_events:
        print("No events found in the specified period")
        return 0

    # Run detectors
    detector_config = config.get("detectors", {})
    all_detections = []
    for detector_cls in ALL_DETECTORS:
        category = detector_cls.__name__.replace("Detector", "").lower()
        config_key_map = {
            "highfrequency": "high_frequency",
            "hiddenproduct": "hidden_product",
            "paymentfailure": "payment_failure",
            "sessionexplosion": "session_explosion",
            "anomalousagent": "anomalous_agent",
            "geoconcentration": "geo_concentration",
        }
        det_config = detector_config.get(
            config_key_map.get(category, category), {},
        )
        detector = detector_cls(det_config)
        all_detections.extend(detector.detect(all_events))

    # Generate report (needed as input to guardrail generator)
    engine = ScoringEngine(config)
    report = engine.generate_report(
        detections=all_detections,
        total_events=len(all_events),
        sources=source_names,
        period_start=start_time,
        period_end=end_time,
    )

    # Generate guardrail rules
    if args.platform == "aws_waf":
        from cad.guardrails.aws_waf import AwsWafGuardrail
        guardrail = AwsWafGuardrail()
    else:
        from cad.guardrails.cloudflare import CloudflareGuardrail
        guardrail = CloudflareGuardrail()

    rules = guardrail.generate(report)

    if not rules:
        print("No guardrail rules generated (no actionable threats)")
        return 0

    # Export in requested format
    if args.format == "commands":
        if args.platform == "aws_waf":
            output = guardrail.export_as_commands(
                rules, web_acl_name=args.web_acl_name,
            )
        else:
            output = guardrail.export_as_commands(
                rules, zone_id=args.zone_id,
            )
    else:
        output = guardrail.export(rules)

    if args.output:
        with open(args.output, "w") as f:
            f.write(output)
        print(f"Guardrail rules written to {args.output}")
        print(f"Generated {len(rules)} rules for {guardrail.platform}")
    else:
        print(output)

    return 0


def _collect_and_score(source_str, config, period):
    """Collect events, run detectors, return (score, events, detections)."""
    end_time = datetime.now(timezone.utc)
    start_time = end_time - period

    collectors = get_collectors(source_str, config)
    if not collectors:
        return None, 0, 0

    all_events = []
    for collector in collectors:
        events = collector.collect(start_time, end_time)
        all_events.extend(events)

    if not all_events:
        return None, 0, 0

    detector_config = config.get("detectors", {})
    all_detections = []
    for detector_cls in ALL_DETECTORS:
        category = detector_cls.__name__.replace("Detector", "").lower()
        config_key_map = {
            "highfrequency": "high_frequency",
            "hiddenproduct": "hidden_product",
            "paymentfailure": "payment_failure",
            "sessionexplosion": "session_explosion",
            "anomalousagent": "anomalous_agent",
            "geoconcentration": "geo_concentration",
        }
        det_config = detector_config.get(
            config_key_map.get(category, category), {},
        )
        detector = detector_cls(det_config)
        all_detections.extend(detector.detect(all_events))

    engine = ScoringEngine(config)
    score = engine.score(all_detections, len(all_events), start_time, end_time)
    return score, len(all_events), len(all_detections)


def run_watch(args: argparse.Namespace, config: dict) -> int:
    """Execute the watch command -- continuous monitoring loop."""
    period = parse_period(args.period)
    interval = parse_period(args.interval)
    interval_secs = int(interval.total_seconds())
    threshold = args.threshold
    log_path = args.log

    # Graceful shutdown on Ctrl+C
    stop = False

    def _handle_signal(sig, frame):
        nonlocal stop
        stop = True
        print("\nStopping watch...")

    signal.signal(signal.SIGINT, _handle_signal)

    print(
        f"CAD Watch | source={args.source} period={args.period} "
        f"interval={args.interval} threshold={threshold}"
    )
    print("-" * 60)

    # Write CSV header
    if log_path:
        with open(log_path, "a") as f:
            f.write("timestamp,score,threat_level,events,detections\n")

    prev_score = None
    check_num = 0

    while not stop:
        check_num += 1
        now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        try:
            score, events_count, det_count = _collect_and_score(
                args.source, config, period,
            )
        except Exception as e:
            print(f"[{now_str}] ERROR: {e}")
            time.sleep(interval_secs)
            continue

        if score is None:
            print(f"[{now_str}] No events found")
            time.sleep(interval_secs)
            continue

        current = score.total_score
        level = score.threat_level.value.upper()

        # Delta from previous check
        delta_str = ""
        if prev_score is not None:
            delta = current - prev_score
            if delta > 0:
                delta_str = f" (+{delta:.1f})"
            elif delta < 0:
                delta_str = f" ({delta:.1f})"

        # Alert prefix
        alert = ""
        if current >= threshold:
            alert = "ALERT "
        if prev_score is not None and (current - prev_score) >= 15:
            alert = "SPIKE "

        print(
            f"[{now_str}] {alert}Score: {current:.1f}/100 "
            f"({level}){delta_str} | "
            f"Events: {events_count} Detections: {det_count}"
        )

        # Append to log
        if log_path:
            with open(log_path, "a") as f:
                f.write(
                    f"{now_str},{current:.1f},{level},"
                    f"{events_count},{det_count}\n"
                )

        prev_score = current

        # Wait for next interval (check stop flag every second)
        for _ in range(interval_secs):
            if stop:
                break
            time.sleep(1)

    print(f"Watch stopped after {check_num} checks.")
    return 0


def main(argv: list[str] | None = None) -> int:
    """Main entry point."""
    setup_logging()
    args = parse_args(argv)

    if not args.command:
        parse_args(["--help"])
        return 1

    config = load_config(args.config)

    if args.command == "report":
        return run_report(args, config)
    elif args.command == "score":
        return run_score(args, config)
    elif args.command == "guardrail":
        return run_guardrail(args, config)
    elif args.command == "watch":
        return run_watch(args, config)

    return 0


if __name__ == "__main__":
    sys.exit(main())
