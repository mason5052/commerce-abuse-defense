# Changelog

All notable changes to this project will be documented in this file.

## [0.1.0] - 2026-02-21

### Added
- Initial release of Commerce Abuse Defense
- 6 detection rules: high-frequency, hidden product, payment failure, session explosion, anomalous agent, geo concentration
- Scoring engine with weighted aggregation (0-100 scale)
- Sample data collector for demo/testing without API keys
- Shopify Admin API collector
- Cloudflare Analytics API collector
- JSON, Markdown, and Console reporters
- CLI interface (`cad report`, `cad score`)
- Response playbooks for card-testing, bot traffic, analytics pollution
