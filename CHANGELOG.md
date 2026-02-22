# Changelog

All notable changes to this project will be documented in this file.

## [0.2.0] - 2026-02-22

### Added
- Guardrail Generator: auto-generate WAF rules from abuse analysis
- Cloudflare WAF rule generation (firewall expressions, rate limiting)
- AWS WAF v2 rule generation (IPSet, ByteMatch, RateBasedStatement)
- Multi-platform CLI: `cad guardrail --platform cloudflare|aws_waf`
- Export formats: JSON (API payload) and CLI commands (curl/aws-cli)
- 5 defense rule types: IP block, bot UA challenge, checkout rate limit, hidden product protection, session flood defense
- Threat-to-action mapping: CRITICAL->Block, HIGH->CAPTCHA, MEDIUM->Count
- Technical blog post: "Measuring Bot Abuse on eCommerce Sites"

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
