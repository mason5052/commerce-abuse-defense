# Commerce Abuse Defense (CAD)

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![CI](https://github.com/mason5052/commerce-abuse-defense/actions/workflows/ci.yml/badge.svg)](https://github.com/mason5052/commerce-abuse-defense/actions)

**Detect and score bot abuse, card-testing, and fraud on eCommerce sites.**

---

## Problem

eCommerce platforms face constant automated attacks that existing defenses handle poorly:

- **Card-testing bots** validate stolen credit cards through checkout flows, causing chargebacks and payment processor penalties
- **Scraper bots** from datacenter ASNs pollute analytics, inflate traffic metrics, and probe for pricing errors
- **Hidden product exploits** target $0/warranty products via direct URL, bypassing normal browse flows
- **Session flooding** generates thousands of fake sessions, corrupting conversion rate data and A/B test results

Shopify's native fraud tools and marketplace apps provide per-order risk scores, but lack **aggregate abuse pressure measurement** -- the ability to answer: "How much bot pressure is my site under right now?"

CAD fills this gap by computing an **Abuse Score** (0-100) from multiple data sources, giving operators a single metric to monitor and act on.

## Architecture

```
Data Sources          Collectors         Detectors          Scoring         Reporters
+-----------+       +------------+     +------------+    +---------+     +----------+
| Shopify   |------>| Shopify    |--+  | High Freq  |    |         |     | JSON     |
| Admin API |       | Collector  |  |  | Hidden Prod|    |         |     | Markdown |
+-----------+       +------------+  |  | Pay Fail   |--->| Scoring |---->| Console  |
                                    |  | Session Exp|    | Engine  |     +----------+
+-----------+       +------------+  |  | Anom Agent |    |         |
| Cloudflare|------>| Cloudflare |--+->| Geo Conc   |    +---------+
| Analytics |       | Collector  |  |  +------------+
+-----------+       +------------+  |
                                    |
+-----------+       +------------+  |
| JSON      |------>| Sample     |--+
| Fixtures  |       | Collector  |
+-----------+       +------------+
```

## Quick Start

```bash
# Clone
git clone https://github.com/mason5052/commerce-abuse-defense.git
cd commerce-abuse-defense

# Install
pip install -e ".[dev]"

# Run with sample data (no API keys needed)
cad report --source sample --format console
```

## Repository Structure

```
commerce-abuse-defense/
|-- src/cad/
|   |-- cli.py                    # CLI entry point
|   |-- config.py                 # Configuration (env vars + YAML)
|   |-- collectors/
|   |   |-- base.py               # Abstract collector interface
|   |   |-- shopify.py            # Shopify Admin API collector
|   |   |-- cloudflare.py         # Cloudflare Analytics API collector
|   |   |-- sample.py             # Sample data (demo/testing)
|   |-- detectors/
|   |   |-- base.py               # Abstract detector interface
|   |   |-- high_frequency.py     # Rapid-fire request detection
|   |   |-- hidden_product.py     # $0/warranty product targeting
|   |   |-- payment_failure.py    # Card-testing signal detection
|   |   |-- session_explosion.py  # Bot swarm indicator
|   |   |-- anomalous_agent.py    # Suspicious UA patterns
|   |   |-- geo_concentration.py  # Datacenter ASN traffic
|   |-- scoring/
|   |   |-- engine.py             # Weighted score aggregation
|   |   |-- models.py             # Pydantic data models
|   |-- reporters/
|   |   |-- json_reporter.py      # Machine-readable output
|   |   |-- markdown_reporter.py  # Human-readable reports
|   |   |-- console_reporter.py   # Colored terminal output
|   |-- playbooks/                # Response playbooks
|-- tests/                        # Unit tests + fixtures
|-- docs/                         # Setup guides + threat model
|-- examples/                     # Quickstart script + demo report
```

## Detection Rules

| Rule | ID | What It Detects | Severity |
|------|----|-----------------|----------|
| High-Frequency Requests | CAD-001 | >N events from same IP in M minutes | HIGH |
| Hidden Product Targeting | CAD-002 | Direct access to $0/warranty/test products | HIGH |
| Payment Failure Spike | CAD-003 | Payment failure rate above baseline (card-testing) | CRITICAL |
| Session Explosion | CAD-004 | Sudden increase in unique sessions/devices | MEDIUM |
| Anomalous User-Agent | CAD-005 | Known bot UAs, headless browsers, missing UA | MEDIUM |
| Geo/ASN Concentration | CAD-006 | Traffic from datacenter ASNs, unexpected geo patterns | LOW-MEDIUM |

## Abuse Score Scale

| Score | Threat Level | Meaning |
|-------|-------------|---------|
| 0-25 | Normal | Typical eCommerce traffic |
| 25-50 | Elevated | Unusual patterns, worth monitoring |
| 50-75 | High | Likely active abuse, action recommended |
| 75-100 | Critical | Active attack, immediate action required |

## Usage

```bash
# Full report with sample data
cad report --source sample --format markdown --output report.md

# Quick score check
cad score --source sample --period 1h

# With real Shopify + Cloudflare data
export CAD_SHOPIFY_SHOP="your-store"
export CAD_SHOPIFY_API_KEY="your-key"
export CAD_SHOPIFY_PASSWORD="your-token"
export CAD_CF_API_TOKEN="your-cf-token"
export CAD_CF_ZONE_ID="your-zone-id"

cad report --source shopify,cloudflare --period 24h --format json
```

## Configuration

| Variable | Description | Required For |
|----------|-------------|-------------|
| `CAD_SHOPIFY_SHOP` | Shopify store name | Shopify source |
| `CAD_SHOPIFY_API_KEY` | Shopify Admin API key | Shopify source |
| `CAD_SHOPIFY_PASSWORD` | Shopify Admin API token | Shopify source |
| `CAD_CF_API_TOKEN` | Cloudflare API token | Cloudflare source |
| `CAD_CF_ZONE_ID` | Cloudflare zone ID | Cloudflare source |

All configuration can also be set via YAML file (`--config cad.yml`).

## Roadmap

- **Phase 1** (current): Abuse Score Reporter -- batch analysis, rule-based detection, CLI output
- **Phase 2**: Automated Guardrails -- real-time blocking, Cloudflare WAF rule generation, Shopify Flow integration
- **Phase 3**: Attack Chain Documentation -- published attack pattern research, adversarial eCommerce security guides

## Author

**Mason Kim** -- DevSecOps Engineer | Georgia Tech MS Cybersecurity

- GitHub: [@mason5052](https://github.com/mason5052)
- LinkedIn: [Mason Kim](https://www.linkedin.com/in/mason-kim-b5458816a/)

Built from real operational pain defending eCommerce sites against intelligent bot attacks.

## License

[MIT](LICENSE)
