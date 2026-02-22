# Threat Model

## Attack Patterns Detected by CAD

### 1. Card-Testing Attacks

**Description**: Criminals validate stolen credit card numbers by making small
purchases on eCommerce sites.

**Signal Chain**:
- High payment failure rate (>30%)
- Multiple unique emails from same IP
- Small transaction amounts ($0-$5)
- Targeting $0/warranty products
- Rapid succession of checkout attempts

**Business Impact**: Chargebacks, payment processor penalties, increased fraud rate
metrics, potential Shopify Payments account suspension.

**CAD Detection**: Rules CAD-001, CAD-002, CAD-003

### 2. Bot Scraping / Inventory Probing

**Description**: Automated bots scrape product data, pricing, and inventory
levels for competitive intelligence or to find exploitable pricing errors.

**Signal Chain**:
- Known bot user-agents
- Requests from datacenter ASNs
- No organic referrer chain
- High page view rate with no cart/checkout conversion

**Business Impact**: Server load, analytics pollution, competitive disadvantage,
bandwidth costs.

**CAD Detection**: Rules CAD-004, CAD-005, CAD-006

### 3. Analytics Pollution

**Description**: Bot traffic generates fake sessions and page views that corrupt
business analytics, leading to incorrect decisions about marketing spend,
product performance, and conversion optimization.

**Signal Chain**:
- Session explosion (hundreds of unique sessions per hour)
- Geographic anomalies (unexpected country dominance)
- Zero conversion rate from high-traffic sources
- Bounce rate < 1 second

**Business Impact**: Misleading analytics, wasted marketing budget on fake
traffic sources, incorrect A/B test results.

**CAD Detection**: Rules CAD-004, CAD-005, CAD-006

### 4. Account Enumeration

**Description**: Attackers test email/password combinations against the
customer login endpoint using credential stuffing lists.

**Signal Chain**:
- High-frequency login attempts from same IP
- Known bot user-agents on authentication endpoints
- Geographic concentration from unexpected regions

**Business Impact**: Account takeovers, customer data exposure, trust damage.

**CAD Detection**: Rules CAD-001, CAD-005, CAD-006

## Threat Severity Matrix

| Attack Type | Financial Impact | Data Impact | Detection Confidence |
|------------|-----------------|-------------|---------------------|
| Card-Testing | HIGH | LOW | HIGH |
| Bot Scraping | LOW | MEDIUM | MEDIUM |
| Analytics Pollution | MEDIUM | LOW | MEDIUM |
| Account Enumeration | HIGH | HIGH | MEDIUM |
