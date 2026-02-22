# Measuring Bot Abuse on eCommerce Sites: A Quantitative Approach

*By Mason Kim | February 2026*

---

## The Problem Nobody Measures

Every eCommerce site gets attacked by bots. Card-testing rings probe checkout
endpoints with stolen credit card numbers. Scraper bots harvest product data and
pricing. Credential stuffing bots try leaked username/password pairs against
customer accounts. Inventory bots snap up limited-edition drops before real
customers can load the page.

Most teams know bots are a problem. Few can answer the question: **how bad is it
right now?**

I run eCommerce operations for a company with multiple Shopify stores generating
eight-figure annual revenue. We use Cloudflare for edge security, Shopify's
native fraud detection, and a third-party bot mitigation service. Despite this
stack, we regularly see:

- Payment failure rates spiking to 80%+ during card-testing attacks
- Hidden/zero-price products (warranties, test products) being directly accessed
  by bots that bypass normal browse patterns
- Checkout endpoints hammered by 10+ requests per minute from single IPs
- 70-80% of traffic originating from datacenter ASNs (AWS, GCP) instead of
  residential ISPs

The existing defenses catch some of it. The problem is that none of them give us
a single number that answers: "On a scale of 0-100, how much abuse is hitting
us right now?" Without that number, every security conversation becomes
subjective. "It seems like bot traffic is up" is not actionable. "Our abuse
score jumped from 25 to 72 in the last 6 hours" is.

## What an Abuse Score Looks Like

I built [Commerce Abuse Defense (CAD)](https://github.com/mason5052/commerce-abuse-defense),
an open-source Python tool that computes this score. It ingests events from
Shopify (orders, abandoned checkouts) and Cloudflare (firewall events, traffic
analytics), runs them through six detection rules, and produces a weighted
composite score from 0-100.

The score breaks down into categories:

| Category | Weight | What It Detects |
|----------|--------|-----------------|
| Payment Failure | 25% | Card-testing: high failure rates, multiple emails per IP, small amounts |
| High Frequency | 20% | Rapid-fire requests from single IPs exceeding thresholds |
| Hidden Product | 15% | Direct access to $0/warranty/test products without browse session |
| Session Explosion | 15% | Sudden spike in unique sessions -- bot swarm indicator |
| Geo/ASN Concentration | 15% | Traffic dominated by datacenter ASNs (AWS, GCP, Azure) |
| Anomalous User-Agent | 10% | Known bot UA patterns (python-requests, headless Chrome, curl) |

Each detection rule produces results with a severity (LOW/MEDIUM/HIGH/CRITICAL)
and confidence score (0-100%). The scoring engine takes the highest-severity
detection per category, multiplies by confidence, adds a volume boost for
multiple detections, and computes the weighted total.

Thresholds:
- **0-25: Normal** -- Typical eCommerce traffic patterns
- **25-50: Elevated** -- Unusual patterns worth monitoring
- **50-75: High** -- Likely active abuse, action recommended
- **75-100: Critical** -- Active attack, immediate action required

## The Six Detection Rules, Explained

### Rule 1: Payment Failure Rate (CAD-003) -- Most Critical Signal

Card-testing is the most economically damaging bot attack pattern on eCommerce.
Attackers use stolen card numbers to make small purchases ($1-5) to validate
which cards are still active. The validated cards are then sold on dark web
marketplaces or used for larger fraudulent purchases elsewhere.

Detection logic:
- **Global rate:** If overall payment failure rate exceeds 30% (configurable),
  trigger CRITICAL severity
- **Per-IP analysis:** If a single IP has >50% failure rate with multiple unique
  email addresses and small transaction amounts, flag as card-testing pattern

Why this matters: A legitimate store might have a 5-15% payment failure rate
(expired cards, insufficient funds, typos). When the rate jumps to 60-80%, it
is almost certainly card-testing. The combination of high failure rate + multiple
emails + small amounts is the signature.

### Rule 2: Hidden Product Targeting (CAD-002)

Every Shopify store has products that should not be directly accessible:
- $0.00 test products used during development
- Extended warranty products that should only appear as upsells
- Protection plans with intentionally low prices

Bots that enumerate product catalogs via the Shopify Storefront API discover
these products and attempt checkout. A human customer browsing your site would
never find a hidden warranty product -- they access it only through the upsell
flow after adding a main product to cart.

Detection logic:
- Flag any order/checkout event targeting products with price <= $0.01
- Flag products with keywords: "warranty", "protection plan", "test"
- Severity increases with volume and IP concentration

### Rule 3: High-Frequency Requests (CAD-001)

Simple but effective: count events per IP within a sliding time window.
Legitimate customers rarely generate more than 5-10 events in 5 minutes.
A bot hitting checkout at 3 requests/second generates hundreds.

The key insight is that this rule should not block at the firewall level (that
creates false positives). Instead, it feeds into the composite score. A single
high-frequency IP might be a power user. A high-frequency IP combined with
card-testing patterns and datacenter ASN origin is definitely a bot.

### Rule 4: Session Explosion (CAD-004)

Legitimate traffic has a stable ratio of sessions to events. A real customer
creates one session and generates 10-50 events (page views, cart adds, checkout
steps). Bot swarms create thousands of unique sessions, each generating 1-3
events.

Detection: Calculate the session-to-event ratio. If unique_sessions /
total_events exceeds 0.7 (configurable), it signals that most "sessions" are
actually individual bot instances.

### Rule 5: Anomalous User-Agent (CAD-005)

The lowest-confidence signal, but useful in combination. Known bot UA patterns:
`python-requests`, `HeadlessChrome`, `curl/`, `Go-http-client`, `Scrapy`.

Sophisticated attackers rotate user-agents, so this catches only the lazy
automation. But on a Shopify store where 99% of legitimate traffic comes from
Chrome, Safari, and Firefox on real devices, even one `python-requests` session
making purchases is suspicious.

### Rule 6: Geo/ASN Concentration (CAD-006)

The most underrated signal. Legitimate eCommerce traffic comes from residential
ISPs (Comcast, AT&T, Verizon). Bot traffic overwhelmingly originates from cloud
providers: AWS (ASN 16509), Google Cloud (ASN 15169), DigitalOcean (ASN 14061).

Detection: Calculate the percentage of traffic from known datacenter ASNs. If
it exceeds 30% (configurable), flag it. A US-based store seeing 80% of traffic
from Amazon AWS in Romania is under attack.

## From Detection to Defense: Automatic Guardrail Generation

Knowing your abuse score is step one. Step two is automated response.

CAD includes a guardrail generator that converts abuse analysis into deployable
Cloudflare WAF rules:

```bash
# Analyze sample data and generate Cloudflare WAF rules
cad guardrail --source sample --format json --output rules.json

# Generate as curl commands for manual deployment
cad guardrail --source sample --format commands --zone-id YOUR_ZONE_ID
```

The generator maps threat severity to defense strategy:
- **CRITICAL threats** (confirmed card-testing IPs) -> Block
- **HIGH threats** (bot user-agents) -> Managed Challenge (CAPTCHA)
- **MEDIUM threats** (datacenter ASN on checkout) -> JS Challenge
- **LOW threats** -> Log only

The principle is "increase attacker cost" rather than blanket blocking. A JS
challenge costs legitimate users nothing (executes invisibly in the browser)
but breaks `python-requests` automation. A managed challenge (CAPTCHA) disrupts
semi-automated tools. A full block is reserved for confirmed attackers.

Generated rules include:
1. IP blocklist from confirmed attacking IPs
2. Bot UA challenge rules
3. Datacenter ASN + sensitive path filtering
4. Checkout rate limiting (3 requests per 5 minutes per IP)
5. Hidden product referrer validation
6. New session JS challenge during active attacks

## Why Existing Tools Fall Short

Shopify's built-in fraud analysis is order-level, not traffic-level. It tells
you if a specific order is suspicious after the order is placed. It cannot tell
you that your checkout endpoint is being probed at 100 requests/minute from
datacenter IPs with `python-requests` user-agents.

Bot mitigation services (we use one) operate as black boxes. They block some
bots, but provide limited visibility into what they are blocking and why. When a
card-testing attack gets through, the service says it blocked 90% of bots -- but
the 10% that got through generated $50K in chargebacks.

Cloudflare's analytics dashboard shows traffic patterns, but it does not
correlate traffic data with Shopify order data. You can see that 80% of requests
came from AWS, but you cannot see that those AWS requests are the same ones
generating failed payments in Shopify.

CAD bridges this gap by correlating signals across platforms into a single
quantified metric.

## Getting Started

```bash
# Clone and install
git clone https://github.com/mason5052/commerce-abuse-defense.git
cd commerce-abuse-defense
pip install -e .

# Run with sample data (no API keys needed)
cad report --source sample --format markdown --output report.md

# Quick score check
cad score --source sample

# Generate WAF rules
cad guardrail --source sample --format json
```

The sample data includes realistic attack patterns based on real incidents --
card-testing from datacenter IPs, hidden product enumeration, bot user-agents.
The generated report shows exactly what CAD detects and how it scores.

For production use with real data, configure Shopify API credentials and
Cloudflare API token. See the
[Shopify setup guide](https://github.com/mason5052/commerce-abuse-defense/blob/main/docs/shopify-setup.md)
and
[Cloudflare setup guide](https://github.com/mason5052/commerce-abuse-defense/blob/main/docs/cloudflare-setup.md).

## What's Next

Phase 1 (current): Detection and scoring with manual report generation.

Phase 2 (in progress): Automatic guardrail generation -- Cloudflare WAF rules
produced directly from abuse analysis. Already functional for Cloudflare; AWS
WAF and Shopify Flow support coming next.

Phase 3 (planned): Attack chain documentation -- detailed writeups of real
attack patterns observed in production, with detection signatures and defense
playbooks.

The long-term goal is a tool that any eCommerce operator can run to get
quantified visibility into bot abuse -- and then deploy automated defenses
directly from the analysis.

---

*Mason Kim is a DevSecOps Engineer with experience running eCommerce operations
under adversarial conditions. He is pursuing an MS in Cybersecurity at Georgia
Tech. The Commerce Abuse Defense project is open source at
[github.com/mason5052/commerce-abuse-defense](https://github.com/mason5052/commerce-abuse-defense).*
