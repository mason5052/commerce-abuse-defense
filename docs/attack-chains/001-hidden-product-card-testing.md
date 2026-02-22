# Attack Chain 001: Hidden Product Card-Testing on Shopify

*Commerce Abuse Defense -- Attack Chain Analysis*
*Author: Mason Kim | February 2026*

---

## Summary

Attackers discover hidden, zero-price, or warranty products on Shopify stores
through API enumeration, then use these products to validate stolen credit
cards at minimal cost. This attack chain combines product discovery via the
Shopify Storefront API with card-testing through the checkout flow.

**MITRE ATT&CK Mapping**: T1595 (Active Scanning), T1190 (Exploit
Public-Facing Application)

**CAD Detection Rules**: CAD-002 (Hidden Product Targeting), CAD-003
(Payment Failure Spike), CAD-001 (High-Frequency Requests)

---

## 1. Attack Economics

Card-testing is a validation service. Attackers acquire stolen card numbers
from data breaches, phishing campaigns, or dark web marketplaces at $0.50-$5
per card (bulk). They need to determine which cards are still active before
selling them at 10-50x markup or using them for high-value fraud.

The economics favor low-cost testing:
- A $0.00 test product incurs $0 in chargebacks
- A $0.01 warranty product keeps test costs under payment processor minimums
- Even failed payment attempts reveal whether a card number is valid
  (declined vs. invalid format produces different error responses)

**Attacker profit model**: Buy 10,000 stolen cards at $2 each ($20K).
Validate 2,000 as active. Sell validated cards at $20-50 each ($40-100K).
Net profit: $20-80K per batch. Testing cost per card: $0 if using $0
products.

---

## 2. Discovery Phase: Finding Hidden Products

### 2.1 Shopify Storefront API Enumeration

Shopify exposes a public Storefront API that does not require authentication
for read operations. Any store with a storefront has this API available.

**Product listing endpoint (GraphQL)**:
```graphql
{
  products(first: 250) {
    edges {
      node {
        id
        title
        handle
        priceRange {
          minVariantPrice { amount }
          maxVariantPrice { amount }
        }
        availableForSale
        tags
      }
    }
  }
}
```

This returns ALL published products, including:
- Test products with $0.00 price (development artifacts)
- Warranty/protection plan add-ons (e.g., "Mulberry Protection")
- Hidden promotional products intended only for internal links
- Gift cards with unusual denominations

### 2.2 Product Handle Enumeration

Shopify product URLs follow a predictable pattern:
`https://store.myshopify.com/products/{handle}`

Attackers can enumerate handles through:
- Sitemap.xml (often lists all products including hidden ones)
- Google dorking: `site:store.myshopify.com inurl:products`
- Brute-force common handles: "test", "warranty", "protection", "sample"
- Shopify collection pages that inadvertently include hidden products

### 2.3 Real-World Evidence

From CAD analysis of a production Shopify store (7-day window):

```
8 events targeting hidden/zero-price products from 2 unique IPs

IP 75.141.171.17: 6 hidden product accesses
IP 23.234.101.249: 2 hidden product accesses
Targeted products: Mulberry Protection
```

The "Mulberry Protection" product is a warranty add-on that should only
appear as an upsell after a customer adds a main product to cart. Direct
access to this product by external IPs with no prior browse session is a
strong indicator of automated enumeration.

---

## 3. Execution Phase: Card Validation

Once hidden products are discovered, the attacker automates checkout:

### 3.1 Checkout Flow Automation

```
1. Create cart with hidden product (price: $0 or minimal)
2. Submit checkout with stolen card data
3. Observe response:
   - "Payment accepted" -> Card is valid and active
   - "Card declined" -> Card is valid but lacks funds or is frozen
   - "Invalid card number" -> Card number is invalid (discard)
   - "Transaction limit exceeded" -> Card is valid but rate-limited
4. Record card status
5. Repeat with next card
```

### 3.2 Evasion Techniques

Sophisticated attackers use several techniques to avoid detection:

**IP rotation**: Residential proxy networks (e.g., Bright Data, Oxylabs)
provide rotating IP addresses from real ISPs, making IP-based blocking
ineffective. Each request appears to come from a different residential
connection.

**Session management**: Each card test uses a fresh session with a unique
session ID, new cookies, and randomized browser fingerprint. This prevents
session-based rate limiting from triggering.

**UA rotation**: User-agents are randomly selected from a pool of real
browser UA strings. The attacker appears as Chrome 120 on Windows, Safari
on macOS, Firefox on Linux -- all in the same batch.

**Timing**: Requests are spaced at human-realistic intervals (3-15 seconds
between attempts) to avoid rate limiting. More advanced attackers add
jitter: normally distributed delays centered on 8 seconds.

**Email generation**: Each checkout uses a unique, disposable email address
from services like Guerrilla Mail, TempMail, or algorithmically generated
addresses at real-looking domains.

---

## 4. Detection Signatures

### 4.1 Primary Signal: Hidden Product Access (CAD-002)

The most reliable signal is access to products that legitimate customers
would never find through normal browse patterns.

Detection logic:
```python
# Flag events targeting hidden or underpriced products
if product_price <= 0.01:
    flag(severity=HIGH)
if any(kw in product_title.lower()
       for kw in ["warranty", "protection", "test"]):
    flag(severity=HIGH)
```

Key insight: This signal has very low false positive rate because
legitimate customers access warranty products only through upsell flows
that include a main product in the cart first. A checkout containing ONLY
a warranty product, from an IP with no prior browsing session on the store,
is almost certainly automated.

### 4.2 Supporting Signal: Payment Failure Rate (CAD-003)

Card-testing produces distinctive payment failure patterns:
- Global failure rate jumps from baseline 5-15% to 60-80%+
- Per-IP failure rates near 100% (attacker testing many bad cards)
- Small transaction amounts concentrated at $0-$5

### 4.3 Supporting Signal: IP Concentration (CAD-001)

Even with proxy rotation, attackers typically have a limited proxy pool.
The same /24 subnet appearing repeatedly in hidden product access is
suspicious.

### 4.4 Composite Score

CAD combines these signals through weighted scoring:

| Signal | Weight | Score Contribution |
|--------|--------|--------------------|
| Hidden Product (CAD-002) | 15% | 0-15 points |
| Payment Failure (CAD-003) | 25% | 0-25 points |
| High Frequency (CAD-001) | 20% | 0-20 points |

A pure hidden-product targeting attack without payment failures scores
~11-15 (Normal/Elevated). Adding card-testing failures pushes the score
to 50+ (High), triggering automatic guardrail recommendations.

---

## 5. Defense Playbook

### 5.1 Immediate: Hidden Product Protection

**Block direct checkout without prior browse session**:
```
# Cloudflare WAF expression
(http.request.uri.path contains "/cart/add" and
 http.request.uri.query contains "warranty" and
 not http.referer contains "products/")
```

**Restrict zero-price products**:
- Set minimum price >$0 (even $0.01 disrupts pure card validation)
- Require main product in cart before warranty can be added
- Remove hidden products from Storefront API using
  `published_scope: web` with collection-only visibility

### 5.2 Medium-Term: Rate Limiting

**Checkout rate limit per IP**:
```bash
# CAD generates this rule automatically
cad guardrail --source shopify --platform cloudflare --format commands
# Output: Checkout rate limit: 3 requests per 5 minutes per IP
```

**Referrer validation**:
Require that checkout requests include a valid referrer from the same
domain. Direct POST to checkout from external origins is blocked.

### 5.3 Long-Term: Attacker Cost Elevation

The goal is not to block all bots (impossible with residential proxies).
The goal is to increase the cost per card test above the economic
threshold where card-testing becomes unprofitable.

**JS Challenge on checkout**: A JavaScript challenge costs legitimate
users nothing (runs invisibly) but breaks `requests`/`curl` automation.
The attacker must upgrade to headless browser automation (higher cost,
slower, more detectable).

**CAPTCHA on high-risk checkouts**: If a checkout contains only warranty
products and the session has no prior page views, require a managed
challenge (CAPTCHA). This makes automation significantly more expensive
while not affecting legitimate upsell flows.

**Deferred payment processing**: Instead of returning immediate
accept/decline, queue the payment and return "processing". The attacker
cannot distinguish valid from invalid cards, eliminating the validation
signal entirely. This is the nuclear option -- highly effective but
requires custom checkout flow implementation.

---

## 6. CAD Integration

### Detection

```bash
# Detect hidden product targeting in real-time
cad watch --source shopify --period 1h --interval 5m --threshold 15

# Generate detailed report after alert
cad report --source shopify --period 24h --format markdown --output alert.md
```

### Response

```bash
# Auto-generate WAF rules from detected threats
cad guardrail --source shopify --platform cloudflare --format commands \
  --zone-id YOUR_ZONE_ID > deploy-rules.sh

# For AWS WAF
cad guardrail --source shopify --platform aws_waf --format commands \
  --web-acl-name production-acl > deploy-rules.sh
```

---

## 7. Indicators of Compromise

| IOC Type | Pattern | Confidence |
|----------|---------|------------|
| Product targeting | Direct access to $0/warranty products without browse session | HIGH |
| IP behavior | Multiple hidden product accesses from same IP within 1 hour | HIGH |
| Payment pattern | >30% payment failure rate with small amounts from same IP | CRITICAL |
| Checkout pattern | Cart contains only warranty/protection products | HIGH |
| Session pattern | New session -> direct product URL -> immediate checkout | MEDIUM |
| Email pattern | Disposable/temporary email domains on checkout | MEDIUM |

---

## References

- Shopify Storefront API: https://shopify.dev/docs/api/storefront
- MITRE ATT&CK T1595: https://attack.mitre.org/techniques/T1595/
- MITRE ATT&CK T1190: https://attack.mitre.org/techniques/T1190/
- CAD Detection Rule CAD-002: src/cad/detectors/hidden_product.py
- CAD Detection Rule CAD-003: src/cad/detectors/payment_failure.py

---

*This analysis is based on real attack patterns observed in production
eCommerce environments. Product names and specific IP addresses are
included as illustrative examples from sanitized data. No exploit code
is provided -- this document focuses on detection and defense.*
