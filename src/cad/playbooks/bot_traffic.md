# Playbook: Bot Traffic Response

## Attack Pattern

Automated bots scrape product data, test site defenses, or generate fake traffic
for analytics pollution. Signatures:

- Known bot user-agents (python-requests, headless browsers, curl)
- High session creation rate (many unique sessions in short windows)
- Traffic from datacenter ASNs (AWS, GCP, Azure, DigitalOcean)
- No referrer or organic search entry
- Abnormal page view patterns (no browsing flow, direct to checkout)

## Detection Rules

- **CAD-005**: Anomalous user-agent patterns
- **CAD-004**: Session explosion
- **CAD-006**: Geo/ASN concentration from datacenters

## Immediate Response

1. **Block known bot UAs** at the edge via Cloudflare WAF rule
2. **Challenge datacenter ASNs** with Managed Challenge
3. **Rate limit** by IP on all endpoints (Cloudflare Rate Limiting)
4. **Enable JS Challenge** for requests without referrer to checkout pages

## Cloudflare WAF Rules

Block known automation tools:
```
(http.user_agent contains "python-requests" or
 http.user_agent contains "Go-http-client" or
 http.user_agent contains "HeadlessChrome" or
 http.user_agent contains "PhantomJS" or
 http.user_agent contains "curl/" or
 http.user_agent contains "wget/" or
 http.user_agent contains "scrapy")
```
Action: Block

Challenge datacenter traffic:
```
(ip.geoip.asnum in {16509 14618 15169 396982 8075 14061 16276 24940})
```
Action: Managed Challenge

## Long-Term Prevention

- Deploy Cloudflare Bot Management with ML scoring
- Implement server-side bot detection (TLS fingerprinting)
- Add honeypot fields to forms (hidden inputs that only bots fill)
- Monitor Cloudflare Bot Analytics dashboard for trend changes
