# Playbook: Analytics Pollution Response

## Attack Pattern

Bot traffic pollutes analytics data (Google Analytics, Shopify Analytics),
making business decisions unreliable. Symptoms:

- Inflated page view counts
- Skewed conversion rates (high visits, low purchases)
- Bounce rate anomalies
- Geographic distribution shifts (unexpected country dominance)
- Revenue attribution errors from bot-generated sessions

## Detection Rules

- **CAD-004**: Session explosion (inflated session counts)
- **CAD-006**: Geo/ASN concentration (datacenter traffic skewing geo data)
- **CAD-005**: Anomalous user-agents (non-browser traffic in analytics)

## Immediate Response

1. **Add GA4 bot filtering** -- enable "Exclude all hits from known bots and spiders"
2. **Create Shopify Analytics segments** excluding known bot traffic patterns
3. **Review Cloudflare Analytics** vs Shopify Analytics for discrepancies
4. **Block bot traffic at edge** to prevent it from reaching analytics trackers

## Analytics Cleanup

- Compare Cloudflare Analytics (server-side) with GA4 (client-side)
  - If Cloudflare shows 10x more traffic than GA4, most excess is bots
  - Cloudflare bot score < 30 = likely automated
- Create custom GA4 audience excluding:
  - Sessions < 2 seconds
  - Sessions from datacenter ASNs
  - Sessions with known bot referrers

## Long-Term Prevention

- Move to server-side analytics where possible (Cloudflare Analytics)
- Implement Consent Mode v2 with bot filtering
- Set up automated weekly reports comparing CF vs GA4 metrics
- Use CAD abuse scores to weight analytics confidence
