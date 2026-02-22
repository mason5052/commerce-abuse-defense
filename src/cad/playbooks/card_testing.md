# Playbook: Card-Testing Attack Response

## Attack Pattern

Attackers use stolen credit card numbers and test them against eCommerce checkout
flows. The signature:

- High payment failure rates (>30% in short windows)
- Multiple unique emails from same IP
- Small transaction amounts ($0-$5)
- Rapid succession of checkout attempts
- Often targets $0 or low-value products

## Detection Rules

- **CAD-003**: Payment failure rate spike
- **CAD-002**: Hidden product targeting ($0 products)
- **CAD-001**: High-frequency requests from same IP

## Immediate Response

1. **Block attacking IPs** in Cloudflare Firewall (WAF custom rule)
2. **Enable CAPTCHA** on checkout page via Cloudflare Managed Challenge
3. **Rate limit** payment endpoint (max 3 attempts per session per 5 minutes)
4. **Remove or restrict** $0/test products from direct URL access

## Cloudflare WAF Rule Example

```
(http.request.uri.path contains "/checkout" and
 ip.src in {198.51.100.0/24} and
 cf.bot_management.score lt 30)
```
Action: Block

## Shopify-Side Mitigations

- Enable Shopify Fraud Analysis on all orders
- Set payment capture to manual for orders from flagged regions
- Remove hidden/test products or set them to "not visible" in sales channels
- Consider Shopify Flow automation to auto-cancel orders matching card-test patterns

## Long-Term Prevention

- Implement 3D Secure (3DS) for all transactions
- Deploy Cloudflare Bot Management (Enterprise)
- Add device fingerprinting at checkout
- Monitor and rotate API keys if bots use Admin API
