# Cloudflare Setup Guide

## Prerequisites

- Cloudflare account with the target domain proxied
- API token with Analytics read permissions

## Step 1: Create API Token

1. Go to [Cloudflare Dashboard](https://dash.cloudflare.com/profile/api-tokens)
2. Click **Create Token**
3. Use the **Custom Token** template
4. Configure permissions:
   - **Zone > Analytics > Read**
   - **Zone > Firewall Services > Read**
5. Set **Zone Resources** to your specific zone
6. Click **Continue to summary** then **Create Token**
7. Copy the token (shown only once)

## Step 2: Find Zone ID

1. In Cloudflare Dashboard, select your domain
2. On the **Overview** page, scroll down to the right sidebar
3. Copy the **Zone ID** value

## Step 3: Configure CAD

```bash
export CAD_CF_API_TOKEN="your-cloudflare-api-token"
export CAD_CF_ZONE_ID="your-zone-id"
```

## Step 4: Test Connection

```bash
cad report --source cloudflare --period 24h --format console
```

## What Data is Collected

CAD queries the Cloudflare GraphQL Analytics API for:

- **Firewall Events**: Blocked/challenged requests with IP, UA, country, ASN, path
- **HTTP Requests**: Request volume, user agents, geographic distribution

The GraphQL endpoint: `https://api.cloudflare.com/client/v4/graphql`

## Data Retention

Cloudflare retains analytics data based on your plan:
- Free: 24 hours
- Pro: 72 hours
- Business: 30 days
- Enterprise: 90+ days

Adjust your `--period` flag accordingly.
