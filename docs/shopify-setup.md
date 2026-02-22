# Shopify Setup Guide

## Prerequisites

- Shopify store with Admin API access
- Custom app or private app credentials

## Step 1: Create a Custom App

1. In Shopify Admin, go to **Settings > Apps and sales channels**
2. Click **Develop apps** (enable if not already enabled)
3. Click **Create an app**
4. Name it "Commerce Abuse Defense"
5. Click **Configure Admin API scopes**
6. Enable these scopes:
   - `read_orders` -- access order data
   - `read_checkouts` -- access abandoned checkouts
   - `read_customers` -- access customer data (optional)
7. Click **Save** then **Install app**
8. Copy the **Admin API access token** (shown only once)

## Step 2: Configure CAD

Set the following environment variables:

```bash
export CAD_SHOPIFY_SHOP="your-store-name"      # e.g., "mystore" for mystore.myshopify.com
export CAD_SHOPIFY_API_KEY="your-api-key"       # From custom app credentials
export CAD_SHOPIFY_PASSWORD="your-access-token" # Admin API access token
```

Or add to a `.env` file (never commit this file):

```
CAD_SHOPIFY_SHOP=your-store-name
CAD_SHOPIFY_API_KEY=your-api-key
CAD_SHOPIFY_PASSWORD=your-access-token
```

## Step 3: Test Connection

```bash
cad report --source shopify --period 1h --format console
```

## API Rate Limits

Shopify Admin API has a leaky bucket rate limit:
- 2 requests/second for standard plans
- Higher limits for Shopify Plus

CAD respects these limits through its paginated collection approach.

## What Data is Collected

- **Orders**: ID, timestamp, total, payment status, browser IP, line items, customer email
- **Abandoned Checkouts**: ID, timestamp, total, browser IP, line items, email

No sensitive payment card data is accessed or stored.
