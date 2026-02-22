"""Shopify Admin API collector for order and checkout data."""

from __future__ import annotations

import os
from datetime import datetime
from typing import Any

import requests

from cad.collectors.base import BaseCollector
from cad.scoring.models import CommerceEvent, EventType


class ShopifyCollector(BaseCollector):
    """Collector that ingests order and checkout data from Shopify Admin API.

    Uses REST API with basic auth (API key + password). Supports
    generator-based pagination with since_id for efficient data retrieval.

    Required environment variables:
    - CAD_SHOPIFY_SHOP: Shop name (e.g., 'mystore' for mystore.myshopify.com)
    - CAD_SHOPIFY_API_KEY: Shopify Admin API key
    - CAD_SHOPIFY_PASSWORD: Shopify Admin API password/access token
    """

    def __init__(self, config: dict[str, Any] | None = None):
        super().__init__(config)
        self._shop = self.config.get("shop_name") or os.environ.get("CAD_SHOPIFY_SHOP", "")
        self._api_key = self.config.get("api_key") or os.environ.get("CAD_SHOPIFY_API_KEY", "")
        self._password = self.config.get("password") or os.environ.get("CAD_SHOPIFY_PASSWORD", "")
        self._api_version = self.config.get("api_version", "2024-01")

    @property
    def source_name(self) -> str:
        return "shopify"

    @property
    def _base_url(self) -> str:
        return f"https://{self._shop}.myshopify.com/admin/api/{self._api_version}"

    def validate_config(self) -> list[str]:
        errors = []
        if not self._shop:
            errors.append("Missing shop name (CAD_SHOPIFY_SHOP)")
        if not self._api_key:
            errors.append("Missing API key (CAD_SHOPIFY_API_KEY)")
        if not self._password:
            errors.append("Missing password (CAD_SHOPIFY_PASSWORD)")
        return errors

    def collect(
        self,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
    ) -> list[CommerceEvent]:
        """Collect orders and abandoned checkouts from Shopify."""
        events: list[CommerceEvent] = []
        events.extend(self._collect_orders(start_time, end_time))
        events.extend(self._collect_abandoned_checkouts(start_time, end_time))
        return sorted(events, key=lambda e: e.timestamp)

    def _collect_orders(
        self,
        start_time: datetime | None,
        end_time: datetime | None,
    ) -> list[CommerceEvent]:
        """Fetch orders using paginated REST API."""
        events = []
        params: dict[str, Any] = {
            "limit": 250,
            "status": "any",
            "fields": (
                "id,created_at,total_price,financial_status,currency,"
                "browser_ip,line_items,customer,billing_address"
            ),
        }

        if start_time:
            params["created_at_min"] = start_time.isoformat()
        if end_time:
            params["created_at_max"] = end_time.isoformat()

        for order in self._paginate("orders.json", params):
            event = self._order_to_event(order)
            if event:
                events.append(event)

        return events

    def _collect_abandoned_checkouts(
        self,
        start_time: datetime | None,
        end_time: datetime | None,
    ) -> list[CommerceEvent]:
        """Fetch abandoned checkouts."""
        events = []
        params: dict[str, Any] = {
            "limit": 250,
        }

        if start_time:
            params["created_at_min"] = start_time.isoformat()
        if end_time:
            params["created_at_max"] = end_time.isoformat()

        for checkout in self._paginate("checkouts.json", params):
            event = self._checkout_to_event(checkout)
            if event:
                events.append(event)

        return events

    def _paginate(self, endpoint: str, params: dict[str, Any]):
        """Generator-based pagination using since_id."""
        since_id = 0
        while True:
            if since_id:
                params["since_id"] = since_id

            url = f"{self._base_url}/{endpoint}"
            response = requests.get(
                url,
                params=params,
                auth=(self._api_key, self._password),
                timeout=30,
            )
            response.raise_for_status()

            data = response.json()
            # Extract the resource key (e.g., 'orders' from 'orders.json')
            resource_key = endpoint.replace(".json", "")
            items = data.get(resource_key, [])

            if not items:
                break

            for item in items:
                yield item

            since_id = items[-1]["id"]

            if len(items) < params.get("limit", 250):
                break

    def _order_to_event(self, order: dict) -> CommerceEvent | None:
        """Convert a Shopify order to a CommerceEvent."""
        try:
            # Determine payment status
            financial = order.get("financial_status", "")
            if financial in ("paid", "partially_paid"):
                payment_status = "paid"
            elif financial in ("refunded", "voided"):
                payment_status = financial
            else:
                payment_status = "failed"

            # Extract first line item info
            line_items = order.get("line_items", [])
            product_id = None
            product_title = None
            product_price = None
            if line_items:
                first_item = line_items[0]
                product_id = str(first_item.get("product_id", ""))
                product_title = first_item.get("title", "")
                product_price = float(first_item.get("price", 0))

            # Extract customer info
            customer = order.get("customer", {}) or {}
            billing = order.get("billing_address", {}) or {}

            return CommerceEvent(
                event_id=f"shopify_order_{order['id']}",
                event_type=EventType.ORDER,
                timestamp=datetime.fromisoformat(
                    order["created_at"].replace("Z", "+00:00")
                ),
                source="shopify",
                ip_address=order.get("browser_ip"),
                customer_id=str(customer.get("id", "")) if customer else None,
                email=customer.get("email"),
                product_id=product_id,
                product_title=product_title,
                product_price=product_price,
                order_total=float(order.get("total_price", 0)),
                currency=order.get("currency", "USD"),
                payment_status=payment_status,
                country_code=billing.get("country_code"),
                city=billing.get("city"),
                raw_data=order,
            )
        except (KeyError, ValueError):
            return None

    def _checkout_to_event(self, checkout: dict) -> CommerceEvent | None:
        """Convert a Shopify abandoned checkout to a CommerceEvent."""
        try:
            line_items = checkout.get("line_items", [])
            product_id = None
            product_title = None
            product_price = None
            if line_items:
                first_item = line_items[0]
                product_id = str(first_item.get("product_id", ""))
                product_title = first_item.get("title", "")
                product_price = float(first_item.get("price", 0))

            return CommerceEvent(
                event_id=f"shopify_checkout_{checkout['id']}",
                event_type=EventType.ABANDONED_CHECKOUT,
                timestamp=datetime.fromisoformat(
                    checkout["created_at"].replace("Z", "+00:00")
                ),
                source="shopify",
                ip_address=checkout.get("browser_ip"),
                email=checkout.get("email"),
                product_id=product_id,
                product_title=product_title,
                product_price=product_price,
                order_total=float(checkout.get("total_price", 0)),
                currency=checkout.get("currency", "USD"),
                payment_status="abandoned",
                raw_data=checkout,
            )
        except (KeyError, ValueError):
            return None
