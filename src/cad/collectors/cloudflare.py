"""Cloudflare Analytics API collector for traffic and bot detection data."""

from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any

import requests

from cad.collectors.base import BaseCollector
from cad.scoring.models import CommerceEvent, EventType


class CloudflareCollector(BaseCollector):
    """Collector that ingests traffic analytics from Cloudflare GraphQL API.

    Uses the Cloudflare Analytics API to fetch:
    - HTTP request data (volume, user agents, countries, ASNs)
    - Firewall events (blocked/challenged requests)
    - Bot management signals

    Required environment variables:
    - CAD_CF_API_TOKEN: Cloudflare API token with Analytics:Read permission
    - CAD_CF_ZONE_ID: Cloudflare zone ID for the target domain
    """

    GRAPHQL_URL = "https://api.cloudflare.com/client/v4/graphql"

    def __init__(self, config: dict[str, Any] | None = None):
        super().__init__(config)
        self._api_token = (
            self.config.get("api_token") or os.environ.get("CAD_CF_API_TOKEN", "")
        )
        self._zone_id = (
            self.config.get("zone_id") or os.environ.get("CAD_CF_ZONE_ID", "")
        )

    @property
    def source_name(self) -> str:
        return "cloudflare"

    def validate_config(self) -> list[str]:
        errors = []
        if not self._api_token:
            errors.append("Missing API token (CAD_CF_API_TOKEN)")
        if not self._zone_id:
            errors.append("Missing zone ID (CAD_CF_ZONE_ID)")
        return errors

    def collect(
        self,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
    ) -> list[CommerceEvent]:
        """Collect traffic and firewall data from Cloudflare."""
        if not start_time:
            start_time = datetime.now(timezone.utc)
        if not end_time:
            end_time = datetime.now(timezone.utc)

        events: list[CommerceEvent] = []
        events.extend(self._collect_firewall_events(start_time, end_time))
        return sorted(events, key=lambda e: e.timestamp)

    def _collect_firewall_events(
        self,
        start_time: datetime,
        end_time: datetime,
    ) -> list[CommerceEvent]:
        """Fetch firewall events using Cloudflare GraphQL API."""
        query = """
        query GetFirewallEvents($zoneTag: String!, $since: String!, $until: String!) {
          viewer {
            zones(filter: {zoneTag: $zoneTag}) {
              firewallEventsAdaptiveGroups(
                filter: {
                  datetime_gt: $since,
                  datetime_lt: $until
                }
                limit: 1000
                orderBy: [datetime_ASC]
              ) {
                count
                dimensions {
                  action
                  clientASNDescription
                  clientAsn
                  clientCountryName
                  clientIP
                  clientRequestHTTPHost
                  clientRequestHTTPMethodName
                  clientRequestPath
                  datetime
                  userAgent
                }
              }
            }
          }
        }
        """

        variables = {
            "zoneTag": self._zone_id,
            "since": start_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "until": end_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        }

        data = self._graphql_request(query, variables)
        events: list[CommerceEvent] = []

        zones = data.get("viewer", {}).get("zones", [])
        if not zones:
            return events

        fw_groups = zones[0].get("firewallEventsAdaptiveGroups", [])
        for i, group in enumerate(fw_groups):
            dims = group.get("dimensions", {})
            event = self._fw_event_to_commerce_event(dims, i)
            if event:
                events.append(event)

        return events

    def _graphql_request(self, query: str, variables: dict) -> dict:
        """Execute a GraphQL query against Cloudflare Analytics API."""
        response = requests.post(
            self.GRAPHQL_URL,
            json={"query": query, "variables": variables},
            headers={
                "Authorization": f"Bearer {self._api_token}",
                "Content-Type": "application/json",
            },
            timeout=30,
        )
        response.raise_for_status()

        result = response.json()
        if result.get("errors"):
            error_msgs = [e.get("message", "Unknown error") for e in result["errors"]]
            raise RuntimeError(f"Cloudflare API errors: {'; '.join(error_msgs)}")

        return result.get("data", {})

    def _fw_event_to_commerce_event(
        self, dims: dict, index: int
    ) -> CommerceEvent | None:
        """Convert a Cloudflare firewall event to a CommerceEvent."""
        try:
            timestamp_str = dims.get("datetime", "")
            if not timestamp_str:
                return None

            asn = dims.get("clientAsn")
            if isinstance(asn, str):
                try:
                    asn = int(asn)
                except ValueError:
                    asn = None

            return CommerceEvent(
                event_id=f"cf_fw_{index}_{timestamp_str}",
                event_type=EventType.PAGE_VIEW,
                timestamp=datetime.fromisoformat(
                    timestamp_str.replace("Z", "+00:00")
                ),
                source="cloudflare",
                ip_address=dims.get("clientIP"),
                user_agent=dims.get("userAgent"),
                country_code=dims.get("clientCountryName"),
                asn=asn,
                asn_org=dims.get("clientASNDescription"),
                request_path=dims.get("clientRequestPath"),
                http_method=dims.get("clientRequestHTTPMethodName"),
                raw_data=dims,
            )
        except (KeyError, ValueError):
            return None
