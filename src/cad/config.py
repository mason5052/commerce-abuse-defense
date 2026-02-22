"""Configuration loading from environment variables and YAML files."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml

DEFAULT_CONFIG: dict[str, Any] = {
    "scoring": {
        "weights": {
            "high_frequency": 0.20,
            "hidden_product": 0.15,
            "payment_failure": 0.25,
            "session_explosion": 0.15,
            "anomalous_agent": 0.10,
            "geo_concentration": 0.15,
        },
        "thresholds": {
            "normal": 25,
            "elevated": 50,
            "high": 75,
        },
    },
    "detectors": {
        "high_frequency": {
            "max_events_per_ip": 10,
            "window_minutes": 5,
        },
        "hidden_product": {
            "hidden_price_threshold": 0.01,
            "hidden_keywords": ["warranty", "protection plan", "test product"],
        },
        "payment_failure": {
            "failure_rate_threshold": 0.3,
            "min_attempts": 5,
        },
        "session_explosion": {
            "baseline_multiplier": 3.0,
            "min_sessions": 50,
        },
        "anomalous_agent": {
            "known_bot_patterns": [
                "headlesschrome",
                "phantomjs",
                "python-requests",
                "go-http-client",
                "curl/",
                "wget/",
                "scrapy",
                "httpclient",
            ],
        },
        "geo_concentration": {
            "datacenter_asn_threshold": 0.3,
            "country_concentration_threshold": 0.8,
        },
    },
    "shopify": {
        "api_version": "2024-01",
    },
    "cloudflare": {
        "api_url": "https://api.cloudflare.com/client/v4/graphql",
    },
}


def load_config(config_path: str | Path | None = None) -> dict[str, Any]:
    """Load configuration from YAML file and environment variables.

    Priority (highest to lowest):
    1. Environment variables (CAD_* prefix)
    2. YAML config file
    3. Default values
    """
    config = _deep_copy_dict(DEFAULT_CONFIG)

    if config_path:
        path = Path(config_path)
        if path.exists():
            with open(path) as f:
                file_config = yaml.safe_load(f) or {}
            config = _deep_merge(config, file_config)

    _apply_env_overrides(config)
    return config


def _apply_env_overrides(config: dict[str, Any]) -> None:
    """Apply environment variable overrides to config."""
    env_mappings = {
        "CAD_SHOPIFY_SHOP": ("shopify", "shop_name"),
        "CAD_SHOPIFY_API_KEY": ("shopify", "api_key"),
        "CAD_SHOPIFY_PASSWORD": ("shopify", "password"),
        "CAD_CF_API_TOKEN": ("cloudflare", "api_token"),
        "CAD_CF_ZONE_ID": ("cloudflare", "zone_id"),
        "CAD_MONGO_URI": ("mongodb", "uri"),
        "CAD_MONGO_DB": ("mongodb", "database"),
    }

    for env_var, (section, key) in env_mappings.items():
        value = os.environ.get(env_var)
        if value:
            if section not in config:
                config[section] = {}
            config[section][key] = value


def _deep_merge(base: dict, override: dict) -> dict:
    """Recursively merge override dict into base dict."""
    result = base.copy()
    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def _deep_copy_dict(d: dict) -> dict:
    """Deep copy a nested dict structure."""
    result = {}
    for key, value in d.items():
        if isinstance(value, dict):
            result[key] = _deep_copy_dict(value)
        elif isinstance(value, list):
            result[key] = value.copy()
        else:
            result[key] = value
    return result
