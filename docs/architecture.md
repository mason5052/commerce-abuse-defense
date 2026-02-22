# Architecture

## System Design

Commerce Abuse Defense (CAD) follows a pipeline architecture:

```
Data Sources          Collectors         Detectors          Scoring         Reporters
+-----------+       +------------+     +------------+    +---------+     +----------+
| Shopify   |------>| Shopify    |--+  | High Freq  |    |         |     | JSON     |
| Admin API |       | Collector  |  |  | Hidden Prod|    |         |     | Markdown |
+-----------+       +------------+  |  | Pay Fail   |--->| Scoring |---->| Console  |
                                    |  | Session Exp|    | Engine  |     +----------+
+-----------+       +------------+  |  | Anom Agent |    |         |
| Cloudflare|------>| Cloudflare |--+->| Geo Conc   |    +---------+
| Analytics |       | Collector  |  |  +------------+
+-----------+       +------------+  |
                                    |
+-----------+       +------------+  |
| JSON      |------>| Sample     |--+
| Fixtures  |       | Collector  |
+-----------+       +------------+
```

## Data Flow

1. **Collection**: Collectors pull raw data from external APIs and normalize
   it into `CommerceEvent` objects
2. **Detection**: Each detector analyzes the event stream independently,
   producing `DetectionResult` objects when patterns are found
3. **Scoring**: The scoring engine aggregates all detection results using
   configurable weights per category, producing an `AbuseScore` (0-100)
4. **Reporting**: Reporters format the `AbuseReport` for consumption
   (machine-readable JSON, human-readable Markdown, or colored console)

## Key Design Decisions

- **Rule-based detection**: No ML models in Phase 1. Rules are transparent,
  auditable, and debuggable. ML can be layered on top in Phase 2.
- **Normalized events**: All platforms feed into a common `CommerceEvent`
  schema, making detectors platform-agnostic.
- **Configurable weights**: Scoring weights and thresholds are YAML-configurable,
  allowing tuning per site without code changes.
- **No Shopify SDK**: Uses raw REST API with `requests` for fewer dependencies
  and more control over pagination and error handling.

## Configuration

Configuration is loaded in priority order:
1. Environment variables (`CAD_*` prefix)
2. YAML config file (via `--config` flag)
3. Default values (built into `config.py`)
