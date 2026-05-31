## Why

LiteWaf has completed the MVP protection loop and management capabilities, but operators still lack a reliable way to trace gateway traffic, investigate WAF matches, and understand protection trends from real runtime data. This change starts the stage 3 observability work so access logs, attack logs, and dashboard metrics become queryable and verifiable instead of remaining only local gateway output.

## What Changes

- Add structured gateway access logs for proxied, blocked, rejected, and rate-limited requests.
- Add structured WAF event logs for rule, access-list, and rate-limit matches with enough request and disposition metadata for investigation.
- Add control-plane APIs and persistence for receiving, storing, filtering, and summarizing access and attack logs.
- Add dashboard pages backed by real APIs for attack log search, access log search, and operational metrics.
- Add basic Prometheus-compatible metrics for API and gateway health, request volume, blocked requests, and WAF matches.
- Keep Docker Compose deployment compatible with the existing lightweight stack; optional log collection or ClickHouse integration may be introduced behind configuration rather than becoming mandatory for local development.

## Capabilities

### New Capabilities

- `gateway-observability`: Gateway-side structured access/WAF logging and metrics behavior.
- `log-management`: Control-plane ingestion, persistence, filtering, retention-safe empty states, and dashboard log search behavior.
- `dashboard-observability`: Dashboard metrics and log analysis views backed by real API data.
- `metrics-exposure`: Prometheus-compatible metrics endpoints and basic runtime counters for API and gateway services.

### Modified Capabilities

- `gateway-enforcement`: Gateway enforcement requirements are extended so every block, allow, reject, and rate-limit disposition can be correlated with structured observability output.

## Impact

- Affects `codes/litewaf-gateway` logging, request context, and metrics endpoints.
- Affects `codes/litewaf-api` storage interfaces, database schema/migrations, API routes, log ingestion, log query, and summary endpoints.
- Affects `codes/litewaf-dashboard` navigation, API client types, attack/access log pages, and dashboard metric components.
- Affects `deploy/docker-compose.yml`, environment templates, and deployment documentation for optional log collection, metrics scraping, and persistent log storage.
