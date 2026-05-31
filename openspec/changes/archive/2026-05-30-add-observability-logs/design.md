## Context

LiteWaf currently has a working management plane, publish flow, and OpenResty gateway enforcement loop. Gateway enforcement already emits some structured WAF logs for matches, but stage 3 requires a broader observability loop: every request should produce structured access data, enforcement events should be correlatable, operators should query logs from the dashboard, and Prometheus-compatible metrics should be available without making local development heavy.

The project constraints remain lightweight deployment, Debian 12 minimal as the recommended baseline, Docker Compose as the first production target, no mock data in business pages, and no mandatory external analytics service for the first observability milestone.

## Goals / Non-Goals

**Goals:**

- Produce structured gateway access logs and WAF event logs with request IDs and bounded sensitive data handling.
- Ingest or persist access and attack logs through the control plane using real storage abstractions.
- Provide API filters and dashboard views for attack logs, access logs, and summary metrics.
- Expose basic Prometheus metrics for API and gateway services.
- Keep local development functional with in-memory storage and Docker Compose functional with PostgreSQL persistence.

**Non-Goals:**

- Full ClickHouse-based analytics is not required for the first implementation, though the design leaves a path for it.
- Full alerting workflow is not required in the first task set; only metric/log foundations are prepared.
- Distributed tracing and OpenTelemetry are out of scope for this change.
- Long-term log archival, tiered retention, and advanced aggregation performance are out of scope.

## Decisions

### Use PostgreSQL and in-memory stores first, keep ClickHouse optional

The first implementation will add log storage interfaces to the API and back them with existing storage modes: in-memory when `DATABASE_URL` is empty and PostgreSQL when configured. This keeps tests and local development lightweight and matches current project behavior.

Alternative considered: introduce ClickHouse immediately for access and attack logs. ClickHouse is a good fit for larger volumes, but making it mandatory would increase deployment complexity before the project has validated the log schema and dashboard workflows.

### Gateway writes structured stdout logs and optionally posts ingestion events

The gateway will continue to emit JSON logs to stdout because container log collection is the simplest baseline. For dashboard queryability in lightweight deployments, the gateway can also send bounded access and WAF event payloads to API ingestion endpoints when configured with an API base URL and ingestion token.

Alternative considered: rely only on Vector or Fluent Bit to ship stdout logs. That is a clean production pattern, but it adds an additional service before basic observability pages can work in local Compose.

### Separate access logs from WAF event logs

Access logs represent one completed request and final disposition. WAF event logs represent rule, access-list, or rate-limit matches. They share request ID, site identity, and request metadata so operators can correlate them.

Alternative considered: store all observability rows in one generic event table. A single table is flexible, but separate shapes make filtering and dashboard summaries clearer for the current product.

### Add bounded request metadata and redaction rules

Logs will include host, method, URI/path, query summary, status, duration, client IP, user agent summary, site, rule/action metadata, and request ID. They will not store request bodies, authorization values, cookies, or unbounded matched payloads.

Alternative considered: store full request payloads for forensic detail. That would increase privacy and storage risk and conflict with the lightweight default.

### Metrics endpoints are configurable

API and gateway metrics endpoints will be disabled or protected by configuration for production safety and enabled for internal scraping when desired. The dashboard metrics view will read API summary endpoints, not scrape Prometheus directly.

Alternative considered: always expose metrics endpoints. That is convenient in development, but risky if the management or gateway service is placed on a public network.

## Risks / Trade-offs

- High log volume can grow PostgreSQL tables quickly -> add pagination, bounded default time ranges, indexes on time/site/IP/rule/disposition, and document retention limits.
- Gateway-to-API ingestion can add latency or failure coupling -> make ingestion asynchronous/best-effort where practical and never block request enforcement on ingestion success.
- Storing client IP and URI data can include sensitive information -> redact sensitive headers, bound matched values, avoid request bodies, and document retention controls.
- Metrics labels can explode cardinality -> use bounded labels such as site ID and disposition; avoid raw URI or client IP labels in Prometheus metrics.
- Docker Compose end-to-end verification may depend on Docker availability -> keep unit and local process tests useful, and document Docker validation steps separately.

## Migration Plan

1. Add API data models, storage interfaces, and PostgreSQL schema for access logs and WAF event logs.
2. Add API ingestion, query, and summary endpoints behind existing authentication/authorization patterns plus a dedicated gateway ingestion token.
3. Update gateway logging to generate request IDs, structured access logs, structured WAF event logs, and optional ingestion calls.
4. Add API and gateway metrics endpoints with environment-based enablement.
5. Add dashboard API clients, routes, menu entries, attack/access log tables, filters, empty states, and summary metric widgets.
6. Update Docker Compose environment examples and documentation for ingestion token, metrics enablement, and optional future log collector wiring.

Rollback strategy: disable gateway ingestion and metrics via environment variables, keep stdout logging active, and roll back API/dashboard binaries if schema changes cause issues. PostgreSQL log tables are additive and can remain unused after rollback.

## Open Questions

- Should the first production Compose profile include Vector/Fluent Bit as an optional service, or only document it for a later change?
- What default retention window should the PostgreSQL implementation enforce or recommend for lightweight deployments?
- Should gateway ingestion use a shared token initially, or should it reuse a more formal service credential model when user/service account management expands?
