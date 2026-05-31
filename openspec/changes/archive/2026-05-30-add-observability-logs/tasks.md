## 1. API Data Model and Storage

- [x] 1.1 Add access log and WAF event domain types, query filters, pagination structs, and summary response types.
- [x] 1.2 Extend the storage interface with access log ingestion, WAF event ingestion, access log query, WAF event query, and observability summary methods.
- [x] 1.3 Implement in-memory storage for access logs, WAF events, filters, pagination, and summaries.
- [x] 1.4 Add PostgreSQL schema migration for access log and WAF event tables with indexes on timestamp, site, client IP, rule, status, action, and disposition.
- [x] 1.5 Implement PostgreSQL storage for log ingestion, filtered queries, and summary aggregations.

## 2. API Endpoints and Metrics

- [x] 2.1 Add gateway ingestion authentication using environment-configured credentials or token separate from user login tokens.
- [x] 2.2 Add protected ingestion endpoints for gateway access logs and WAF event logs.
- [x] 2.3 Add `/api/v1` access log query endpoints with time range, site, host, client IP, method, URI, status, and disposition filters.
- [x] 2.4 Add `/api/v1` attack log query endpoints with time range, site, client IP, rule, action, disposition, and event type filters.
- [x] 2.5 Add summary endpoints for request totals, blocked totals, WAF match totals, rate-limit totals, top IPs, top URIs, top rules, and attack types.
- [x] 2.6 Add Prometheus-compatible API metrics endpoint with request, error, duration, health, and storage operation metrics.
- [x] 2.7 Add API tests for ingestion auth, validation errors, empty queries, filtered queries, summaries, and metrics output.

## 3. Gateway Observability

- [x] 3.1 Add request ID generation and propagation through gateway access, WAF event, and upstream request handling.
- [x] 3.2 Emit one JSON access log for each completed proxied, rejected, blocked, or rate-limited request.
- [x] 3.3 Emit JSON WAF event logs for rule matches, access-list matches, and rate-limit matches with request ID and final disposition.
- [x] 3.4 Redact or omit authorization headers, cookies, configured sensitive headers, request bodies, and unbounded matched values from gateway logs.
- [x] 3.5 Add optional best-effort gateway-to-API ingestion for access logs and WAF events using configured API URL and ingestion token.
- [x] 3.6 Add Prometheus-compatible gateway metrics endpoint with bounded labels for site and disposition.
- [x] 3.7 Add or update gateway validation tests for access logs, WAF event logs, request ID correlation, redaction, ingestion failure tolerance, and metrics.

## 4. Dashboard Observability Views

- [x] 4.1 Add API client types and request functions for access logs, attack logs, observability summaries, and metrics-related summary data.
- [x] 4.2 Add attack log route, menu entry, filters, table, loading state, error state, and empty state using real API data.
- [x] 4.3 Add access log route, menu entry, filters, table, loading state, error state, and empty state using real API data.
- [x] 4.4 Update dashboard metrics view to display request count, block count, WAF match count, rate-limit count, and top lists from summary APIs.
- [x] 4.5 Ensure observability routes respect existing login state and role-aware menu/action behavior.
- [x] 4.6 Add frontend build and focused component/composable coverage where existing test tooling supports it.

## 5. Deployment and Documentation

- [x] 5.1 Update environment templates with gateway ingestion URL, ingestion token, metrics enablement, and sensitive header redaction settings.
- [x] 5.2 Update Docker Compose configuration for the new API and gateway observability environment variables and persistent PostgreSQL log storage.
- [x] 5.3 Document local development behavior for in-memory log storage and PostgreSQL-backed log storage.
- [x] 5.4 Document optional future Vector, Fluent Bit, ClickHouse, and Prometheus wiring without making them mandatory for the first implementation.
- [x] 5.5 Update stage 3 verification notes with manual checks for gateway logs, API ingestion/query, dashboard pages, and metrics endpoints.

## 6. End-to-End Verification

- [x] 6.1 Run `go test ./...` in `codes/litewaf-api`.
- [x] 6.2 Run the gateway validation suite or documented OpenResty/Lua tests for observability behavior. Static wiring checks completed; local OpenResty binary is unavailable.
- [x] 6.3 Run `npm run build` in `codes/litewaf-dashboard`.
- [x] 6.4 When Docker is available, run Docker Compose smoke tests for gateway request logs, ingestion, dashboard log queries, and metrics endpoints. Blocked locally: Docker Desktop engine pipe is unavailable.
