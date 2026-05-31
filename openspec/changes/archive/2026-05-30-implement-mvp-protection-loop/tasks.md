## 1. Backend Persistence Foundation

- [x] 1.1 Add PostgreSQL configuration fields and startup connection handling to `codes/litewaf-api`.
- [x] 1.2 Add database initialization SQL or migration assets for sites, rules, policies, policy bindings, publish records, and timestamps.
- [x] 1.3 Add repository layer for sites, rules, policies, bindings, and publish records using plain SQL.
- [x] 1.4 Update health or startup behavior so database connectivity failures are visible in structured logs.
- [x] 1.5 Add backend tests for repository empty-list and create/read behavior.

## 2. Backend Management APIs

- [x] 2.1 Replace site empty-list handlers with create, list, detail, update, and delete site endpoints.
- [x] 2.2 Add site validation for domain, upstream URL, and protection mode.
- [x] 2.3 Replace rule empty-list handlers with create, list, detail, update, and delete rule endpoints.
- [x] 2.4 Add rule validation for type, target, action, expression, score, and enabled state.
- [x] 2.5 Replace policy empty-list handlers with create, list, detail, update, and delete policy endpoints.
- [x] 2.6 Add policy binding validation for existing site and rule identifiers.
- [x] 2.7 Add backend handler tests for success, empty-list, validation-error, and not-found cases.

## 3. Publishing

- [x] 3.1 Define the MVP gateway JSON configuration schema used between API and OpenResty.
- [x] 3.2 Implement publish generation from active sites, policies, and enabled rules.
- [x] 3.3 Persist publish records with version, operator value, timestamp, status, and config path or checksum.
- [x] 3.4 Write published gateway config atomically to a configured shared path.
- [x] 3.5 Add publish list and publish trigger endpoints under `/api/v1`.
- [x] 3.6 Add backend tests for successful publish, empty publish state, and generated config content.

## 4. Gateway

- [x] 4.1 Create `codes/litewaf-gateway` with OpenResty configuration, Lua module layout, and Debian-compatible Dockerfile.
- [x] 4.2 Implement local gateway config loading from the published JSON file.
- [x] 4.3 Implement Host-based site lookup and reverse proxy routing to configured upstreams.
- [x] 4.4 Implement query parameter inspection for configured enabled rules.
- [x] 4.5 Implement `pass`, `block`, and `log-only` actions, including HTTP 403 for blocked requests.
- [x] 4.6 Add baseline SQLi and XSS rule definitions suitable for MVP verification.
- [x] 4.7 Emit JSON WAF match logs to stdout with site, rule, action, request, and client metadata.
- [x] 4.8 Add gateway smoke tests or scripted verification for proxy, unknown host, block, and log-only behavior.

## 5. Dashboard

- [x] 5.1 Update frontend API types and request functions for site, rule, policy, and publish endpoints.
- [x] 5.2 Implement site table and forms backed by real site APIs with loading, empty, and error states.
- [x] 5.3 Implement rule table and forms backed by real rule APIs with enablement controls.
- [x] 5.4 Implement policy table and forms backed by real policy APIs with site and rule binding selection.
- [x] 5.5 Implement release or publish page actions backed by real publish APIs.
- [x] 5.6 Remove any remaining business mock data from MVP management pages.
- [x] 5.7 Build the dashboard and fix TypeScript or Vite errors.

## 6. Compose Deployment

- [x] 6.1 Add `deploy/docker-compose.yml` for gateway, API, dashboard, PostgreSQL, Redis, and a simple upstream service.
- [x] 6.2 Add persistent volumes for PostgreSQL and Redis.
- [x] 6.3 Wire API and gateway shared configuration storage for published gateway JSON.
- [x] 6.4 Add environment variable examples for API database settings, gateway config path, and dashboard API base URL.
- [x] 6.5 Add service healthchecks where practical for API, dashboard, gateway, and PostgreSQL.

## 7. Documentation And Verification

- [x] 7.1 Document MVP startup steps for Debian 12 and Docker Compose.
- [x] 7.2 Document how to create or seed a site, rules, policy, and publish record.
- [x] 7.3 Document curl verification for normal proxy behavior through the gateway.
- [x] 7.4 Document curl verification for SQLi or XSS blocking behavior through the gateway.
- [x] 7.5 Run `go test ./...` for the API.
- [x] 7.6 Run the dashboard build.
- [x] 7.7 Run the Compose smoke test or document any environment blocker. Blocked locally: Docker Desktop engine pipe is unavailable.
