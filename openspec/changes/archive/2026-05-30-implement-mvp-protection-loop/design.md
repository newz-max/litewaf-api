## Context

LiteWaf has completed the project skeleton: a Go `net/http` API, a Vue 3 dashboard, empty-list endpoints, and Debian-oriented container builds. The next milestone must turn that skeleton into a minimal WAF product loop without introducing the larger stage 2 management scope.

The MVP spans the control plane, dashboard, gateway, and local deployment. The control plane must persist operator configuration in PostgreSQL, generate a published gateway configuration, and expose management APIs. The OpenResty gateway must load that local configuration and enforce simple request inspection before proxying to the configured upstream.

## Goals / Non-Goals

**Goals:**

- Provide real PostgreSQL-backed CRUD for sites, rules, and policies.
- Generate versioned publish records and a gateway-readable configuration artifact.
- Add an OpenResty gateway that can reverse proxy by Host and enforce basic WAF actions.
- Provide baseline SQLi and XSS rules that can prove the protection loop works.
- Connect dashboard pages to real APIs with loading, empty, and error states.
- Provide a Debian 12 oriented Docker Compose stack for local MVP verification.

**Non-Goals:**

- User login, RBAC, protected management APIs, and role-aware menus.
- Full publish rollback, advanced validation workflow, or approval gates.
- Blacklist/whitelist and rate-limit management.
- ClickHouse, Vector/Fluent Bit, Prometheus, alerting, or full observability.
- Advanced detection engines such as libinjection or Hyperscan.
- Kubernetes deployment.

## Decisions

1. Use PostgreSQL as the source of truth and plain SQL repositories in the Go API.

   Rationale: The project already favors a lightweight Go standard-library API, and plain SQL keeps the MVP small and inspectable. Alternatives considered were adding an ORM or embedding SQLite. An ORM is unnecessary at this stage, and SQLite would not match the planned Docker Compose production shape.

2. Store publish output as a gateway-readable JSON configuration file on a shared volume.

   Rationale: The gateway hot path must not call the database or API. A local JSON artifact keeps gateway startup and reload behavior simple while allowing the API to own publishing. Alternatives considered were API polling from Lua and direct PostgreSQL access from the gateway. Both add runtime coupling to the request path.

3. Keep the first gateway rule engine pattern-based and deterministic.

   Rationale: MVP verification only needs target extraction, expression matching, action handling, and clear logs. The default SQLi/XSS rules can use conservative Lua patterns or equivalent regex-style checks. Advanced scoring, normalization, body inspection, and external engines remain later-stage work.

4. Model policy binding explicitly rather than embedding all rule IDs in policy rows.

   Rationale: Policies must bind to sites and rule sets, and explicit join tables keep the relationship queryable and easier to extend. The simpler JSON-array-in-row alternative would reduce schema files but complicate filtering and future validation.

5. Keep the dashboard as an operational console, not a demo UI.

   Rationale: Project rules forbid mock business data. Pages must read API state, show empty states when there are no rows, and use forms/tables for real create/update/delete flows. Any sample defaults belong in migrations or deploy assets, not in component-local mock arrays.

6. Make Docker Compose the primary MVP integration contract.

   Rationale: The project prioritizes Debian 12 and Docker Compose quick deployment. Compose should wire API, dashboard, gateway, PostgreSQL, Redis, persistent volumes, and a simple upstream service so the protection loop can be verified with commands.

## Risks / Trade-offs

- [Risk] Shared-volume JSON publishing can become stale if the API writes partial files or the gateway reads mid-write. -> Mitigation: write to a temporary file, validate JSON shape, then atomically replace the active config file where the platform permits.
- [Risk] Basic pattern rules can produce false positives or miss evasive payloads. -> Mitigation: mark the rules as MVP baseline, keep them editable, and avoid promising advanced detection coverage in this change.
- [Risk] Adding persistence touches many handlers at once. -> Mitigation: keep repository interfaces small, test handler/repository behavior, and preserve existing JSON response conventions.
- [Risk] Compose networking can hide Host routing mistakes. -> Mitigation: include explicit verification steps that set the `Host` header through the gateway and check the upstream response.
- [Risk] Publish without full validation may emit incomplete gateway config. -> Mitigation: perform minimal required-field checks during CRUD and publish, while leaving comprehensive stage 2 validation for a later change.

## Migration Plan

1. Add database initialization SQL and API startup configuration for PostgreSQL.
2. Implement repository-backed APIs while preserving `/api/v1` and `/healthz`.
3. Add the gateway project and local JSON config format.
4. Add publish generation to write the gateway config artifact.
5. Connect dashboard pages to real CRUD and publish APIs.
6. Add Compose deployment and documentation for local verification.

Rollback for the MVP is operational: stop the Compose stack, restore the previous image set or source revision, and keep PostgreSQL volumes unless data reset is explicitly desired. Database migrations for this phase should be additive from the stage 0 skeleton because no existing production schema exists.

## Open Questions

- Should the publish actor default to a configured service user until authentication exists?
- Should default baseline SQLi/XSS rules be inserted by database initialization or provided as an importable seed file?
- Should gateway config reload be file mtime polling, OpenResty reload, or an explicit admin endpoint in the MVP?
