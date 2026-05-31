## Context

LiteWaf has a working MVP loop for sites, rules, policies, publishing, dashboard CRUD, and OpenResty enforcement. Stage 2 expands that loop into an operational management plane: write actions must be authenticated, permissions must match the operator role, sensitive changes must be auditable, and published gateway configuration must include management controls such as access lists, rate limits, validation, and rollback.

The project constraints remain lightweight Go `net/http`, PostgreSQL with in-memory fallback for local development, Vue 3 + TypeScript + Naive UI, Debian 12 minimal as the recommended host baseline with mainstream Linux + Docker Compose compatibility, lightweight runtime images where practical, and no mock business data in pages or API responses.

## Goals / Non-Goals

**Goals:**

- Add token-based administrator login and authenticated access to `/api/v1` management endpoints.
- Enforce administrator, auditor, and read-only permissions consistently in API handlers and dashboard actions.
- Persist audit logs for create, update, delete, publish, and rollback operations.
- Manage IP/CIDR/URI/User-Agent black and white lists and publish them to the gateway.
- Manage IP/URI/site-level rate limits and publish them to the gateway.
- Validate publish inputs before writing active gateway configuration.
- Roll back active gateway configuration to a previous successful publish version.
- Keep the dashboard operational: real API data, loading/empty/error states, and role-aware controls.

**Non-Goals:**

- External identity providers, OAuth, SSO, MFA, or password reset flows.
- Fine-grained custom permission editing beyond the three planned roles.
- Distributed rate limiting across multiple gateway nodes.
- ClickHouse-backed log analytics, alerting, or Prometheus metrics.
- Advanced WAF detection engines or request body scanning.
- Kubernetes deployment.

## Decisions

1. Use stateless bearer tokens issued by the API and stored client-side by the dashboard.

   Rationale: The current API is lightweight and does not require server-side session storage for the stage 2 scope. Tokens should carry subject, role, issued time, and expiry, and the signing secret must come from environment configuration. Alternatives considered were cookie sessions and database-backed sessions. Cookie sessions add CSRF concerns to resolve now, and database sessions add persistence work that is not necessary for the first management boundary.

2. Keep role permissions fixed in code for the stage 2 release.

   Rationale: The required roles are stable: administrators can write and publish, auditors can read audit and release data, and read-only users can inspect configuration without mutation. Fixed permissions reduce schema and UI complexity. A later change can introduce editable roles if there is a real need.

3. Add audit logging as a shared service called by mutating handlers.

   Rationale: Audit records must be consistent across CRUD, publish, and rollback. A shared service can capture actor, role, action, resource type, resource ID, result, timestamp, and request metadata. Middleware-only logging was considered but cannot reliably include domain-specific resource IDs and operation results.

4. Store access lists and rate limits in PostgreSQL and include enabled entries in the published JSON configuration.

   Rationale: The control plane remains the source of truth while the gateway keeps the hot path independent from the API and database. Direct API lookups from OpenResty were rejected because management controls must not add remote calls to request processing.

5. Enforce gateway controls in short-circuit order: whitelist, blacklist, rate limit, then existing WAF rule inspection.

   Rationale: Whitelist entries should allow trusted traffic before block or rate logic, blacklist entries should reject known bad traffic cheaply, and rate limits should run before heavier rule evaluation. This order is simple to reason about and test.

6. Treat publish and rollback as versioned configuration operations.

   Rationale: Publish validation prevents bad active config, and rollback must produce a new auditable operation while restoring a previous configuration payload. Reusing the existing publish record model preserves the current release history contract and keeps gateway loading unchanged.

## Risks / Trade-offs

- [Risk] Token handling can expose the dashboard to stale or leaked credentials. -> Mitigation: require token expiry, keep secrets environment-provided, return 401 on invalid/expired tokens, and clear dashboard auth state on 401.
- [Risk] Fixed roles may be too coarse for future enterprise use. -> Mitigation: keep permission checks centralized so editable permissions can replace fixed maps later.
- [Risk] Audit logging can be skipped by new handlers. -> Mitigation: add handler tests for each mutating endpoint and make audit creation part of the shared mutation flow where practical.
- [Risk] CIDR, URI, and User-Agent matching can diverge between API validation and gateway behavior. -> Mitigation: validate format in the API and add gateway tests or smoke cases for each match type.
- [Risk] In-memory development storage may drift from PostgreSQL behavior. -> Mitigation: keep repository interfaces identical and cover both storage modes where low-cost.
- [Risk] Single-node OpenResty rate limiting will not coordinate across multiple gateway replicas. -> Mitigation: document the limit as node-local for this stage and defer distributed counters to a later design.

## Migration Plan

1. Add database tables for users, audit logs, access lists, rate limits, and any publish rollback metadata.
2. Add default/local administrator bootstrap through environment or initialization data without hard-coding production secrets.
3. Add authentication middleware and permission checks while leaving `/healthz` and `/api/v1/version` publicly readable.
4. Add API and dashboard flows for login, role-aware navigation, access lists, rate limits, publish validation, and rollback.
5. Extend publish output with access list and rate limit sections, and update the gateway to enforce them.
6. Update tests and documentation for protected endpoints, role behavior, audit records, publish validation, rollback, and gateway controls.

Rollback strategy: database changes should be additive, so an older service version can ignore the new tables and config sections. If a new gateway configuration causes issues, use the rollback API to restore a previous successful published payload or restore the previous active config file from backup.

## Open Questions

- Should local development create an initial administrator automatically when no users exist, or require explicit environment-provided credentials on every start?
- Should read-only users be allowed to trigger expression tests that do not mutate state?
- Should rollback create a new publish version marked as rollback, or reuse the historical version number as the active pointer?
