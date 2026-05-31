## Why

LiteWaf currently has the stage 0 skeleton, but it does not yet provide an end-to-end WAF protection loop. The next milestone needs a runnable MVP where operators can configure sites, rules, and policies, publish them, and have an OpenResty gateway enforce the published configuration.

## What Changes

- Add PostgreSQL-backed persistence for sites, rules, policies, policy bindings, publish records, and audit-ready metadata.
- Replace empty list management APIs with real CRUD APIs for sites, rules, and policies.
- Add publish APIs that produce versioned gateway configuration artifacts from the current policy state.
- Add a `litewaf-gateway` OpenResty project that reverse proxies requests by Host, loads local published configuration, and supports `pass`, `block`, and `log-only` actions.
- Add baseline SQLi and XSS detection rules suitable for MVP verification.
- Connect dashboard site, rule, policy, and publish views to real APIs without mock data.
- Add Docker Compose orchestration for API, dashboard, gateway, PostgreSQL, Redis, and a simple upstream service for local verification.
- Keep advanced stage 2 items such as authentication, role permissions, blacklist/whitelist management, rate limit management, publish rollback, and publish validation out of this change except where minimal data structures are needed for forward compatibility.

## Capabilities

### New Capabilities

- `control-plane-persistence`: PostgreSQL schema, connection handling, migrations/init, and repository behavior for MVP entities.
- `site-management`: Management APIs and dashboard behavior for site domain, upstream, and protection mode CRUD.
- `rule-management`: Management APIs and dashboard behavior for WAF rule CRUD, enablement, actions, targets, expressions, scores, and types.
- `policy-management`: Management APIs and dashboard behavior for policies that bind sites and rules.
- `config-publishing`: Versioned publish records and generated gateway configuration artifacts for published policy state.
- `gateway-enforcement`: OpenResty gateway behavior for Host-based reverse proxying, local config loading, request inspection, and `pass`/`block`/`log-only` enforcement.
- `mvp-compose-deployment`: Debian 12 oriented Docker Compose topology for running the MVP stack locally.

### Modified Capabilities

None.

## Impact

- Affects backend code under `codes/litewaf-api`, including database initialization, repositories, API routes, handlers, models, configuration, and tests.
- Affects frontend code under `codes/litewaf-dashboard`, including API clients, pages, forms, tables, loading/empty/error states, and build-time environment configuration.
- Adds gateway code under `codes/litewaf-gateway`, including OpenResty configuration, Lua modules, default rules/config, logging, and container build files.
- Adds deployment assets under `deploy/`, including Docker Compose, service configuration, volumes, and optional sample upstream wiring.
- Adds or updates documentation for MVP startup and verification commands, prioritizing Debian 12 and Docker Compose.
