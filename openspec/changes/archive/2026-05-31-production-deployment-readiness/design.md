## Context

LiteWaf currently has a working Docker Compose stack, production-oriented `docker-compose.prod.yml`, a PowerShell deployment helper, and Debian 12 deployment notes. The remaining gap is to turn those pieces into a clear production contract: prebuilt images are consumed instead of building on the host, secrets are generated or validated, services expose health checks, state can be backed up and restored, and upgrades have a repeatable rollback path.

The deployment target remains Debian 12 minimal first, with mainstream Linux + Docker Engine + Docker Compose v2 compatibility. The root workspace is not a Git repository; implementation work may span `deploy/`, `doc/`, and independent service repositories under `codes/`.

## Goals / Non-Goals

**Goals:**

- Provide a lightweight production installation path that does environment checks, prepares `.env`, pulls images, starts services, and verifies health.
- Keep production installs free of host-side Go, Node, OpenResty, or image builds by default.
- Define release image expectations for API, dashboard, and gateway.
- Provide backup, restore, upgrade, and rollback flows suitable for a single-node Compose deployment.
- Harden deployment defaults around weak secrets, management exposure, metrics exposure, and Docker log growth.
- Preserve local development workflows and the existing MVP Compose stack.

**Non-Goals:**

- Kubernetes deployment, multi-node high availability, and managed database deployments.
- ClickHouse, Vector/Fluent Bit, Prometheus, Grafana, and alerting as required production dependencies.
- A public SaaS installer or hosted control plane.
- Replacing Docker Compose with a custom orchestrator.

## Decisions

### Keep Docker Compose as the v1 production unit

Production readiness will extend the existing Compose files and deployment scripts instead of introducing Kubernetes or systemd-managed service units. This keeps the first production milestone aligned with the project's lightweight deployment goal and the Debian 12 minimal baseline.

Alternative considered: introduce Kubernetes manifests now. This would improve future scalability but would raise the minimum operational burden before the single-node product is proven.

### Prefer prebuilt versioned images for production

The production install path will pull `litewaf-api`, `litewaf-dashboard`, and `litewaf-gateway` images by prefix and tag from `.env`. Host-side builds remain available only through explicit development or emergency flags, such as the existing remote build option.

Alternative considered: build images on the target host during install. This is easier before CI is available, but it makes installs slower, less reproducible, and dependent on Go/Node/OpenResty build toolchains.

### Treat `.env` as the operator-owned configuration boundary

The installer will create `.env` from `.env.example`, fill missing keys, generate secrets when values are empty or known defaults, and preserve existing operator edits. Compose files should consume environment variables for ports, image tags, secrets, metrics switches, and runtime settings.

Alternative considered: generate Compose YAML dynamically. Keeping YAML static and moving local decisions into `.env` is easier to audit, document, and support.

### Provide scriptable backup/restore around Compose volumes

Backup and restore will be implemented as operator scripts that use Docker Compose services to dump PostgreSQL data, collect gateway configuration, collect `.env`/deployment metadata, and restore into an offline or controlled stack. Backups should be timestamped archives with a manifest.

Alternative considered: rely on raw Docker volume snapshots. Volume snapshots can be fast, but they are platform-specific and harder for users to inspect or move between hosts.

### Make upgrades reversible by default

The upgrade flow will take a backup, record the previous image tag and Compose release metadata, pull the target tag, apply startup/migration behavior, verify health, and keep a rollback command path to the previous tag. Rollback focuses on single-node Compose operations and depends on pre-upgrade backups for destructive data changes.

Alternative considered: support fully automatic database downgrade migrations. That would be more complex and risky than requiring pre-upgrade backups for early production releases.

### Enforce dangerous production defaults early

The API and deployment scripts should reject or warn on known weak defaults for admin password, token secret, ingestion token, and database password when `APP_ENV=production`. Documentation should also steer management dashboard and metrics endpoints behind VPN, reverse proxy auth, IP restrictions, or internal networks.

Alternative considered: document warnings only. Runtime checks are more likely to prevent accidental insecure deployments.

## Risks / Trade-offs

- Production scripts may diverge between Windows operator machines and Linux target hosts -> keep target-host logic POSIX shell compatible and document tested paths.
- Image publishing may be blocked by registry decisions -> make registry/prefix configurable and keep local image tag support for private registries.
- Backup archives may contain secrets -> warn operators, restrict file permissions where practical, and document secure storage expectations.
- Rollback after irreversible migrations may require restore rather than tag rollback -> require pre-upgrade backup and document restore-based rollback for migration failures.
- Compose health checks can report process health without full traffic validation -> include smoke checks for dashboard, API health, gateway, and published config where practical.

## Migration Plan

1. Add or refine production deployment scripts and `.env.example` without changing the development Compose flow.
2. Add backup/restore/upgrade helpers that operate against the production Compose project.
3. Add CI/release workflow or documented commands for versioned image publishing.
4. Add production startup validation for weak defaults where implementation is local to the API.
5. Update Debian 12 and production operations documentation with install, backup, restore, upgrade, rollback, and security guidance.
6. Verify with static checks, service tests, Compose config validation where available, and script dry-run/help paths.

Rollback for this change is file-level: revert the new deployment helpers, docs, and optional API startup validation. Rollback for a deployed LiteWaf release is covered by the `upgrade-and-rollback` capability.

## Open Questions

- Which public registry namespace should be treated as the default for published images before the project has a formal release process?
- Should production API startup hard-fail on weak secrets immediately, or warn first until existing test/deploy scripts are updated?
- Should the first backup format include Redis AOF/RDB content, or only PostgreSQL, gateway config, `.env`, and deployment metadata until Redis carries durable state?
