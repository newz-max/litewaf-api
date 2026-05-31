## Why

LiteWaf has working control-plane, dashboard, gateway, and observability foundations, but the current deployment path is still closer to a development/MVP stack than an operator-ready production installation. This change moves the project toward the v1.0.0 milestone by making Debian 12 minimal and mainstream Linux + Docker Compose deployments installable, upgradeable, recoverable, and safer to run long term.

## What Changes

- Add a lightweight production installation flow that checks host prerequisites, prepares environment configuration, pulls published images, and starts the Compose stack without building services on the host.
- Add release image publishing expectations for API, dashboard, and gateway images so production installs can consume versioned prebuilt artifacts.
- Extend Compose deployment behavior for production health checks, persistent data volumes, resource/logging guidance, and operator-facing `.env` configuration.
- Add backup and restore support for PostgreSQL data, Redis/runtime state where applicable, gateway configuration, and environment/configuration files.
- Add an upgrade and rollback flow that supports image tag changes, database migration safety, pre-upgrade backup, health verification, and rollback to the previous release.
- Add deployment security checks and documentation for default credentials, token secrets, management exposure, metrics exposure, and admin access protection.

## Capabilities

### New Capabilities

- `production-installation`: Covers host prerequisite checks, `.env` generation/validation, image pulling, and production stack startup.
- `release-image-publishing`: Covers versioned prebuilt images for API, dashboard, and gateway services.
- `backup-and-restore`: Covers backup package creation and restoration for persistent LiteWaf state and configuration.
- `upgrade-and-rollback`: Covers production release upgrades, migration safety, health verification, and rollback behavior.
- `deployment-security-hardening`: Covers checks and guidance that prevent weak production secrets and unsafe management/metrics exposure.

### Modified Capabilities

- `mvp-compose-deployment`: Production deployment requires Compose behavior beyond the MVP stack, including health checks, production environment wiring, persistent volumes, and long-running operational guidance.

## Impact

- Affects `deploy/` Compose files, environment templates, and deployment scripts.
- Affects documentation under `doc/`, especially Debian 12 minimal deployment and production operations guidance.
- May add CI/release workflow files for image build and publish behavior.
- May add API startup validation for production weak/default secrets and migration/health-check integration.
- Does not introduce breaking API changes for existing management or gateway endpoints.
