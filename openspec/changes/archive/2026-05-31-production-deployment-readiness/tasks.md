## 1. Production Compose and Environment

- [x] 1.1 Review `deploy/docker-compose.prod.yml` against production requirements for image coordinates, ports, secrets, metrics switches, gateway logging settings, volumes, and health checks.
- [x] 1.2 Update `deploy/.env.example` with production-safe defaults, required keys, image tag guidance, and comments for metrics and management exposure.
- [x] 1.3 Add Compose validation notes or scripts so operators can check the production Compose file before starting services.
- [x] 1.4 Verify persistent volumes cover PostgreSQL data, Redis data, and generated gateway configuration.

## 2. Production Installation Flow

- [x] 2.1 Refine the production installer to validate Docker Engine, Docker Compose v2, disk visibility, nofile limits, and occupied dashboard/gateway ports before service changes.
- [x] 2.2 Ensure the installer creates `.env` from the template on first install and preserves existing non-default operator values on later runs.
- [x] 2.3 Ensure the default install path pulls prebuilt images and starts the production Compose stack without host-side image builds.
- [x] 2.4 Add post-start health verification and clear diagnostic output for unhealthy services.

## 3. Backup and Restore

- [x] 3.1 Add a backup command or script that creates a timestamped archive with PostgreSQL dump, gateway configuration, `.env`, Compose metadata, and a manifest.
- [x] 3.2 Make backup failure non-destructive and avoid deleting previous successful backups.
- [x] 3.3 Restrict backup archive permissions where supported and warn that archives contain secrets.
- [x] 3.4 Add a restore command or script that validates the manifest, stops or confirms running services, restores state, and restarts the production stack.

## 4. Upgrade and Rollback

- [x] 4.1 Add an upgrade command or script that records the current image tag and deployment metadata before changing releases.
- [x] 4.2 Require or create a pre-upgrade backup before pulling and starting a target image tag.
- [x] 4.3 Verify target release health after upgrade and mark the release current only after required services pass checks.
- [x] 4.4 Add rollback behavior that restores the previous image tag and documents restore-from-backup when irreversible data changes occur.

## 5. Release Image Publishing

- [x] 5.1 Add CI workflow or documented release commands for building API, dashboard, and gateway container images.
- [x] 5.2 Publish or document immutable release tags for all LiteWaf service images.
- [x] 5.3 Ensure runtime images contain the assets required by their Compose health checks.
- [x] 5.4 Document registry prefix, image names, and tag configuration for public and private registries.

## 6. Deployment Security Hardening

- [x] 6.1 Add production weak-secret validation for admin password, auth token secret, gateway ingestion token, and database password.
- [x] 6.2 Ensure generated production `.env` values default metrics exposure to disabled.
- [x] 6.3 Document required protection for management dashboard and management API exposure.
- [x] 6.4 Document Docker log rotation and long-running host hardening guidance.

## 7. Documentation and Verification

- [x] 7.1 Update `doc/Debian12部署说明.md` with production install, health verification, backup, restore, upgrade, rollback, and security procedures.
- [x] 7.2 Update `doc/功能需求与迭代规划.md` to mark completed production-readiness items after implementation.
- [x] 7.3 Run backend tests for any API startup validation changes.
- [x] 7.4 Run frontend build if dashboard deployment assets or configuration change.
- [x] 7.5 Run available script dry-runs, Compose config validation, or documented manual checks and record any environment limitations.
