# backup-and-restore Specification

## Purpose
Define production backup and restore behavior for LiteWaf single-node Docker Compose deployments.

## Requirements
### Requirement: Backup creates portable archive
The backup flow SHALL create a timestamped archive containing the persistent LiteWaf state and deployment metadata needed for recovery.

#### Scenario: Operator creates backup
- **WHEN** an operator runs the backup command against a running production Compose stack
- **THEN** the command creates an archive containing PostgreSQL data dump, gateway configuration, `.env`, Compose metadata, and a manifest

#### Scenario: Backup cannot complete
- **WHEN** a required service or volume cannot be read
- **THEN** the backup command fails without deleting the previous successful backup

### Requirement: Backup protects sensitive material
The backup flow SHALL warn operators that backup archives contain secrets and SHALL restrict archive file permissions where the host supports it.

#### Scenario: Backup archive is created
- **WHEN** the backup command writes an archive on a Linux host
- **THEN** the archive is created with permissions that avoid world-readable access where practical

### Requirement: Restore recreates state from backup
The restore flow SHALL restore LiteWaf persistent state from a backup archive into a compatible production Compose deployment.

#### Scenario: Operator restores backup
- **WHEN** an operator runs the restore command with a valid backup archive
- **THEN** PostgreSQL data, gateway configuration, and deployment environment files are restored before services are restarted

#### Scenario: Restore target has running services
- **WHEN** services are running during restore
- **THEN** the restore flow stops or requires confirmation before replacing persistent state

### Requirement: Restore validates backup manifest
The restore flow SHALL validate the backup manifest before modifying persistent state.

#### Scenario: Backup manifest is invalid
- **WHEN** a backup archive is missing required manifest fields or payloads
- **THEN** the restore command stops before changing the current deployment
