# upgrade-and-rollback Specification

## Purpose
Define production upgrade and rollback behavior for LiteWaf single-node Docker Compose deployments.

## Requirements
### Requirement: Upgrade records previous release state
The upgrade flow SHALL record the currently deployed image tag and deployment metadata before switching to a new release.

#### Scenario: Operator starts upgrade
- **WHEN** an operator requests an upgrade to a target image tag
- **THEN** the upgrade flow records the previous tag, current Compose metadata, and timestamp before pulling new images

### Requirement: Upgrade performs pre-upgrade backup
The upgrade flow SHALL create or require a recent backup before applying a new production release.

#### Scenario: Backup succeeds before upgrade
- **WHEN** the pre-upgrade backup completes successfully
- **THEN** the upgrade flow may proceed to pull and start the target release

#### Scenario: Backup fails before upgrade
- **WHEN** the pre-upgrade backup fails
- **THEN** the upgrade flow stops before changing image tags or service state

### Requirement: Upgrade verifies new release health
The upgrade flow SHALL verify service health after applying the target release.

#### Scenario: Target release is healthy
- **WHEN** the target release starts and required health checks pass
- **THEN** the upgrade flow marks the target release as current

#### Scenario: Target release is unhealthy
- **WHEN** required health checks fail after upgrade
- **THEN** the upgrade flow reports the failure and provides the rollback command using the recorded previous release state

### Requirement: Rollback returns to previous release
The rollback flow SHALL restore the previous image tag and restart the production Compose stack.

#### Scenario: Operator rolls back tag
- **WHEN** an operator runs rollback after a failed upgrade without destructive data migration
- **THEN** the stack restarts using the previous image tag and verifies health

#### Scenario: Rollback requires data restore
- **WHEN** a failed upgrade involved irreversible data changes
- **THEN** the rollback documentation directs the operator to restore the pre-upgrade backup before starting the previous release
