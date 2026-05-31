## ADDED Requirements

### Requirement: Installer validates host prerequisites
The production installation flow SHALL validate required host prerequisites before starting LiteWaf services.

#### Scenario: Required runtime is present
- **WHEN** an operator runs the production installer on a supported Linux host with Docker Engine and Docker Compose v2 installed
- **THEN** the installer reports the runtime versions and continues to configuration preparation

#### Scenario: Required runtime is missing
- **WHEN** Docker Engine or Docker Compose v2 is not available
- **THEN** the installer stops before changing service state and reports the missing prerequisite

### Requirement: Installer prepares operator environment
The production installation flow SHALL create or update an operator-owned `.env` file without overwriting existing non-default values.

#### Scenario: First install creates environment
- **WHEN** no production `.env` exists
- **THEN** the installer creates one from the template, fills required keys, and generates secrets for values that are empty or known unsafe defaults

#### Scenario: Existing environment is preserved
- **WHEN** a production `.env` already contains operator-edited values
- **THEN** the installer preserves those values and only adds missing required keys

### Requirement: Installer starts prebuilt production stack
The production installation flow SHALL start LiteWaf from prebuilt images and the production Compose file by default.

#### Scenario: Production install pulls images
- **WHEN** an operator runs the production installer with an image prefix and tag
- **THEN** the installer pulls the API, dashboard, and gateway images for that tag and starts the stack without building images on the host

#### Scenario: Explicit remote build is requested
- **WHEN** an operator explicitly enables a build-on-host mode
- **THEN** the installer MAY build images on the host and SHALL label that mode as non-default development or emergency behavior

### Requirement: Installer verifies service health
The production installation flow SHALL verify key service health after starting the stack.

#### Scenario: Services become healthy
- **WHEN** PostgreSQL, Redis, API, dashboard, and gateway health checks pass
- **THEN** the installer reports the dashboard and gateway access URLs

#### Scenario: Service health fails
- **WHEN** a required service does not become healthy within the documented timeout
- **THEN** the installer reports the failing service and leaves diagnostic commands for the operator
