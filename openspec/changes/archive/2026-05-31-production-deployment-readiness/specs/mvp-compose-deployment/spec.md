## ADDED Requirements

### Requirement: Compose supports production environment wiring
The Compose deployment SHALL support production environment variables for image coordinates, exposed ports, secrets, metrics switches, and gateway logging settings.

#### Scenario: Production environment is supplied
- **WHEN** an operator starts the production Compose file with a completed `.env`
- **THEN** the API, dashboard, and gateway services use the configured image prefix, image tag, ports, secrets, metrics switches, and gateway logging settings

### Requirement: Compose defines production health checks
The Compose deployment SHALL define health checks for stateful services and LiteWaf runtime services used in production.

#### Scenario: Compose health is inspected
- **WHEN** an operator runs Docker Compose status commands after startup
- **THEN** PostgreSQL, Redis, API, dashboard, and gateway expose health status through Compose

### Requirement: Compose persists production state
The Compose deployment SHALL persist PostgreSQL data, Redis data, and generated gateway configuration across container recreation.

#### Scenario: Production containers are recreated
- **WHEN** an operator recreates production containers without deleting volumes
- **THEN** LiteWaf configuration, logs stored in PostgreSQL, Redis runtime state, and active gateway configuration remain available

### Requirement: Compose documents long-running operations
The Compose deployment documentation SHALL include operational guidance for volumes, resource limits, nofile tuning, and Docker log rotation.

#### Scenario: Operator prepares a production host
- **WHEN** an operator reads the production Compose deployment documentation
- **THEN** the documentation describes persistent volumes, resource considerations, nofile tuning, and Docker log rotation expectations
