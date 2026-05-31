# mvp-compose-deployment Specification

## Purpose
TBD - created by archiving change implement-mvp-protection-loop. Update Purpose after archive.
## Requirements
### Requirement: Compose runs MVP services
The project SHALL provide Docker Compose configuration that runs the gateway, API, dashboard, PostgreSQL, Redis, and a simple upstream service for MVP or validation workflows, while keeping production Compose focused on production services.

#### Scenario: Start MVP stack
- **WHEN** an operator runs the documented Docker Compose startup command on Debian 12 minimal or another supported Linux host for MVP or validation
- **THEN** all MVP services start with the required networking and volumes

#### Scenario: Production stack excludes validation upstream by default
- **WHEN** an operator runs the production Compose deployment without enabling example validation wiring
- **THEN** the example upstream service is not started as part of the production stack

### Requirement: Compose persists stateful services
The Compose configuration SHALL mount persistent volumes for PostgreSQL and Redis data.

#### Scenario: Database survives container recreation
- **WHEN** the PostgreSQL container is recreated without deleting volumes
- **THEN** previously persisted LiteWaf configuration remains available

### Requirement: Compose wires gateway configuration sharing
The Compose configuration SHALL make the API-generated gateway configuration available to the OpenResty gateway.

#### Scenario: Publish affects gateway container
- **WHEN** the API publishes a new gateway configuration
- **THEN** the gateway container can read the updated configuration through the configured shared path

### Requirement: Documentation explains MVP verification
The project SHALL document the commands needed to start the stack, create or seed MVP configuration, publish it, and verify proxy and block behavior through the gateway using real baseline rules and an example upstream.

#### Scenario: Operator verifies block behavior
- **WHEN** an operator follows the documented MVP or quick-start verification steps
- **THEN** they can observe a normal proxied request and a blocked SQLi or XSS request through the gateway

#### Scenario: Operator verifies example upstream routing
- **WHEN** an operator follows the documented validation example steps
- **THEN** they can send a request through the gateway to the example upstream and observe the expected deterministic upstream response

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
