## ADDED Requirements

### Requirement: Compose runs MVP services
The project SHALL provide Docker Compose configuration that runs the gateway, API, dashboard, PostgreSQL, Redis, and a simple upstream service.

#### Scenario: Start MVP stack
- **WHEN** an operator runs the documented Docker Compose startup command on Debian 12
- **THEN** all MVP services start with the required networking and volumes

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
The project SHALL document the commands needed to start the stack, create or seed MVP configuration, publish it, and verify proxy and block behavior through the gateway.

#### Scenario: Operator verifies block behavior
- **WHEN** an operator follows the documented MVP verification steps
- **THEN** they can observe a normal proxied request and a blocked SQLi or XSS request through the gateway
