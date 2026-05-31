## MODIFIED Requirements

### Requirement: Compose runs MVP services
The project SHALL provide Docker Compose configuration that runs the gateway, API, dashboard, PostgreSQL, Redis, and a simple upstream service for MVP or validation workflows, while keeping production Compose focused on production services.

#### Scenario: Start MVP stack
- **WHEN** an operator runs the documented Docker Compose startup command on Debian 12 minimal or another supported Linux host for MVP or validation
- **THEN** all MVP services start with the required networking and volumes

#### Scenario: Production stack excludes validation upstream by default
- **WHEN** an operator runs the production Compose deployment without enabling example validation wiring
- **THEN** the example upstream service is not started as part of the production stack

### Requirement: Documentation explains MVP verification
The project SHALL document the commands needed to start the stack, create or seed MVP configuration, publish it, and verify proxy and block behavior through the gateway using real baseline rules and an example upstream.

#### Scenario: Operator verifies block behavior
- **WHEN** an operator follows the documented MVP or quick-start verification steps
- **THEN** they can observe a normal proxied request and a blocked SQLi or XSS request through the gateway

#### Scenario: Operator verifies example upstream routing
- **WHEN** an operator follows the documented validation example steps
- **THEN** they can send a request through the gateway to the example upstream and observe the expected deterministic upstream response
