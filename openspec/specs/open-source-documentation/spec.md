# open-source-documentation Specification

## Purpose
Define the user-facing documentation needed for first-run operation, integration, contribution, and LiteWaf rule ecosystem guidance.

## Requirements
### Requirement: Quick start documentation enables first-run validation
The project SHALL provide quick start documentation for Debian 12 minimal and compatible Linux hosts using Docker Compose, including prerequisites, configuration, startup, dashboard login, publish, gateway smoke test, and shutdown steps.

#### Scenario: New user starts LiteWaf
- **WHEN** a new user follows the quick start on a supported Linux host with Docker Engine and Docker Compose v2 installed
- **THEN** they can start the core LiteWaf services and identify the dashboard, API, gateway, PostgreSQL, and Redis endpoints used during validation

#### Scenario: New user verifies protection behavior
- **WHEN** a new user follows the quick start validation section
- **THEN** they can publish baseline protection and observe at least one normal proxied request and one blocked WAF request through the gateway

### Requirement: Architecture documentation explains system boundaries
The project SHALL document the LiteWaf architecture, including the control plane API, dashboard, OpenResty gateway, PostgreSQL, Redis, published gateway configuration, logs, metrics, and deployment boundaries.

#### Scenario: Reader reviews architecture
- **WHEN** a reader opens the architecture documentation
- **THEN** they can understand how rules and policies move from dashboard/API storage to gateway enforcement and how logs and metrics flow back for observation

### Requirement: API documentation covers management integration
The project SHALL document the `/api/v1` management API groups, authentication model, role expectations, common request and response shape, error behavior, and representative examples for core resources.

#### Scenario: Integrator reads API documentation
- **WHEN** an integrator reads the API documentation
- **THEN** they can identify how to authenticate and call site, rule, policy, publish, access-list, rate-limit, audit, log, observability, backup-related, and version endpoints at a high level

### Requirement: Rule authoring documentation covers supported rule model
The project SHALL document rule fields, supported targets, actions, scores, policy thresholds, normalization, body inspection, upload metadata inspection, access lists, rate limits, and safe authoring examples.

#### Scenario: Operator authors a custom rule
- **WHEN** an operator reads the rule authoring guide
- **THEN** they can create a valid custom WAF rule with an appropriate target, expression, action, score, and policy expectation

#### Scenario: Operator avoids unsupported behavior
- **WHEN** an operator reads the rule authoring guide
- **THEN** they can identify unsupported or deferred capabilities such as arbitrary Lua plugins, remote rule execution, libinjection, and Hyperscan integration

### Requirement: Contribution documentation defines project workflow
The project SHALL provide contribution guidance for local development, repository boundaries, branch and commit expectations, testing commands, security-sensitive configuration, documentation updates, and rule contribution review.

#### Scenario: Contributor prepares a change
- **WHEN** a contributor reads the contribution guide
- **THEN** they can identify the relevant module, run the expected checks, avoid committing generated or secret files, and submit a focused contribution

### Requirement: Ecosystem roadmap documents rule pack direction
The project SHALL document the intended community rule pack direction, including metadata, versioning, compatibility, review expectations, and the distinction between importable rule data and executable plugins.

#### Scenario: Rule author reviews ecosystem guidance
- **WHEN** a rule author reads the ecosystem documentation
- **THEN** they can understand how future rule packs are expected to be structured and why this stage does not execute third-party code dynamically
