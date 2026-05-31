# deployment-security-hardening Specification

## Purpose
Define production deployment security checks and operator guidance for LiteWaf.

## Requirements
### Requirement: Production rejects weak secrets
Production startup SHALL reject or block known weak default secrets for administrator password, authentication token secret, gateway ingestion token, and database password.

#### Scenario: Weak secret is configured
- **WHEN** `APP_ENV` indicates production and a required secret is empty or set to a known default such as `change-me`
- **THEN** startup or installation fails with a message identifying the unsafe key

#### Scenario: Strong secrets are configured
- **WHEN** all required production secrets are non-default values
- **THEN** startup continues without weak-secret errors

### Requirement: Management exposure is documented as protected
Production deployment documentation SHALL require the management dashboard and management API to be protected from direct public exposure.

#### Scenario: Operator reviews production security guidance
- **WHEN** an operator follows the production deployment documentation
- **THEN** the documentation directs them to use VPN, bastion access, reverse proxy authentication, IP allowlists, or equivalent controls for management access

### Requirement: Metrics exposure is disabled or internal by default
Production deployment SHALL keep API and gateway metrics disabled or limited to internal scraping paths by default.

#### Scenario: Default production environment is generated
- **WHEN** the installer creates the production `.env`
- **THEN** API and gateway metrics exposure values default to disabled

#### Scenario: Metrics are intentionally enabled
- **WHEN** an operator enables metrics in production
- **THEN** documentation states that metrics endpoints must be exposed only on trusted internal networks or behind access controls

### Requirement: Docker log growth guidance is provided
Production deployment documentation SHALL include Docker logging and rotation guidance for long-running hosts.

#### Scenario: Operator prepares host logging
- **WHEN** an operator follows the production operations documentation
- **THEN** they receive Docker log rotation guidance that prevents unbounded container log growth
