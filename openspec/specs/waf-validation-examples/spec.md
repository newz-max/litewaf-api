# waf-validation-examples Specification

## Purpose
Define local-only validation services and request samples that demonstrate LiteWaf proxying, blocking, rate limiting, and observability behavior.

## Requirements
### Requirement: Example upstream service supports gateway validation
The project SHALL provide a lightweight example upstream service or documented equivalent that can run locally and return deterministic responses for normal proxy, header, path, query, and body validation through the WAF gateway.

#### Scenario: Normal request reaches upstream
- **WHEN** the example upstream is running and the gateway is configured for its host
- **THEN** a normal request through the gateway is proxied to the upstream and returns a deterministic success response

#### Scenario: Unknown path remains observable
- **WHEN** a request reaches an example upstream path intended for diagnostics
- **THEN** the upstream response includes enough non-sensitive request information to confirm host, path, method, and selected headers used in validation

### Requirement: Attack sample commands validate baseline protections
The project SHALL provide local-only sample requests for SQLi, XSS, RCE-like, CC/rate-limit, body inspection, upload metadata, access-list, and normal pass-through validation where supported by current LiteWaf capabilities.

#### Scenario: SQLi sample is blocked
- **WHEN** baseline SQLi protection is published and the user runs the documented SQLi sample against the local gateway
- **THEN** the gateway returns the documented blocked response and emits a corresponding WAF event

#### Scenario: XSS sample is blocked
- **WHEN** baseline XSS protection is published and the user runs the documented XSS sample against the local gateway
- **THEN** the gateway returns the documented blocked response and emits a corresponding WAF event

#### Scenario: Rate limit sample triggers limiting
- **WHEN** a sample rate limit configuration is active and the user runs the documented repeated request sample
- **THEN** requests beyond the configured threshold receive the documented rate-limit response or temporary ban behavior

### Requirement: Validation examples are isolated from production defaults
The project SHALL keep example upstream services, sample payloads, and validation-only Compose wiring out of the default production deployment path.

#### Scenario: Production Compose is used
- **WHEN** an operator uses the production deployment files without enabling validation examples
- **THEN** no example upstream service or attack-sample workload is started as part of the production stack

#### Scenario: Validation examples are enabled
- **WHEN** a user explicitly follows the validation example instructions
- **THEN** the example upstream and samples run only in the local validation context described by the documentation

### Requirement: Validation samples document expected observations
The project SHALL document expected HTTP statuses, response bodies at a high level, and log or dashboard observations for each validation sample.

#### Scenario: User checks sample result
- **WHEN** a user runs a documented validation sample
- **THEN** they can compare the actual HTTP result and dashboard or log observation with the documented expected outcome
