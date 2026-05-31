## ADDED Requirements

### Requirement: API exposes Prometheus metrics
The API SHALL expose a Prometheus-compatible metrics endpoint for runtime and HTTP metrics.

#### Scenario: Prometheus scrapes API metrics
- **WHEN** a client requests the API metrics endpoint
- **THEN** the API returns text in Prometheus exposition format containing process health, request count, request duration, error count, and storage operation metrics

#### Scenario: API metrics endpoint avoids management data
- **WHEN** a client requests the API metrics endpoint
- **THEN** the response does not include secrets, tokens, request bodies, or personally sensitive header values

### Requirement: Gateway exposes Prometheus metrics
The gateway SHALL expose a Prometheus-compatible metrics endpoint for gateway traffic and enforcement metrics.

#### Scenario: Prometheus scrapes gateway metrics
- **WHEN** a client requests the gateway metrics endpoint
- **THEN** the gateway returns text in Prometheus exposition format containing request count, response status counts, blocked request count, WAF match count, and rate-limit rejection count

#### Scenario: Gateway metrics distinguish site labels
- **WHEN** gateway metrics are emitted for configured sites
- **THEN** counters include bounded labels for site identity and disposition where practical

### Requirement: Metrics endpoints can be disabled or protected
Metrics endpoints SHALL support configuration that prevents accidental public exposure in production.

#### Scenario: Metrics disabled by configuration
- **WHEN** metrics exposure is disabled by environment configuration
- **THEN** API and gateway metrics endpoints return not found or forbidden responses

#### Scenario: Metrics enabled for internal scraping
- **WHEN** metrics exposure is enabled for internal deployment
- **THEN** API and gateway metrics endpoints are reachable from the configured internal network path
