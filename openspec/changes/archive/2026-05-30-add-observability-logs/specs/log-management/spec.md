## ADDED Requirements

### Requirement: API accepts gateway log ingestion
The API SHALL expose protected ingestion endpoints for gateway access logs and WAF event logs.

#### Scenario: Access log ingestion succeeds
- **WHEN** an authorized gateway submits a valid access log payload
- **THEN** the API stores the log entry and returns a successful JSON response

#### Scenario: WAF event ingestion succeeds
- **WHEN** an authorized gateway submits a valid WAF event payload
- **THEN** the API stores the event entry and returns a successful JSON response

#### Scenario: Unauthorized ingestion is rejected
- **WHEN** a log ingestion request is missing valid gateway ingestion credentials
- **THEN** the API returns 401 and does not store the payload

### Requirement: Access logs are queryable
The API SHALL expose access log query endpoints under `/api/v1` with filters for time range, site, host, client IP, method, URI, status, and disposition.

#### Scenario: Query access logs by site
- **WHEN** an allowed user queries access logs with a site filter
- **THEN** the API returns only access log records matching that site

#### Scenario: Empty access log query returns empty list
- **WHEN** an allowed user queries access logs and no records match
- **THEN** the API returns a successful JSON response containing an empty list

### Requirement: Attack logs are queryable
The API SHALL expose WAF event or attack log query endpoints under `/api/v1` with filters for time range, site, client IP, rule, action, disposition, and event type.

#### Scenario: Query attack logs by rule
- **WHEN** an allowed user queries attack logs with a rule ID filter
- **THEN** the API returns only WAF event records matching that rule ID

#### Scenario: Empty attack log query returns empty list
- **WHEN** an allowed user queries attack logs and no records match
- **THEN** the API returns a successful JSON response containing an empty list

### Requirement: Log summaries are available
The API SHALL expose summary endpoints that aggregate stored logs for dashboard views.

#### Scenario: Dashboard requests traffic summary
- **WHEN** an allowed user requests a traffic summary for a time range
- **THEN** the API returns totals for requests, blocked requests, WAF matches, and rate-limited requests

#### Scenario: Dashboard requests top dimensions
- **WHEN** an allowed user requests top dimensions for a time range
- **THEN** the API returns ranked client IPs, URIs, rules, and attack types from stored logs

### Requirement: Log storage works without mandatory external analytics services
The API SHALL support a default log storage path that works in local development and Docker Compose without requiring ClickHouse or an external log pipeline.

#### Scenario: Database URL is empty
- **WHEN** `DATABASE_URL` is empty in local development
- **THEN** log ingestion and query endpoints use in-memory storage and return real stored entries for the process lifetime

#### Scenario: PostgreSQL is configured
- **WHEN** `DATABASE_URL` points to PostgreSQL
- **THEN** log ingestion and query endpoints persist logs in database tables
