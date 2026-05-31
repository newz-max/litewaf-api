## ADDED Requirements

### Requirement: PostgreSQL connection is configurable
The API service SHALL connect to PostgreSQL using environment-provided configuration and SHALL expose database connectivity in service startup behavior.

#### Scenario: API starts with reachable database
- **WHEN** the API process starts with valid PostgreSQL connection settings
- **THEN** the service establishes database connectivity and starts serving HTTP requests

#### Scenario: API starts with unreachable database
- **WHEN** the API process starts and PostgreSQL is unreachable
- **THEN** the service fails fast with a structured log entry describing the database connection failure

### Requirement: MVP schema is initialized
The system SHALL provide initialization SQL or migrations for sites, rules, policies, policy bindings, publish records, and required timestamps.

#### Scenario: Database initializes in Compose
- **WHEN** the MVP Compose stack starts PostgreSQL with an empty data volume
- **THEN** the required MVP tables are created automatically before API traffic depends on them

### Requirement: Repositories persist MVP entities
The API SHALL persist and retrieve sites, rules, policies, policy bindings, and publish records from PostgreSQL rather than returning hard-coded or mock data.

#### Scenario: Created entity is returned later
- **WHEN** an operator creates a site, rule, policy, or publish record through the API
- **THEN** a later list or detail request returns that persisted entity from PostgreSQL

### Requirement: Empty database returns empty collections
The API SHALL return empty JSON collections for list endpoints when PostgreSQL contains no matching rows.

#### Scenario: Empty list from database
- **WHEN** a list endpoint is called and the backing table has no matching rows
- **THEN** the API returns a successful JSON response containing an empty list
