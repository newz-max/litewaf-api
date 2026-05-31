## ADDED Requirements

### Requirement: Policies can be published as versions
The API SHALL allow operators to publish current policy state as a versioned release record.

#### Scenario: Publish current policy state
- **WHEN** an operator triggers a publish with valid sites, policies, and enabled rules
- **THEN** the API creates a publish record containing a version number, operator value, timestamp, and status

### Requirement: Publish generates gateway configuration
The publish process SHALL generate a gateway-readable configuration artifact containing active sites, upstreams, policies, and enabled rules.

#### Scenario: Gateway config is written
- **WHEN** a publish succeeds
- **THEN** the active gateway configuration file is updated with the published site and rule data

### Requirement: Publish records are queryable
The API SHALL expose publish records under the `/api/v1` prefix.

#### Scenario: List publish records
- **WHEN** an operator opens the release or publish page
- **THEN** the dashboard can display publish records returned by the API

### Requirement: Dashboard can trigger publish
The dashboard SHALL provide a publish action and display publish status using API data.

#### Scenario: Publish from dashboard
- **WHEN** an operator confirms a publish action in the dashboard
- **THEN** the dashboard calls the publish API and displays the resulting publish status
