## ADDED Requirements

### Requirement: Publish validates configuration before activation
The publish process SHALL validate rule expressions, site upstreams, policy bindings, access list entries, and rate limit rules before updating active gateway configuration.

#### Scenario: Invalid rule expression blocks publish
- **WHEN** an administrator triggers publish and an enabled rule has an invalid expression
- **THEN** the API returns a validation error, records the publish as failed or not activated, and does not update the active gateway configuration

#### Scenario: Incomplete policy blocks publish
- **WHEN** an administrator triggers publish and a site references an incomplete policy binding
- **THEN** the API returns a validation error and does not update the active gateway configuration

#### Scenario: Valid configuration publishes
- **WHEN** an administrator triggers publish with valid sites, policies, rules, access lists, and rate limits
- **THEN** the API creates a successful publish record and updates the active gateway configuration

### Requirement: Publish changes can be summarized before activation
The API SHALL provide a publish preview or summary containing the configuration changes that would be activated.

#### Scenario: Dashboard requests publish summary
- **WHEN** an administrator opens the publish confirmation flow
- **THEN** the dashboard can request a summary of pending changes from the API

#### Scenario: Summary contains changed resources
- **WHEN** the API returns a publish summary
- **THEN** the response identifies changed sites, policies, rules, access lists, and rate limits when those resources changed since the last successful publish

### Requirement: Published versions can be rolled back
The API SHALL allow authorized administrators to roll back active gateway configuration to a previous successful publish version.

#### Scenario: Roll back to successful version
- **WHEN** an administrator rolls back to a previous successful publish version
- **THEN** the API restores that version's gateway configuration as active and records the rollback operation

#### Scenario: Rollback to failed version is rejected
- **WHEN** an administrator attempts to roll back to a failed or nonexistent publish version
- **THEN** the API returns an error and does not update the active gateway configuration

## MODIFIED Requirements

### Requirement: Dashboard can trigger publish
The dashboard SHALL provide a publish confirmation flow, show publish status using API data, and only call the publish activation API after an authorized administrator confirms the change.

#### Scenario: Publish from dashboard
- **WHEN** an administrator confirms a publish action in the dashboard
- **THEN** the dashboard calls the publish API and displays the resulting publish status

#### Scenario: Publish cancelled from dashboard
- **WHEN** an administrator opens the publish confirmation flow and cancels it
- **THEN** the dashboard does not call the publish activation API
