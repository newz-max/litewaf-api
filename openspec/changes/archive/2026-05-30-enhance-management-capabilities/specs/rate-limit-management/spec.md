## ADDED Requirements

### Requirement: Rate limits can be managed
The API SHALL allow authorized administrators to create, list, update, and delete rate limit rules for IP, URI, and site-level scopes.

#### Scenario: Create rate limit rule
- **WHEN** an administrator submits a valid rate limit rule
- **THEN** the API persists the rule and returns it in the response

#### Scenario: Invalid rate limit is rejected
- **WHEN** an administrator submits a rate limit rule with non-positive threshold, window, or ban duration
- **THEN** the API returns a validation error and does not persist the rule

#### Scenario: Empty rate limit list
- **WHEN** an allowed user lists rate limit rules and no rules exist
- **THEN** the API returns a successful JSON response containing an empty list

### Requirement: Rate limits can be published to gateway configuration
The publish process SHALL include enabled rate limit rules in the gateway-readable configuration artifact.

#### Scenario: Publish includes enabled rate limits
- **WHEN** an administrator publishes configuration with enabled rate limit rules
- **THEN** the generated gateway configuration contains those rules with scope, match criteria, threshold, window, action, and ban duration

#### Scenario: Disabled rate limits are not enforced
- **WHEN** an administrator publishes configuration with disabled rate limit rules
- **THEN** the generated gateway configuration does not require the gateway to enforce those disabled rules

### Requirement: Dashboard manages rate limits
The dashboard SHALL provide a rate limit configuration page using real API data and role-aware write controls.

#### Scenario: Administrator saves rate limit rule
- **WHEN** an administrator creates or edits a rate limit rule in the dashboard
- **THEN** the dashboard sends the rule to the API and refreshes the list from the API response

#### Scenario: Read-only user views rate limits
- **WHEN** a read-only user opens the rate limit page
- **THEN** the dashboard displays returned rules without create, edit, or delete controls
