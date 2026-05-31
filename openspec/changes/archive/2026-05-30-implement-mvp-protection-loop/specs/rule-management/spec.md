## ADDED Requirements

### Requirement: Rules can be managed through API
The API SHALL allow operators to create, list, view, update, and delete WAF rules under the `/api/v1` prefix.

#### Scenario: Create rule
- **WHEN** an operator submits a valid rule name, type, target, action, expression, score, and enabled state
- **THEN** the API persists the rule and returns the created rule with an identifier

#### Scenario: Disable rule
- **WHEN** an operator updates a rule enabled state to false
- **THEN** the API persists the disabled state and the next publish excludes or marks the rule inactive for enforcement

### Requirement: Rule fields are validated
The API SHALL reject rule writes with unsupported type, target, action, missing expression, or invalid score values.

#### Scenario: Unsupported rule action
- **WHEN** an operator submits a rule action outside `pass`, `block`, or `log-only`
- **THEN** the API returns a validation error and does not persist the rule

### Requirement: Baseline SQLi and XSS rules are available
The system SHALL provide baseline SQLi and XSS rules that can be enabled and published for MVP verification.

#### Scenario: Baseline SQLi rule exists
- **WHEN** a fresh MVP environment is initialized or seeded
- **THEN** at least one SQLi detection rule is available for query parameter inspection

#### Scenario: Baseline XSS rule exists
- **WHEN** a fresh MVP environment is initialized or seeded
- **THEN** at least one XSS detection rule is available for query parameter inspection

### Requirement: Dashboard displays real rules
The dashboard SHALL load rule data from the rule API and SHALL provide create, update, delete, enablement, loading, empty, and error states without mock rule rows.

#### Scenario: Rule list refreshes after create
- **WHEN** an operator creates a rule from the dashboard
- **THEN** the dashboard refreshes or updates the table so the new persisted rule is visible
