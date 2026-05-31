## MODIFIED Requirements

### Requirement: Rules can be managed through API
The API SHALL allow operators to create, list, view, update, and delete WAF rules under the `/api/v1` prefix, including rules that target normalized URI, path, query, header, body, and upload metadata inspection values.

#### Scenario: Create rule
- **WHEN** an operator submits a valid rule name, type, target, action, expression, score, and enabled state
- **THEN** the API persists the rule and returns the created rule with an identifier

#### Scenario: Disable rule
- **WHEN** an operator updates a rule enabled state to false
- **THEN** the API persists the disabled state and the next publish excludes or marks the rule inactive for enforcement

#### Scenario: Create body-targeted rule
- **WHEN** an operator submits a valid rule targeting inspected request body values
- **THEN** the API persists the rule and makes it available for the next publish

#### Scenario: Create upload-targeted rule
- **WHEN** an operator submits a valid rule targeting upload filename, extension, MIME type, or size metadata
- **THEN** the API persists the rule and makes it available for the next publish

### Requirement: Rule fields are validated
The API SHALL reject rule writes with unsupported type, target, action, missing expression, invalid score values, or incompatible advanced-target settings.

#### Scenario: Unsupported rule action
- **WHEN** an operator submits a rule action outside `pass`, `block`, or `log-only`
- **THEN** the API returns a validation error and does not persist the rule

#### Scenario: Unsupported advanced target
- **WHEN** an operator submits a rule target not supported by the gateway inspection model
- **THEN** the API returns a validation error and does not persist the rule

#### Scenario: Invalid upload size expression
- **WHEN** an operator submits an upload-size rule with a non-numeric or negative size expression
- **THEN** the API returns a validation error and does not persist the rule

### Requirement: Dashboard displays real rules
The dashboard SHALL load rule data from the rule API and SHALL provide create, update, delete, enablement, loading, empty, and error states for baseline and advanced rule targets without mock rule rows.

#### Scenario: Rule list refreshes after create
- **WHEN** an operator creates a rule from the dashboard
- **THEN** the dashboard refreshes or updates the table so the new persisted rule is visible

#### Scenario: Advanced target options come from supported values
- **WHEN** an operator opens the rule form
- **THEN** the dashboard presents supported advanced targets without hard-coded mock rules

