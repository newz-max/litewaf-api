# rule-management Specification

## Purpose
TBD - created by archiving change implement-mvp-protection-loop. Update Purpose after archive.
## Requirements
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

### Requirement: Baseline SQLi and XSS rules are available
The system SHALL provide baseline SQLi, XSS, and RCE-like rules that can be seeded as real managed rules, enabled, bound to policies, and published for MVP and open-source validation.

#### Scenario: Baseline SQLi rule exists
- **WHEN** a fresh MVP or quick-start environment is initialized or seeded
- **THEN** at least one SQLi detection rule is available for query parameter inspection through the rule API and dashboard

#### Scenario: Baseline XSS rule exists
- **WHEN** a fresh MVP or quick-start environment is initialized or seeded
- **THEN** at least one XSS detection rule is available for query parameter inspection through the rule API and dashboard

#### Scenario: Baseline RCE-like rule exists
- **WHEN** a fresh quick-start environment is initialized or seeded
- **THEN** at least one RCE-like detection rule is available through the rule API and dashboard using a target supported by the gateway inspection model

#### Scenario: Default rule seed is idempotent
- **WHEN** default baseline rule seeding is executed repeatedly
- **THEN** the API storage contains one deterministic managed rule per default rule identifier instead of duplicates

### Requirement: Dashboard displays real rules
The dashboard SHALL load rule data from the rule API and SHALL provide create, update, delete, enablement, loading, empty, and error states for baseline and advanced rule targets without mock rule rows.

#### Scenario: Rule list refreshes after create
- **WHEN** an operator creates a rule from the dashboard
- **THEN** the dashboard refreshes or updates the table so the new persisted rule is visible

#### Scenario: Advanced target options come from supported values
- **WHEN** an operator opens the rule form
- **THEN** the dashboard presents supported advanced targets without hard-coded mock rules
