## ADDED Requirements

### Requirement: Policies can be managed through API
The API SHALL allow operators to create, list, view, update, and delete policies under the `/api/v1` prefix.

#### Scenario: Create policy
- **WHEN** an operator submits a valid policy name with site and rule bindings
- **THEN** the API persists the policy and its bindings and returns the created policy with an identifier

#### Scenario: Update policy bindings
- **WHEN** an operator changes the sites or rules bound to a policy
- **THEN** the API persists the new binding set and uses it in the next publish

### Requirement: Policy bindings reference existing entities
The API SHALL reject policy bindings that reference missing sites or rules.

#### Scenario: Missing rule binding
- **WHEN** an operator submits a policy referencing a nonexistent rule identifier
- **THEN** the API returns a validation error and does not persist the invalid binding

### Requirement: Dashboard displays real policies
The dashboard SHALL load policy data from the policy API and SHALL provide create, update, delete, binding selection, loading, empty, and error states without mock policy rows.

#### Scenario: Policy list refreshes after binding update
- **WHEN** an operator updates a policy's site or rule bindings from the dashboard
- **THEN** the dashboard shows the persisted binding relationship after the save completes
