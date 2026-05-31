# policy-management Specification

## Purpose
TBD - created by archiving change implement-mvp-protection-loop. Update Purpose after archive.
## Requirements
### Requirement: Policies can be managed through API
The API SHALL allow operators to create, list, view, update, and delete policies under the `/api/v1` prefix, including score thresholds and advanced inspection settings used by gateway enforcement.

#### Scenario: Create policy
- **WHEN** an operator submits a valid policy name with site and rule bindings
- **THEN** the API persists the policy and its bindings and returns the created policy with an identifier

#### Scenario: Update policy bindings
- **WHEN** an operator changes the sites or rules bound to a policy
- **THEN** the API persists the new binding set and uses it in the next publish

#### Scenario: Configure score threshold
- **WHEN** an operator submits a policy with a valid score threshold and threshold action
- **THEN** the API persists those settings and uses them in the next publish

#### Scenario: Configure advanced inspection
- **WHEN** an operator submits valid body inspection, upload inspection, normalization, or dynamic-ban settings for a policy
- **THEN** the API persists those settings and uses them in the next publish

### Requirement: Policy bindings reference existing entities
The API SHALL reject policy bindings that reference missing sites or rules and SHALL reject invalid advanced policy settings.

#### Scenario: Missing rule binding
- **WHEN** an operator submits a policy referencing a nonexistent rule identifier
- **THEN** the API returns a validation error and does not persist the invalid binding

#### Scenario: Invalid score threshold
- **WHEN** an operator submits a policy with a negative score threshold or unsupported threshold action
- **THEN** the API returns a validation error and does not persist the invalid policy

#### Scenario: Invalid inspection limit
- **WHEN** an operator submits a policy with non-positive body, upload, normalization, or ban limits
- **THEN** the API returns a validation error and does not persist the invalid policy

### Requirement: Dashboard displays real policies
The dashboard SHALL load policy data from the policy API and SHALL provide create, update, delete, binding selection, advanced setting controls, loading, empty, and error states without mock policy rows.

#### Scenario: Policy list refreshes after binding update
- **WHEN** an operator updates a policy's site or rule bindings from the dashboard
- **THEN** the dashboard shows the persisted binding relationship after the save completes

#### Scenario: Policy advanced settings save
- **WHEN** an operator updates score threshold or inspection settings from the dashboard
- **THEN** the dashboard sends the values to the policy API and displays the persisted response

