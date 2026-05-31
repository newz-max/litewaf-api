## ADDED Requirements

### Requirement: Sites can be managed through API
The API SHALL allow operators to create, list, view, update, and delete sites under the `/api/v1` prefix.

#### Scenario: Create site
- **WHEN** an operator submits a valid site domain, upstream URL, and protection mode
- **THEN** the API persists the site and returns the created site with an identifier

#### Scenario: Update site
- **WHEN** an operator updates an existing site's upstream URL or protection mode
- **THEN** the API persists the new values and returns the updated site

#### Scenario: Delete site
- **WHEN** an operator deletes an existing site
- **THEN** the API removes or marks the site unavailable so it no longer appears in normal site lists

### Requirement: Site fields are validated
The API SHALL reject site writes that omit required fields or contain invalid domain, upstream, or protection mode values.

#### Scenario: Invalid site write
- **WHEN** an operator submits a site without a domain or upstream URL
- **THEN** the API returns a validation error and does not persist the site

### Requirement: Dashboard displays real sites
The dashboard SHALL load site data from the site API and SHALL provide create, update, delete, loading, empty, and error states without mock site rows.

#### Scenario: Site list refreshes after create
- **WHEN** an operator creates a site from the dashboard
- **THEN** the dashboard refreshes or updates the table so the new persisted site is visible
