# admin-authentication Specification

## Purpose
TBD - created by archiving change enhance-management-capabilities. Update Purpose after archive.
## Requirements
### Requirement: Administrators can log in
The API SHALL provide an administrator login endpoint that verifies submitted credentials and returns an access token for valid users.

#### Scenario: Valid login returns token
- **WHEN** a user submits valid administrator credentials
- **THEN** the API returns a successful JSON response containing an access token, token expiry, user identity, and role

#### Scenario: Invalid login is rejected
- **WHEN** a user submits an unknown account or incorrect password
- **THEN** the API returns HTTP 401 without returning an access token

### Requirement: Management APIs require authentication
The API SHALL require a valid access token for protected `/api/v1` management endpoints.

#### Scenario: Missing token is rejected
- **WHEN** a protected management endpoint is called without an access token
- **THEN** the API returns HTTP 401

#### Scenario: Expired token is rejected
- **WHEN** a protected management endpoint is called with an expired access token
- **THEN** the API returns HTTP 401

#### Scenario: Valid token allows protected read
- **WHEN** a protected read endpoint is called with a valid access token
- **THEN** the API evaluates the user's permissions and returns the requested resource when allowed

### Requirement: Public health endpoints remain accessible
The API SHALL keep operational health and version endpoints readable without login.

#### Scenario: Health check without token
- **WHEN** `GET /healthz` is called without an access token
- **THEN** the API returns the health response without requiring authentication

#### Scenario: Version endpoint without token
- **WHEN** `GET /api/v1/version` is called without an access token
- **THEN** the API returns the version response without requiring authentication

### Requirement: Dashboard supports authenticated sessions
The dashboard SHALL provide a login page and attach the access token to protected API requests after successful login.

#### Scenario: Login enters console
- **WHEN** a user logs in successfully from the dashboard
- **THEN** the dashboard stores the authenticated session state and routes the user to the console

#### Scenario: Unauthorized response clears session
- **WHEN** the dashboard receives HTTP 401 from a protected API request
- **THEN** the dashboard clears the current session state and sends the user to the login page

