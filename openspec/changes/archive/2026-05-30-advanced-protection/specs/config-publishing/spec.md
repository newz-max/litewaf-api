## MODIFIED Requirements

### Requirement: Publish generates gateway configuration
The publish process SHALL generate a gateway-readable configuration artifact containing active sites, upstreams, policies, enabled rules, and advanced protection settings needed by the gateway.

#### Scenario: Gateway config is written
- **WHEN** a publish succeeds
- **THEN** the active gateway configuration file is updated with the published site and rule data

#### Scenario: Advanced settings are written
- **WHEN** a publish succeeds with policies that enable advanced inspection or dynamic bans
- **THEN** the active gateway configuration file includes policy score thresholds, body inspection limits, upload inspection limits, normalization options, and dynamic-ban settings

### Requirement: Publish validates configuration before activation
The publish process SHALL validate rule expressions, site upstreams, policy bindings, access list entries, rate limit rules, advanced inspection settings, and dynamic-ban settings before updating active gateway configuration.

#### Scenario: Invalid rule expression blocks publish
- **WHEN** an administrator triggers publish and an enabled rule has an invalid expression
- **THEN** the API returns a validation error, records the publish as failed or not activated, and does not update the active gateway configuration

#### Scenario: Incomplete policy blocks publish
- **WHEN** an administrator triggers publish and a site references an incomplete policy binding
- **THEN** the API returns a validation error and does not update the active gateway configuration

#### Scenario: Valid configuration publishes
- **WHEN** an administrator triggers publish with valid sites, policies, rules, access lists, and rate limits
- **THEN** the API creates a successful publish record and updates the active gateway configuration

#### Scenario: Invalid inspection limits block publish
- **WHEN** an administrator triggers publish with non-positive body, upload, normalization, score, or ban limits
- **THEN** the API returns a validation error and does not update the active gateway configuration

### Requirement: Publish changes can be summarized before activation
The API SHALL provide a publish preview or summary containing the configuration changes that would be activated, including advanced protection changes.

#### Scenario: Dashboard requests publish summary
- **WHEN** an administrator opens the publish confirmation flow
- **THEN** the dashboard can request a summary of pending changes from the API

#### Scenario: Summary contains changed resources
- **WHEN** the API returns a publish summary
- **THEN** the response identifies changed sites, policies, rules, access lists, and rate limits when those resources changed since the last successful publish

#### Scenario: Summary contains advanced protection changes
- **WHEN** advanced inspection, score threshold, upload limit, or dynamic-ban settings changed since the last successful publish
- **THEN** the response identifies those advanced protection changes in the publish summary

