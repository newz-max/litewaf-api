## ADDED Requirements

### Requirement: Release builds publish service images
The release process SHALL build and publish versioned container images for the API, dashboard, and gateway services.

#### Scenario: Versioned release images are published
- **WHEN** a release tag is built
- **THEN** `litewaf-api`, `litewaf-dashboard`, and `litewaf-gateway` images are published with the release tag

#### Scenario: Latest tag is updated intentionally
- **WHEN** the release process updates a floating tag such as `latest`
- **THEN** the same immutable release tag remains available for reproducible production installs

### Requirement: Release images include runtime health behavior
Release images SHALL include the runtime assets needed by their Compose health checks.

#### Scenario: API image health check runs
- **WHEN** Compose runs the API health check command inside the API image
- **THEN** the command exits successfully only when the API process is healthy

#### Scenario: Gateway image validates OpenResty configuration
- **WHEN** Compose runs the gateway health check command inside the gateway image
- **THEN** the command validates the OpenResty configuration and fails on invalid runtime configuration

### Requirement: Release documentation identifies image coordinates
The release process SHALL document the registry prefix, image names, and tag values used by production installation.

#### Scenario: Operator configures private registry
- **WHEN** an operator sets the image prefix and tag in `.env`
- **THEN** the production Compose file pulls all LiteWaf service images from the configured coordinates
