## ADDED Requirements

### Requirement: Default rule set is versioned and reviewable
The project SHALL provide a versioned default rule set source containing baseline SQLi, XSS, RCE-like, and CC/rate-limit oriented protections compatible with the existing LiteWaf rule and policy model.

#### Scenario: Reader reviews default rules
- **WHEN** a reader opens the default rule set source
- **THEN** they can identify the rule set version, rule identifiers, names, types, targets, expressions, actions, scores, enabled defaults, and compatibility notes

### Requirement: Default rules seed real managed rules
The system SHALL load or import default baseline rules as real managed rules that are visible through the rule API and dashboard, without using dashboard mock data or gateway-only hidden rules.

#### Scenario: Fresh environment is seeded
- **WHEN** a fresh local development or quick-start environment initializes default rules
- **THEN** baseline SQLi, XSS, and RCE-like rules are available through the rule list API and dashboard

#### Scenario: Seed does not duplicate existing rules
- **WHEN** default rule seeding runs more than once against the same persistent store
- **THEN** existing default rules are updated or skipped deterministically without creating duplicate managed rules

### Requirement: Default rules can be published through existing pipeline
The default baseline rules SHALL be publishable through the existing policy and config publishing pipeline so the OpenResty gateway enforces them from generated gateway configuration.

#### Scenario: Default rules are published
- **WHEN** an operator binds default rules to a policy and publishes configuration
- **THEN** the generated gateway configuration includes the enabled default rules in the same structure as operator-created rules

### Requirement: Default rule behavior is covered by validation samples
The project SHALL provide validation samples that exercise at least one default SQLi rule, one default XSS rule, and one default RCE-like rule where supported by the current gateway targets.

#### Scenario: Default SQLi rule is validated
- **WHEN** the SQLi validation sample runs against a gateway using the default rule set
- **THEN** the request matches a default SQLi rule and produces the documented enforcement result

#### Scenario: Default XSS rule is validated
- **WHEN** the XSS validation sample runs against a gateway using the default rule set
- **THEN** the request matches a default XSS rule and produces the documented enforcement result

#### Scenario: Default RCE-like rule is validated
- **WHEN** the RCE-like validation sample runs against a gateway using the default rule set
- **THEN** the request matches a default RCE-like rule and produces the documented enforcement result

### Requirement: Default rule set remains lightweight
The default rule set SHALL prioritize a small, understandable baseline over exhaustive coverage and SHALL document known limitations and tuning expectations.

#### Scenario: Operator reads default rule limitations
- **WHEN** an operator reviews the default rule set documentation
- **THEN** they can understand that the baseline is intended for initial protection and validation, not comprehensive managed-rule coverage
